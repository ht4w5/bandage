# splint-nft: installing ban rules

`splint-nft` is the companion binary that turns bandage's advice into
enforcement. It fetches the report document (`GET /reports`, see
[the report document](reports.md)) on a fixed interval, compiles every
live [Report](../GLOSSARY.md) into [ban rules](../GLOSSARY.md), and
installs them into a wholly-owned nftables table (`splint`, inet family)
in the host's — or a chosen container's — network namespace. Each
Report's [Penalty](../GLOSSARY.md) is applied as stated; what each
Penalty becomes on the wire is in the mapping table below.

The lifecycle is built to fail at deploy time and never open the
floodgates:

- a **startup test install** runs one full fetch-compile-install before
  the loop begins — a broken flag, endpoint, or kernel exits non-zero at
  deploy time, not at ban time;
- every **update interval** (default 5m) refetches the document and
  rebuilds the ruleset wholesale in one atomic batch;
- a **failed fetch** keeps the last installed rules with a loud log — a
  bandage outage never opens the floodgates;
- **SIGINT/SIGTERM** reset the owned table before exit, so a clean
  shutdown leaves no stale rules;
- **`--dry-run`** prints the compiled ban rules without touching netlink
  and without privileges.

The report document is consumed as published: `splint-nft` parses the
contract, ignores unknown fields, refuses a document `version` it does
not know (keeping the last installed rules), and skips individual
malformed Reports with a log and a counter instead of failing the cycle.

## Flag reference

| flag | default | meaning |
|---|---|---|
| `--url`, `-u` | (required) | URL of the report document — bandage's `GET /reports`, e.g. `http://127.0.0.1:8080/reports`. `http` or `https` with a host. |
| `--hook` | `input` | Enforcement hook: `input` (a web server host) or `prerouting` (a routing box). Anything else is refused at startup. |
| `--netns` | (current namespace) | Target network namespace as a literal nsfs path, repeatable. **Replaces** the default target rather than adding to it. Empty values and duplicates are refused at startup. |
| `--cacert` | — | CA certificate file used to verify the bandage server's certificate (HTTPS). |
| `--cert` | — | Client certificate file presented to the server (mutual TLS). Must be given together with `--key`. |
| `--key` | — | Client key file. Must be given together with `--cert`. |
| `--fetch-timeout`, `-t` | `10s` | HTTP timeout for fetching the report document. Values below 1s are refused at startup. |
| `--update-interval`, `-i` | `5m` | How often the report document is refetched and the ruleset rebuilt. Values below 1m are clamped up to the 1m floor (with a warning). |
| `--exclude-prefix`, `-x` | — | Prefix excluded from every ban set, repeatable. A bare address counts as its host prefix. |
| `--exclude-private`, `-p` | `true` | Also exclude RFC1918 and ULA Targets. `--exclude-private=false` opts out. |
| `--service-port` | (all ports) | Service destination port the ban prefilter matches, repeatable; values 1–65535. |
| `--service-address` | (all addresses) | Service destination address or prefix the ban prefilter matches, repeatable. |
| `--dry-run`, `-d` | `false` | Fetch once, print the compiled ban rules and ruleset hash, exit — no netlink, no privileges. |
| `--log-level`, `-l` | `info` | Log level: `debug`, `info`, `warn` or `error`. |
| `--version`, `-v` | — | Print build identity and exit. |

Exit codes: `0` a clean run, `1` a load or run error, `2` a bad command
line. Operator logs go to stderr; `--dry-run` output goes to stdout.

There is deliberately no insecure mode: an unverified server is
refused, never accepted.

## The penalty → nftables mapping

| Penalty (`action`) | nftables construct |
|---|---|
| `drop` | verdict `drop` |
| `reject` | `reject with icmpx admin-prohibited` (TCP gets a reset automatically) |
| `limit-pkt-rate` | `limit rate over N/second`, then `drop` |
| `limit-bandwidth` | `limit rate bytes over N/second` on the egress chain, then `drop` |
| `limit-req-rate` | nothing — **declined** with a reason (application-layer intent), logged and counted |

The direction split: one **ingress** chain at the configured hook
carries `drop`, `reject` and `limit-pkt-rate`, matched on source ∈
Target; one **egress** chain carries `limit-bandwidth` meters matched on
destination ∈ Target — the response direction the Penalty's unit names
(response-payload bytes). In input mode the egress chain attaches at
output and the ingress chain at input (filter priority 0); in
prerouting mode the egress chain attaches at forward and the ingress
chain at prerouting (raw priority −300, so ban rules run before
conntrack). `limit-req-rate` is application-layer intent and is never
faked at the packet layer: the driver declines it with a reason and the
engine logs and counts every decline (ADR 0012 narrows ADR 0011).

Every limit is an aggregate over the Report's whole Target prefix, not
each host inside it. Rate limits carry a derived burst of one second's
worth of the rate (floored), so legitimate micro-bursts survive
enforcement. Every ban rule carries a packet/byte counter on the
traffic the rule matches — never the traffic its prefilter or Target
match lets past; nonzero hits are logged at each install — "since the
last change" (see the cycle logs below).

## Merge policy

Overlapping Reports resolve by most specific Target first, with the
strictest Penalty breaking ties:

1. **Most specific Target wins** (longest prefix): a `/32` Report can
   carve an exception under a `/16` ban rule even with a weaker Penalty.
2. **Ties on specificity resolve strictest first**: `drop` > `reject` >
   limits; within one limit action, a smaller `rate` is stricter.
3. **Dimensionally incomparable limits at a tie are combined** — one
   meter per dimension (packet rate, bandwidth, request rate), all
   enforced. No recommendation is lost to an invented ordering.

Reports group by (address family, prefix length, Penalty) into one ban
rule per group holding an equal-length prefix set; ban rules order by
prefix length descending, then strictness, so nftables first-match
reproduces the policy. The result does not depend on the order of the
document's Reports.

## Exclusions and the service prefilter

Exclusions are subtracted from every ban set before the merge,
overriding every Report:

- **Always excluded, never re-includable:** loopback (`127.0.0.0/8`,
  `::1/128`) and link-local (`169.254.0.0/16`, `fe80::/10`).
- **Excluded by default:** RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16`) and ULA (`fc00::/7`) — opt out with
  `--exclude-private=false`.
- **Operator exclusions:** `--exclude-prefix` adds to the list.

A Target fully covered by exclusions becomes no ban rule at all: its
Report is skipped with a log and a counter. A partially covered Target
keeps only its residual prefixes.

The **service prefilter** is the protected destination surface every
ban rule matches first: a ban rule applies only to traffic whose
destination port is in `--service-port` and whose destination address
is in `--service-address`. Either set may be empty, meaning all. The
prefilter is what keeps enforcement away from SSH, monitoring, and
unrelated forwarded traffic even when a Report targets a broad prefix.

## Auditing with --dry-run

Preview and verify a ruleset before enforcing it: run `splint-nft` with
`--dry-run` and **the same flags the service will run with** — the
exclusion and prefilter flags change the compiled ruleset, so audit
exactly what you will deploy:

```console
$ bin/splint-nft --dry-run --url http://127.0.0.1:8080/reports \
    --service-port 443 --service-address 203.0.113.10/32
```

The output on stdout has three parts: the compiled ban rules as
indented JSON, one mapping line per ban rule (`stance=… rate=…
chain=…` — the penalty → nftables mapping preview, with `rate=-` for
non-limits), and the ruleset's rolling hash as `hash=<hex>`. Skipped
Reports are logged on stderr. The same run with no policy flags
against the report document's canonical example (docs/reports.md)
prints:

```text
[
  {
    "targets": [
      "203.0.113.7/32"
    ],
    "prefilter": {
      "dst_ports": [],
      "dst_addrs": []
    },
    "stance": "limit-bandwidth",
    "rate": 1000000
  }
]
stance=limit-bandwidth rate=1000000 chain=egress
hash=42c6bdd2
```

Reading the output:

- **`targets`** are the ban set's prefixes after exclusion subtraction;
  `prefilter` shows the effective destination sets (empty = all).
- **`stance` and `rate`** name the compiled Penalty; the mapping line's
  `chain` is the chain it installs in (`ingress` or `egress`, or `-`
  when no packet-layer chain installs it — `limit-req-rate`, which the
  driver declines).
- **`hash=<hex>`** is the compiled ruleset's rolling hash. The same
  hash appears in every cycle's `compiled ban rules` log line, so an
  audited dry-run correlates with what the running installer later
  installs — and unchanged hashes mean the install is skipped.

Verify before enforcing: check that every Penalty in the document
resolves to the stance you expect, that no Target in `targets` is one
you rely on (jump boxes, monitoring), that the prefilter sets are the
service's real ports and addresses, and that the `hash=` matches on a
second identical run. Then deploy the same flags via the sample unit.

## Deploying: the sample systemd unit

The repo ships a sample unit at
[`configs/splint-nft.service`](../configs/splint-nft.service). It runs
`splint-nft` against a bandage endpoint on the host namespace:

```text
ExecStart=/usr/local/bin/splint-nft --url http://127.0.0.1:8080/reports
```

Install and enable:

```console
$ make build
$ install -m 0755 bin/splint-nft /usr/local/bin/splint-nft
$ install -m 0644 configs/splint-nft.service /etc/systemd/system/splint-nft.service
# edit /etc/systemd/system/splint-nft.service: point --url at your
# bandage endpoint (and add the flags you audited with --dry-run)
$ systemctl daemon-reload
$ systemctl enable --now splint-nft
$ journalctl -u splint-nft -f
```

`systemctl start` performs the startup test install; the journal shows
`startup test install ok` when the endpoint, flags and kernel all
check out. Installing nftables rules needs `CAP_NET_ADMIN` — the sample
unit runs as root by default and carries a commented block for a
dedicated user instead. A startup test install that keeps failing
(broken flags, endpoint or kernel) stops retrying and leaves the unit
failed — `systemctl status splint-nft` says why.

`systemctl stop` is SIGTERM: the owned table is reset before exit, so
stopping the service removes its ban rules. (A *crashed* installer
cannot reset — see the caveats.)

### The cycle logs

One update cycle, as captured (timestamps omitted):

```text
INF compiled ban rules hash=42c6bdd2 reports=1 rules=1 skipped=0
INF installed ban rules netns=current rules=1
INF startup test install ok
INF compiled ban rules hash=524f7991 reports=1 rules=1 skipped=0
INF ban rule hit bytes=2555 netns=current packets=22 rule=0
INF installed ban rules netns=current rules=1
INF compiled ban rules hash=524f7991 reports=1 rules=1 skipped=0
INF ban rules unchanged; skipping install hash=524f7991 netns=current
INF reset and exit
```

`compiled ban rules` logs every cycle's counts and the ruleset hash;
`installed ban rules` a changed install; `ban rule hit` the nonzero
counters of the rules just replaced (what enforcement did since the
last change); `ban rules unchanged; skipping install` the
skip-if-unchanged path; `reset and exit` the clean shutdown. A skipped
Report looks like `WRN skipped report record …` with its rule, Target
and reason; a failed fetch logs `update failed; keeping last installed
rules` and enforcement continues with the previous ruleset; an
unreachable namespace logs `namespace unreachable; skipping for the
cycle` while the others still install.

## Network namespaces

`--netns` targets one network namespace per flag value; the flags are
repeatable so one instance can enforce the same compiled ban rules
across several containers and the host (addressed by its own nsfs
path). `--netns` **replaces** the default target — the current
namespace is only included if you pass its path too. One fetch-compile
serves every namespace. The nsfs path is re-opened every cycle, so a
recreated container is picked up through a stable handle; a namespace
that cannot be opened is warned and skipped for the cycle.

**Stable handle via an `ip netns attach`-style name.** `ip netns attach
NAME PID` creates a named handle at `/run/netns/NAME` for whatever
namespace PID lives in (root required):

```console
$ ip netns attach splint-web "$(pgrep -n nginx)"
$ splint-nft --url http://127.0.0.1:8080/reports --netns /run/netns/splint-web
```

When the process is recreated, re-attach the name to its new pid
(`ip netns attach` again) and the next cycle picks it up — the path
never changes:

```console
$ ip netns attach splint-web "$(pgrep -n nginx)"
```

**Docker's per-pid namespace path.** A container's namespace is at
`/proc/<pid>/ns/net`, where `<pid>` is the container's init pid on the
host:

```console
$ docker inspect -f '{{.State.Pid}}' web
23456
$ splint-nft --url http://127.0.0.1:8080/reports --netns /proc/23456/ns/net
```

This handle dies with the container: a recreated container has a new
pid, and the stale path is warned and skipped each cycle. For a handle
that survives recreation, prefer the named form above and re-attach on
restart:

```console
$ ip netns attach splint-web "$(docker inspect -f '{{.State.Pid}}' web)"
$ splint-nft --url http://127.0.0.1:8080/reports --netns /run/netns/splint-web
```

## Caveats

- **Kernel floor: reject at prerouting needs roughly Linux 5.9.** On
  older kernels pick `--hook input`; the startup test install is the
  guard — an unsupported hook fails at deploy time, not at ban time.
- **TLS terminates at whatever fronts bandage.** Bandage itself serves
  plain HTTP; when a proxy fronts it with HTTPS (or mutual TLS), point
  `--url` at the proxy and use `--cacert` (and `--cert`/`--key`) as you
  would for any TLS client. There is no insecure mode.
- **A ban rule can outlive its Report by up to one update interval.**
  Expiry is rebuilt-based: a Report that expires between cycles keeps
  its ban rule until the next install. The 5-minute default bounds that
  to five minutes; a shorter `--update-interval` tightens it (1m floor).
- **One instance per namespace.** Each instance wholly owns one
  `splint` table; two instances in one namespace fight over it. Use
  `--netns` fan-out inside one instance instead.
- **The skip-if-unchanged probe is table existence, not rule bodies.**
  When the compiled ruleset hash is unchanged and the table exists, the
  install is skipped; tampering with rules under a surviving table is
  not detected.
- **A crashed installer leaves its table installed** until reboot or a
  manual `nft delete table inet splint`: only a clean exit resets the
  owned table.
- **An unreachable namespace only warns.** A wrong `--netns` path is
  warned and skipped every cycle — including at the startup test
  install, which can still report `ok`. After enabling the service,
  check the journal for `installed ban rules` on every target you
  intended.
