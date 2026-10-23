# splint: installing ban rules

`splint` is the companion binary that turns bandage's advice into
enforcement. It fetches the report document (`GET /reports`, see
[the report document](reports.md)) on a fixed interval, compiles every
[Report](../GLOSSARY.md) the document publishes into
[ban rules](../GLOSSARY.md) — the Report's [Target](../GLOSSARY.md)
prefixes plus the [Penalty](../GLOSSARY.md) as stated — and installs
them through the selected **[firewall driver](../GLOSSARY.md)**
(`--firewall`, nftables by default). The bandage daemon produces
Reports and never enforces; `splint` is the tool that derives ban rules
from Reports and installs them.

One binary serves every enforcement surface. The engine — report
fetch, contract parsing, exclusions, the merge policy, the update
lifecycle — speaks only ban rules. Everything about the enforcement
surface belongs to the firewall driver: where to enforce (its
targeting), what to police (its enforcement scope), how each Penalty
becomes real, and its own identity (the ruleset hash, the
skip-if-unchanged decision and the rule counters). A driver applies
each Penalty exactly as stated or declines it loudly — never
substitutes, weakens or tunes — and what it declines is logged and
counted so lost enforcement is visible (the decision of record is
[ADR 0012](adr/0012-enforcement-through-pluggable-firewall-drivers.md)).

This document is structured around drivers: a general section — the
engine's options, the merge policy, the exclusions, the lifecycle and
the `--dry-run` audit recipe — followed by one section per firewall
driver carrying that driver's options, recipes and caveats. The
nftables driver is the one that ships today.

## The update lifecycle

The lifecycle is built to fail at deploy time and never open the
floodgates:

- a **startup test install** runs one full fetch-compile-install before
  the loop begins — a broken flag, endpoint, or kernel exits non-zero at
  deploy time, not at ban time;
- every **update interval** (default 5m, floor 1m) refetches the
  document and rebuilds the ruleset wholesale; values below the 1m
  floor are clamped up with a warning;
- a **failed fetch** keeps the last installed rules with a loud log — a
  bandage outage never opens the floodgates;
- **SIGINT/SIGTERM** reset the owned ruleset before exit, so a clean
  shutdown leaves no stale ban rules;
- **`--dry-run`** prints the compiled ban rules and the driver's plan
  without touching any enforcement surface and without privileges.

The report document is consumed as published: `splint` parses the
contract, ignores unknown fields, refuses a document `version` it does
not know (keeping the last installed rules), and skips individual
malformed Reports with a log and a counter instead of failing the cycle.

## Engine options

These options configure the engine — the fetch, the policy and the
lifecycle. Driver-specific options live in the driver's own section;
`splint --help` groups the flags by owner (engine options first, then
one group per registered driver), verbatim as built:

```text
Usage of splint:

engine options:
      --cacert string              CA certificate file
      --cert string                client certificate file
  -d, --dry-run                    fetch and print the compiled ban rules once without installing
  -x, --exclude-prefix strings     prefix excluded from every ban set (repeatable)
  -p, --exclude-private            exclude RFC1918 and ULA targets (default true)
  -t, --fetch-timeout duration     set fetch HTTP timeout (default 10s)
      --firewall string            firewall driver: nftables (default "nftables")
      --key string                 client key file
  -l, --log-level string           log level: debug, info, warn or error (default "info")
  -i, --update-interval duration   report document update interval (clamped to a 1m floor) (default 5m0s)
  -u, --url string                 URL of the bandage report document
  -v, --version                    print version and exit

nftables driver options:
      --nft-hook string               enforcement hook: input or prerouting (default "input")
      --nft-netns stringArray         target network namespace nsfs path (repeatable; default: the current namespace)
      --nft-service-address strings   service destination address or prefix the ban prefilter matches (repeatable)
      --nft-service-port uints        service destination port the ban prefilter matches (repeatable) (default [])
```

| flag | default | meaning |
|---|---|---|
| `--firewall` | `nftables` | Firewall driver selected from the registry. An unknown value is refused at startup, listing the known drivers. Driver-specific flags live in their driver's own group (`--nft-*` for nftables); a flag of an unselected driver, set explicitly, is a usage error. |
| `--url`, `-u` | (required) | URL of the report document — bandage's `GET /reports`, e.g. `http://127.0.0.1:8080/reports`. `http` or `https` with a host. |
| `--cacert` | — | CA certificate file used to verify the bandage server's certificate (HTTPS). |
| `--cert` | — | Client certificate file presented to the server (mutual TLS). Must be given together with `--key`. |
| `--key` | — | Client key file. Must be given together with `--cert`. |
| `--fetch-timeout`, `-t` | `10s` | HTTP timeout for fetching the report document. Values below 1s are refused at startup. |
| `--update-interval`, `-i` | `5m` | How often the report document is refetched and the ruleset rebuilt. Values below 1m are clamped up to the 1m floor (with a warning). |
| `--exclude-prefix`, `-x` | — | Prefix excluded from every ban set, repeatable. A bare address counts as its host prefix. |
| `--exclude-private`, `-p` | `true` | Also exclude RFC1918 and ULA Targets. `--exclude-private=false` opts out. |
| `--dry-run`, `-d` | `false` | Fetch once, print the compiled ban rules, the driver's plan and its hash, exit — no enforcement surface touched, no privileges. |
| `--log-level`, `-l` | `info` | Log level: `debug`, `info`, `warn` or `error`. |
| `--version`, `-v` | — | Print build identity and exit. |

Exit codes: `0` a clean run (including `--dry-run` and `--version`), `1`
a configuration, load or run error (a refused flag value, a missing
`--url`, a failed fetch), `2` a refused command line (an unknown flag,
an unknown `--firewall` driver, a flag of an unselected driver). An
unknown driver value prints the known ones:

```text
unknown firewall driver "bogus" (known drivers: nftables)
```

Operator logs go to stderr; `--dry-run` output goes to stdout.

There is deliberately no insecure mode: an unverified server is
refused, never accepted.

## Merge policy

Overlapping Reports resolve by most specific Target first, with the
strictest Penalty breaking ties:

1. **The most specific Target wins, both ways**: the longer-prefix
   Report decides its own prefixes whether its Penalty is weaker or
   stronger than the broader one — a `/32` Report can carve an
   exception under a `/16` ban rule, or tighten it.
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

## Exclusions

Exclusions are subtracted from every ban set before the merge —
engine-side, before any driver sees the rules — overriding every
Report:

- **Always excluded, never re-includable:** loopback (`127.0.0.0/8`,
  `::1/128`) and link-local (`169.254.0.0/16`, `fe80::/10`).
- **Excluded by default:** RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16`) and ULA (`fc00::/7`) — opt out with
  `--exclude-private=false`.
- **Operator exclusions:** `--exclude-prefix` adds to the list.

A Target fully covered by exclusions becomes no ban rule at all: its
Report is skipped with a log and is counted in the cycle's `skipped`
count. A partially covered Target keeps only its residual prefixes.

## Auditing with --dry-run

Preview and verify a ruleset before enforcing it: run `splint` with
`--dry-run` and **the same flags the service will run with** — the
exclusion flags change the compiled ruleset and the driver's targeting
and scope flags change the driver's effective rules and hash, so audit
exactly what you will deploy:

```console
$ bin/splint --dry-run --url http://127.0.0.1:8080/reports \
    --nft-service-port 443 --nft-service-address 203.0.113.10/32
```

The output on stdout has three parts: the compiled ban rules as
indented JSON, one plan line per effective rule (`stance=… rate=…
placement=…` — with `rate=-` for non-limits) plus the declines with
reasons, and the ruleset's rolling hash as `hash=<hex>`. Skipped
Reports are logged on stderr. The same run with no policy flags
against the report document's canonical example (docs/reports.md)
prints:

```text
[
  {
    "targets": [
      "203.0.113.7/32"
    ],
    "stance": "limit-bandwidth",
    "rate": 1000000
  }
]
stance=limit-bandwidth rate=1000000 placement=egress@output
hash=7312084a
```

A document whose second Report carries a request-rate Penalty and
whose third Targets a fully excluded address shows what a decline and a
skip look like — stdout first, then the stderr log:

```text
[
  {
    "targets": [
      "203.0.113.7/32"
    ],
    "stance": "drop"
  },
  {
    "targets": [
      "203.0.113.9/32"
    ],
    "stance": "limit-req-rate",
    "rate": 5
  }
]
stance=drop rate=- placement=ingress@input
declined rule=1 feature=limit-req-rate reason=application-layer intent; never faked at the packet layer
hash=eeedb4e
```

```text
WRN skipped report record reason="target: fully excluded (got \"10.0.0.5/32\")" rule=lan-noise target=10.0.0.5/32
INF compiled ban rules reports=3 rules=2 skipped=1
```

Reading the output:

- **`targets`** are the ban set's prefixes after exclusion subtraction;
  targeting and enforcement scope are driver configuration, not part of
  the ban rule — they shape the plan's effective rules and the hash.
- **`stance` and `rate`** name the compiled Penalty; the plan line's
  `placement` names where the driver puts it (an opaque label like
  `egress@output`), and a Penalty the driver declines prints as a
  `declined rule=… feature=… reason=…` line instead of a plan line.
- **`hash=<hex>`** is the ruleset's rolling hash. The same hash appears
  in every cycle's `installed ban rules` log line, so an audited
  dry-run correlates with what the running installer later installs —
  and unchanged hashes mean the install is skipped.
- With several enforcement points the compiled rules print once and
  each driver instance's plan follows, headed by `point=<label>`:

```text
point=/run/netns/a
stance=drop rate=- placement=ingress@input
declined rule=1 feature=limit-req-rate reason=application-layer intent; never faked at the packet layer
hash=eeedb4e
point=/run/netns/b
stance=drop rate=- placement=ingress@input
declined rule=1 feature=limit-req-rate reason=application-layer intent; never faked at the packet layer
hash=eeedb4e
```

Verify before enforcing: check that every Penalty in the document
resolves to the stance you expect, that no Target in `targets` is one
you rely on (jump boxes, monitoring), that the driver's targeting and
scope flags match the service's real ports and addresses, and that the
`hash=` matches on a second identical run. Then deploy the same flags
via the sample unit.

## Firewall drivers

One firewall driver serves the whole run (`--firewall`; mixing drivers
per enforcement point is out of scope). The driver owns its targeting,
its enforcement scope and its identity: the rolling hash folds its
**effective** rules — after the Penalties it declines and whatever it
drops — so changing driver configuration re-enforces (the effective
rules changed), and its skip-if-unchanged probe and counter read-back
are its own. A flag set explicitly that belongs to an unselected
driver is refused at startup (`flag --X belongs to the Y driver, not
the selected Z driver`, exit 2). What a driver declines is logged per
rule and feature at every cycle.

### The nftables driver

The nftables firewall driver (`--firewall nftables`, the default)
installs ban rules into a wholly-owned nftables table (`splint`, inet
family) in the host's — or a chosen container's — network namespace.

#### Driver options

| flag | default | meaning |
|---|---|---|
| `--nft-hook` | `input` | Enforcement hook: `input` (a web server host) or `prerouting` (a routing box). Anything else is refused at startup. |
| `--nft-netns` | (current namespace) | Target network namespace as a literal nsfs path, repeatable. **Replaces** the default target rather than adding to it. Empty values and duplicates are refused at startup. |
| `--nft-service-port` | (all ports) | Service destination port the ban prefilter matches, repeatable; values 1–65535. |
| `--nft-service-address` | (all addresses) | Service destination address or prefix the ban prefilter matches, repeatable. |

#### Targeting: network namespaces and stable handles

`--nft-netns` targets one network namespace per flag value; the flags
are repeatable so one instance can enforce the same compiled ban rules
across several containers and the host (addressed by its own nsfs
path) — one driver instance per nsfs path, one fetch-compile serving
all of them. `--nft-netns` **replaces** the default target — the
current namespace is only included if you pass its path too. The nsfs
path is re-opened every cycle, so a recreated container is picked up
through a stable handle; a namespace that cannot be opened is warned
and skipped for the cycle.

**Stable handle via an `ip netns attach`-style name.** `ip netns attach
NAME PID` creates a named handle at `/run/netns/NAME` for whatever
namespace PID lives in (root required):

```console
$ ip netns attach splint-web "$(pgrep -n nginx)"
$ splint --url http://127.0.0.1:8080/reports --nft-netns /run/netns/splint-web
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
$ splint --url http://127.0.0.1:8080/reports --nft-netns /proc/23456/ns/net
```

This handle dies with the container: a recreated container has a new
pid, and the stale path is warned and skipped each cycle. For a handle
that survives recreation, prefer the named form above and re-attach on
restart:

```console
$ ip netns attach splint-web "$(docker inspect -f '{{.State.Pid}}' web)"
$ splint --url http://127.0.0.1:8080/reports --nft-netns /run/netns/splint-web
```

**One instance per enforcement point.** Each instance wholly owns the
`splint` table in every namespace it targets; two instances targeting
the same namespace fight over it. Use `--nft-netns` fan-out inside one
instance instead of stacking instances.

#### Enforcement scope: the service prefilter

The **service prefilter** is the protected destination surface every
effective rule matches first: a ban rule applies only to traffic whose
destination port is in `--nft-service-port` and whose destination
address is in `--nft-service-address`. Either set may be empty,
meaning all. It is what keeps enforcement away from SSH, monitoring,
and unrelated forwarded traffic even when a Report targets a broad
prefix:

```console
$ bin/splint --url http://127.0.0.1:8080/reports \
    --nft-service-port 443 --nft-service-address 203.0.113.10/32
```

The prefilter is folded into the driver's effective rules and therefore
its ruleset hash, so changing it re-enforces.

#### The Penalty → nftables mapping

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
chain at prerouting (raw priority −300, so ingress ban rules run
before conntrack). The placement labels in the dry-run plan name the same
split — `ingress@input` and `egress@output` in input mode,
`ingress@prerouting` and `egress@forward` in prerouting mode.
`limit-req-rate` is application-layer intent and is never faked at the
packet layer: the driver declines it with a reason and the engine logs
and counts every decline (ADR 0012 narrows ADR 0011).

Every limit is an aggregate over the Report's whole Target prefix, not
each host inside it. Rate limits carry a derived burst of one second's
worth of the rate (floored), so legitimate micro-bursts survive
enforcement. Every ban rule carries a packet/byte counter on the
traffic the rule matches — never the traffic the prefilter or Target
match lets past; nonzero hits are logged at each install — "since the
last change" (see the cycle logs below).

#### Known limitation: first-match meter stances

A rate meter matches only once its rate is exceeded: the drop applies
to the excess while in-rate traffic falls through to the next rule. So
when a meter stance carves an exception under a broader ban rule (the
merge policy puts the more specific Target first), the in-rate traffic
of that Target is **not** exempted — it falls through the meter rule
and the broader ban rule below still drops it. This first-match nuance
is a known limitation of the nftables driver; fixing it is a
driver-policy question, not part of this tool's contract.

#### Driver caveats

- **Kernel floor: reject at prerouting needs roughly Linux 5.9.** On
  older kernels pick `--nft-hook input`; the startup test install is
  the guard — an unsupported hook fails at deploy time, not at ban
  time.
- **An unreachable enforcement point only warns.** A wrong
  `--nft-netns` path is warned and skipped every cycle — including at
  the startup test install, which can still report `ok` (as captured,
  excerpt):

```text
WRN enforcement point unreachable; skipping for the cycle error="apply: enforcement point unreachable: open netns /run/netns/nonexistent: open /run/netns/nonexistent: no such file or directory" point=/run/netns/nonexistent
INF startup test install ok
```

  After enabling the service, check the journal for `installed ban
  rules` on every target you intended.

## Deploying: the sample systemd unit

The repo ships a sample unit at
[`configs/splint.service`](../configs/splint.service). It runs
`splint` against a bandage endpoint on the host namespace:

```text
ExecStart=/usr/local/bin/splint --url http://127.0.0.1:8080/reports
```

Install and enable:

```console
$ make build
$ install -m 0755 bin/splint /usr/local/bin/splint
$ install -m 0644 configs/splint.service /etc/systemd/system/splint.service
# edit /etc/systemd/system/splint.service: point --url at your
# bandage endpoint (and add the flags you audited with --dry-run)
$ systemctl daemon-reload
$ systemctl enable --now splint
$ journalctl -u splint -f
```

`systemctl start` performs the startup test install; the journal shows
`startup test install ok` when the endpoint, flags and kernel all
check out. Installing nftables rules needs `CAP_NET_ADMIN` — the sample
unit runs as root by default and carries a commented block for a
dedicated user instead. A startup test install that keeps failing
(broken flags, endpoint or kernel) stops retrying and leaves the unit
failed — `systemctl status splint` says why.

`systemctl stop` is SIGTERM: the owned ruleset is reset before exit, so
stopping the service removes its ban rules. (A *crashed* installer
cannot reset — see the caveats.)

### The cycle logs

A full session as captured against a scratch endpoint (timestamps
omitted; the document held a `drop` Report and a `limit-req-rate`
Report, ten packets arrived from the banned Target between installs,
the endpoint went down before one cycle and came back with one more
`drop` Report, and SIGTERM ended the run):

```text
INF compiled ban rules reports=2 rules=2 skipped=0
INF installed ban rules declined=1 hash=eeedb4e point=current rules=2
WRN declined ban rule feature feature=limit-req-rate point=current reason="application-layer intent; never faked at the packet layer" rule=1
INF startup test install ok
ERR update failed; keeping last installed rules error="fetch: Get \"http://127.0.0.1:18090/reports\": dial tcp 127.0.0.1:18090: connect: connection refused"
INF compiled ban rules reports=3 rules=2 skipped=0
INF ban rule hit bytes=2280 packets=10 point=current rule=0
INF installed ban rules declined=1 hash=6d303a1c point=current rules=2
WRN declined ban rule feature feature=limit-req-rate point=current reason="application-layer intent; never faked at the packet layer" rule=1
INF compiled ban rules reports=3 rules=2 skipped=0
INF ban rules unchanged; skipping install hash=6d303a1c point=current
WRN declined ban rule feature feature=limit-req-rate point=current reason="application-layer intent; never faked at the packet layer" rule=1
INF reset and exit
```

`compiled ban rules` logs every cycle's counts (the two `drop` Reports
group into one ban rule, hence `reports=3 rules=2`); `installed ban
rules` a changed install with its ruleset hash and its `declined`
count; `declined ban rule feature` the lost enforcement of every
declined feature, logged each cycle; `ban rule hit` the nonzero
counters of the rules just replaced — the ten packets the ban rule
dropped since the last change; `update failed; keeping last installed
rules` a failed fetch (the `error` field carries the cause);
`ban rules unchanged; skipping install` the skip-if-unchanged path;
`reset and exit` the clean shutdown. A skipped Report looks like `WRN
skipped report record …` with its rule, Target and reason (see the
dry-run section); an unreachable enforcement point logs `enforcement
point unreachable; skipping for the cycle` while the others still
install.

## Cross-cutting caveats

- **TLS terminates at whatever fronts bandage.** Bandage itself serves
  plain HTTP; when a proxy fronts it with HTTPS (or mutual TLS), point
  `--url` at the proxy and use `--cacert` (and `--cert`/`--key`) as you
  would for any TLS client. There is no insecure mode.
- **A ban rule can outlive its Report by up to one update interval.**
  Expiry is rebuilt-based: a Report that expires between cycles keeps
  its ban rule until the next install. The 5-minute default bounds that
  to five minutes; a shorter `--update-interval` tightens it (1m floor).
- **The skip-if-unchanged probe is ruleset existence, not rule
  bodies.** (For nftables: table existence.) When the ruleset hash is
  unchanged and the owned ruleset exists, the install is skipped;
  tampering with rules under a surviving ruleset is not detected.
- **A crashed installer leaves its ruleset installed** until reboot or
  a manual reset (for nftables: `nft delete table inet splint`): only a
  clean exit resets what the instance owns.
