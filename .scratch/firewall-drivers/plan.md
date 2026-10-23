# splint firewall-driver refactor — plan

**Status:** superseded by `spec.md` in this directory (the grilling
session reshaped targeting and enforcement scope as driver-owned — see
`spec.md`, which is authoritative). Kept as the design-session record.

**Base:** on top of `feat/splint-nft` (the splint work it refactors is not yet on `main`)

## Requirements (what this plan must deliver)

1. `internal/identity` refactored so bandage and splint use it equally —
   today splint is the "more external" consumer (`identity.Summary(progName)`
   bolted on beside `const Name = "bandage"` and the `String()`/`Header()`
   path the daemon uses).
2. `splint-nft` renamed to **`splint`**; nftables encapsulated behind a
   **firewall abstraction**; the report fetch/merge engine ignorant of the
   concrete firewall driver (other drivers may come later).
3. The user chooses the firewall driver (`nft` is the only one for now);
   driver-specific arguments are grouped.
4. The compiled artifact keeps **all** report features; each firewall driver
   decides whether/how to apply them (e.g. `limit-req-rate`).
5. Rolling hash / skip-if-unchanged / counters move **into the firewall
   driver**: only the driver knows which rules are actually effective and
   which it drops.

## Current state (what moves where)

| Concern | Today | After |
|---|---|---|
| Build identity | `identity.Name` const + `String()`/`Header()` for bandage; `Summary(name)` for splint | one `identity.For(name)` value both commands use equally |
| Compiled artifact | `splint.BanRule{Targets, Prefilter, Stance, Rate}`; `mapPenalty` drops `limit-req-rate` at compile time | `firewall.BanRule` carrying the merged **penalty as stated** (all five actions) |
| Merge policy | `splint/compile.go` (`merge`/`resolve`/`strictest`) | unchanged location (engine), vocabulary grows to five actions |
| nftables encoding | `internal/splint/nft` implements `splint.Driver` | `internal/firewall/nft` implements `firewall.Driver` |
| Rolling hash | `splint/hash.go`, engine hashes `[]BanRule`, per-namespace `nsState` in `updater.go` | inside the driver: it hashes its **effective** rules; skip state = per driver instance |
| Skip probe | `Driver.TableExists()` on the port, engine decides | inside the driver's `Apply` |
| Counters | driver reads, engine maps/logs | driver reads and reports in its result |
| Stub | `splint.Stub` recording `Install`/`Reset`/`TableExists` | `firewalltest.Stub` recording `Apply`/`Reset` outcomes |
| CLI | `cmd/splint-nft`, `--hook` among engine flags | `cmd/splint`, `--firewall`, grouped `--nft-*` flags |
| Docs | `docs/splint-nft.md`, `configs/splint-nft.service` | `docs/splint.md`, `configs/splint.service` |

## Target design

### 1. Identity: one API, two names

`internal/identity` exposes a value both commands build identically:

```go
// identity.For("bandage") / identity.For("splint")
type Build struct { /* name + the four linker-injected values + derived */ }
func For(name string) Build
func (b Build) String() string   // one-line summary (`-v`)
func (b Build) Header() string   // short identity (`--test`, `-h`)
func (b Build) Name() string
// Version()/Commit()/BuildDate()/Dirty()/GoVersion()/Platform() as methods
```

- The four linker-injected vars stay package-level (the Makefile's `-X`
  stamps are unchanged; both binaries already share `BUILD_FLAGS`).
- `const Name`, package-level `String()`/`Header()`/`Summary(name)` go away;
  `cmd/bandage` and `cmd/splint` each call `identity.For(...)` with their own
  name. Daemon call sites (`internal/app` uses `Header()` for `--test`/`-h`)
  change mechanically; the **rendered output for bandage must not change**
  (existing identity tests pin it).
- Format stays byte-identical to today (`buildSummary`/`buildHeader` logic,
  just methodized).

### 2. The firewall module: a deep driver seam

New package **`internal/firewall`** — the port. Adapters:
**`internal/firewall/nft`** (the nftables implementation) and
**`internal/firewall/firewalltest`** (the recording stub, test surface of the
engine). Dependency direction: the engine (`internal/splint`) and every
adapter import `firewall`; the engine never imports an adapter; only
`cmd/splint` wires them together (extend `deps_test.go` with an
"engine imports no adapter" rule).

Shared vocabulary types live in `firewall` (they are what crosses the seam):

```go
type Target struct{ NetNSPath string } // "" = current namespace

type Penalty struct {          // the report's Penalty, as stated, post-merge
    Action Action              // drop | reject | limit-pkt-rate |
                               // limit-bandwidth | limit-req-rate
    Rate   *int64              // non-nil exactly for the limits
}

type Prefilter struct { DstPorts []uint16; DstAddrs []netip.Prefix }

type BanRule struct {          // one merged group: equal-length prefix set
    Targets   []netip.Prefix
    Prefilter Prefilter
    Penalty   Penalty
}
```

Note the naming: the compiled artifact's stance vocabulary becomes identical
to the report's closed penalty vocabulary (all five values; today the compiler
already folds into `Stance`, which the GLOSSARY keeps distinct from the
reserved term *Action*). The `Chain` type (`ingress`/`egress`) leaves the
engine entirely — chain/direction placement is nft's own shape.

The **interface** (three methods — all the encoding, identity, probing and
counting behaviour hides behind them):

```go
// Driver is one firewall backend bound to one Target. The engine calls
// it serially; implementations must be safe to Apply repeatedly.
type Driver interface {
    // Plan reports what Apply would do — pure: no I/O, no privileges.
    // --dry-run prints exactly this.
    Plan(rules []BanRule) (Plan, error)

    // Apply makes the rules effective on the target, replacing the
    // wholly-owned ruleset atomically. It skips the install when the
    // plan's hash matches the last hash it applied AND the owned
    // ruleset still exists (probed now); otherwise it installs and
    // reports the nonzero counters of the rules it replaced.
    Apply(rules []BanRule) (Outcome, error)

    // Reset removes the owned ruleset; already-absent is not an error.
    Reset() error
}

type Plan struct {
    Hash    string         // rolling hash of the EFFECTIVE rules
    Rules   []PlannedRule  // what would actually be installed, in order
    Skipped []Skipped      // input features this driver declines
}
type PlannedRule struct {
    Rule      int            // index into the input []BanRule (correlation)
    Placement string         // opaque label for logs ("chain 'ingress@input'")
    Action    Action         // what the driver will do (may differ from input)
    Rate      *int64
    Targets   []netip.Prefix
    Prefilter Prefilter
}
type Skipped struct{ Rule int; Feature, Reason string }
type Outcome struct {
    Applied bool    // false = skipped: unchanged hash + ruleset present
    Hash    string
    Skipped []Skipped
    Hits    []Hit   // nonzero counters of the replaced ruleset
}
type Hit struct{ Rule int; Packets, Bytes uint64 }
```

`ErrUnreachable` moves to `firewall` (target reachability is part of the
seam's contract: the engine warns-and-skips one dead namespace per cycle and
tolerates vanished namespaces on reset).

Depth check (why this is a deep module): the engine learns three methods and
gets — nftables family/interval encoding, hook→chain/priority mapping
(input→filter/0, prerouting→raw/−300), the egress direction split, the
derived burst, per-family reachability of the prefilter, atomic batch with
the delete-probe subtlety, the rolling hash, skip-if-unchanged, the
existence probe, counter read-back and per-rule skip reporting. Deleting the
driver would scatter all of that back across the engine.

### 3. Driver selection and grouped flags

- `--firewall=nft` (default `nft`). `cmd/splint` holds a small registry:
  `map[string]firewall.Factory`. Unknown value → usage error listing the
  known drivers.
- `firewall.Factory` is a small interface: `Name()`, `BindFlags(*pflag.FlagSet)`,
  `Validate() error`, `Open(Target) (Driver, error)` (`Open` is lazy — no
  I/O until `Apply`, which is what keeps `--dry-run` unprivileged).
- **Grouped driver flags**: each factory binds its own prefixed flags —
  today `--hook` becomes **`--nft-hook=input|prerouting`** (the only
  driver-specific flag that exists). The usage printer groups flags by owner
  ("engine options" / "nftables driver options"). Validation rejects flags
  belonging to an unselected driver when explicitly set (pflag `Changed`),
  so `--nft-hook` with `--firewall=pf` is a usage error, not silence.
- **`--netns` stays an engine flag** (target selection — WHERE to enforce),
  flowing into `firewall.Target`; a driver that cannot target a namespace
  fails its `Open`/startup install loudly. Rationale: nsfs paths are the
  Linux target mechanism, not an nft mechanism (iptables/eBPF drivers need
  the same targeting). Alternative considered: grouping it under `--nft-*`
  because `WithNetNSFd` is netlink plumbing — rejected: that leaks the
  adapter's mechanism into the operator surface. *(open decision A)*

### 4. All report features preserved; the driver decides

- The compiler stops translating penalties into nft-shaped stances and stops
  skipping `limit-req-rate`. `Compile` keeps the merged penalty **as stated**
  (all five actions) in `firewall.BanRule`. Parse-level tolerances stay
  engine-side (unknown/missing penalty, unparseable Target, fully excluded
  Target → `Skip`, logged and counted).
- Merge policy is unchanged as *policy* (most specific wins both ways;
  `drop` > `reject` > limits; smaller rate stricter within one action;
  incomparable limit dimensions combine) — it is expressed over the five
  values now, with `limit-req-rate` a third limit dimension that combines
  like the others and never "loses to an invented ordering".
- The **nft adapter** applies `drop`, `reject`, `limit-pkt-rate`,
  `limit-bandwidth` (as today) and **declines `limit-req-rate`** with
  `Skipped{Feature: "limit-req-rate", Reason: "application-layer intent;
  not applied at the packet layer (ADR 0011)"}` — the skip moves from the
  compiler to the driver, and the engine logs/counts it from `Outcome`.
- **Behaviour on nft is preserved** (analysis worth keeping): because the
  merge encodes exceptions by first-match rule order and a declined group
  installs nothing, a `limit-req-rate` report's effect on nft is the same as
  today's pre-merge skip in every case examined (most-specific exception →
  broader rules still match; ties → strictest/combined outcome identical;
  alone → nothing installed). The difference is that a future driver that
  *can* apply request-rate limits now receives them.

### 5. Hash / skip / counters live in the driver

- The rolling-hash **construction** (bandaid's: seed `114514`, per-item fresh
  FNV-1a 32-step fed prev big-endian, fields `0x00`-delimited) ships as tiny
  helpers in `firewall` so every adapter folds "familiar" hashes; what is
  folded is the adapter's **effective** rules (post-decline, post-family
  reachability, in install order). `splint/hash.go` is deleted.
- Skip-if-unchanged and the existence probe move inside `Apply`: the skip
  state is per driver instance (per namespace — today's `nsState` bookkeeping
  disappears from `updater.go`), and the probe is the adapter's own. The
  documented limit stays (existence, not rule bodies).
- Counters: read inside `Apply` (only the adapter knows the kernel-rule ↔
  ban-rule mapping) and reported as `Outcome.Hits`; the engine keeps the
  logging ("ban rule hit", period since last change). A skipped cycle logs
  the skip and no hits.
- `--dry-run` prints the engine's compiled rules **and** the driver's `Plan`
  (effective rules with placement/action/rate lines, `Skipped`, `hash=<hex>`).
  Output shape stays close to today's; the mapping lines and hash now come
  from the adapter, so a future driver prints its own.

### Internal seam inside the nft adapter

The nft adapter splits into an encoding+identity layer (pure) and a thin
netlink layer behind a private interface (list/flush/close on a connection).
That is the adapter's **internal seam**: skip-if-unchanged, hash folding,
counter parsing and batch construction become testable **unprivileged** with
a fake kernel, while the existing root-gated kernel test keeps verifying real
encoding (install → read back → reset). This is replace-don't-layer: the fake
stands in for the kernel, it doesn't wrap the real one.

## Engine (`internal/splint`) after the refactor

- `wire`, `policy` (exclusions + prefilter), `compile` (parse tolerance +
  merge), `fetch`, `updater` (lifecycle) stay; `compile`'s output type moves
  to `firewall.BanRule`; `hash.go`, `driver.go` (port), `Stance`/`Chain` and
  `mapPenalty` leave.
- `Updater` holds `[]struct{ target firewall.Target; driver firewall.Driver }`
  and per cycle: fetch → parse → compile → `Apply` on each → log
  `Outcome` (applied / unchanged-skip + hash / hits / declined features).
  Startup test install, keep-last-on-failed-fetch, SIGINT/SIGTERM reset
  tolerating vanished namespaces — all unchanged behaviour.
- `DryRun`: fetch → compile → `Plan` on one driver → print (no netlink).

## CLI surface after

```
splint --url URL --firewall nft --nft-hook input
       [--netns PATH ...] [--cacert F --cert F --key F] [--fetch-timeout D]
       [--update-interval D] [--exclude-prefix P ...] [--exclude-private]
       [--service-port N ...] [--service-address A ...]
       [--dry-run] [--log-level L] [--version]
```

Flag migration: `--hook` → `--nft-hook`; new `--firewall`; `--netns`,
`--cacert`, `--cert`, `--key`, `--fetch-timeout`, `--update-interval`,
`--exclude-prefix`, `--exclude-private`, `--service-port`, `--service-address`,
`--dry-run`, `--log-level`, `--version` unchanged. The tool is unreleased, so
no compatibility shim; the sample unit and docs ship renamed.

## Domain docs

- `docs/splint.md` (renamed): flag reference with the driver group; the
  penalty→nftables mapping table becomes "what the nft driver does with each
  Penalty" (its decline row for `limit-req-rate` included); merge policy and
  caveats stay; the kernel floor (~5.9) moves under the nft driver section
  (it is a driver caveat, not a tool caveat). TLS-termination, ban staleness,
  one-instance-per-namespace caveats and netns recipes unchanged.
- GLOSSARY: Ban rule entry names `splint` (was `splint-nft`).
- **ADR 0012** ("splint applies penalties through pluggable firewall
  drivers"): records (1) the rename, (2) the driver flag + grouped flags,
  superseding ADR 0011's "sibling binary, not a driver flag" decision,
  (3) the compiler keeping the penalty vocabulary total with drivers deciding
  application, (4) hash/skip/counters living in the driver because only it
  knows the effective rules. ADR 0011 gains a superseded-in-part note (same
  pattern ADR 0004 uses).
- The original `.scratch/nft-installer/spec.md` is a record of that effort —
  its "no user-facing `--firewall-driver` in v0" decision is what ADR 0012
  supersedes; leave the spec as history.

## Work breakdown (suggested tickets)

1. **Identity refactor** — `identity.For(name)` API, both commands equal;
   output for bandage byte-identical (pinned tests). Independent, small.
2. **Firewall port + type move** — `internal/firewall` with `BanRule`/
   `Penalty`/`Target`/`Driver`; engine produces `firewall.BanRule`;
   `internal/firewall/nft` + `firewalltest.Stub` moved behind the port;
   `deps_test.go` rule. Behaviour unchanged (hash still engine-side here or
   moved in 3 — prefer doing 2 and 3 as one ticket if the diff stays
   reviewable).
3. **Driver-owned identity** — hash/skip/probe/counters into `Apply`/`Plan`;
   `updater` slims; dry-run prints the driver's `Plan`; nft internal seam
   (fake kernel) with the skip matrix (identical twice / changed / missing
   ruleset / counter reads) moved here unprivileged.
4. **Penalty pass-through** — compiler keeps all five actions; merge policy
   over five values; `limit-req-rate` decline becomes the nft adapter's
   `Skipped` (engine logs/counts); new merge cases (req-rate participation,
   combination at ties).
5. **CLI + rename** — `--firewall`, grouped `--nft-*` flags + validation,
   `cmd/splint`, `bin/splint`, `configs/splint.service`, docs rename and the
   mapping-table restructure.
6. **Domain docs** — ADR 0012 + ADR 0011 note + GLOSSARY entry (follow
   `docs/agents/domain.md` / domain-modeling conventions).

Order 1 → 2 → 3 → 4 → 5 → 6; 4 and 5 can be parallel after 3.

## Testing strategy

- **Engine seam** (unchanged in spirit): fake report endpoint + recording
  stub driver; assert which `firewall.BanRule`s reach the driver and what the
  engine logs from `Outcome` (keep-last, reset-on-exit, startup install,
  skip-and-warn per namespace, parse tolerances, exclusion/prefilter,
  merge matrix incl. the new five-value cases, dry-run text).
- **Nft adapter suite** (new internal seam, unprivileged): hash fold, skip
  matrix (identical twice / changed / missing ruleset / probe-per-cycle),
  counter parsing → `Hits`, declined `limit-req-rate` → `Skipped`, batch
  construction incl. the delete-probe ENOENT subtlety and the top-of-space
  interval encoding.
- **Root-gated kernel test** (kept): install → read back both chains →
  reset; gains "declined features install nothing".
- Convention throughout: failing + passing case per validation; assertions on
  externally visible effects only (installed rules, call counts, outcomes);
  no hash-value pins.

## Open decisions (recommendations in brackets)

- **A. `--netns` engine flag vs driver flag** [engine flag; see §3].
- **B. Artifact naming**: keep `Stance` for the compiled artifact (GLOSSARY
  reserves *Action*) with its vocabulary grown to five [`Stance`], or rename
  the field to `Penalty` for symmetry with the report.
- **C. Hash helpers in the port vs per-adapter folds** [shared construction
  helpers in `firewall`, per-adapter folding — keeps the bandaid-familiar
  construction without leaking engine state].
- **D.** The known first-match fall-through nuance (a *meter* exception under
  a broader ban doesn't exempt in-rate traffic) is unchanged by this refactor;
  if ever operationally needed it becomes an adapter policy (e.g. a terminal
  within-rate verdict). Keep out of scope [yes].
- **E.** `PlannedRule.Placement` label wording for dry-run/logs (opaque to
  the engine) — pick during implementation.

## Out of scope

- Any new firewall backend (the abstraction makes room; nothing but nft
  ships).
- Changing the merge policy, exclusion defaults or prefilter semantics.
- In-kernel self-expiry, rule-body tampering detection, metrics export —
  unchanged from the original spec's out-of-scope list.
