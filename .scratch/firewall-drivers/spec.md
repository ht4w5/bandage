# splint: pluggable firewall drivers — spec

Status: ready-for-agent

## Problem Statement

`splint` is an nftables tool wearing a general name. Everything
enforcement-surface-specific leaks through the binary: the compiled ban
rule is nft-shaped (a stance with an ingress/egress chain split), the
namespace targeting and the service prefilter sit among generic engine
flags, and the rolling hash, skip-if-unchanged and counters live in the
engine even though only the kernel driver knows which rules were
actually installed and which it dropped. The compiler drops
`limit-req-rate` before any enforcement backend exists to decide about
it. The build-identity package treats bandage as the name and splint as
a bolted-on parameter. And the name `splint-nft` names the artifact the
tool manages, not the tool.

The consequence the operator feels: a second enforcement surface —
nginx, a WAF, anything that can ban a source — means a sibling binary
re-implementing the fetch, the merge and the lifecycle, or a fork of
this one. The one thing that varies (how bans become enforcement) is
the one thing not pluggable.

## Solution

One binary, `splint`, whose `--firewall` flag selects a **firewall
driver** (the nftables driver in v0). The engine — report fetch,
contract parsing, exclusions, the merge policy, the update lifecycle —
speaks only ban rules: Target prefixes plus the Penalty as stated. A
driver owns everything about its enforcement surface: where to enforce
(its targeting), what to police (its enforcement scope), how penalties
become real, and its own identity — the rolling hash, the
skip-if-unchanged decision and the counters — because only it knows the
effective rules. A driver applies each Penalty exactly as stated or
declines it loudly; what it declines is reported so the operator can see
lost enforcement in the logs. Driver-specific arguments are grouped
under the driver's namespace and validated at startup. Both binaries
draw their build identity from the same API as equals.

For the operator with the nftables driver, nothing changes: the same
table, the same rules, the same logs, the same behaviour — the seams
move, the enforcement does not.

## User Stories

1. As an operator, I want to select the firewall driver with a flag
   defaulting to nftables, so that one binary serves every enforcement
   surface without a new command per backend.
2. As an operator, I want every driver-specific argument grouped under
   its driver, so that I can see at a glance which settings belong to
   the thing that enforces.
3. As an operator, I want setting a flag belonging to an unselected
   driver refused at startup, so that a mistyped combination fails
   loudly instead of silently not applying.
4. As an operator, I want namespace targeting as driver configuration
   (nftables: repeatable nsfs paths), so that enforcement points are
   declared in the vocabulary of the thing that reaches them.
5. As an operator, I want enforcement scope as driver configuration
   (nftables: the service prefilter of destination ports and
   addresses), so that a surface that only ever sees its own traffic
   (a web server) is not burdened with kernel-firewall scoping.
6. As an operator, I want my exclusion prefixes subtracted from every
   ban set before any driver sees them, so that my safety margins hold
   regardless of which driver enforces.
7. As an operator, I want skip-if-unchanged per enforcement point, so
   that a quiet cycle costs no enforcement churn anywhere.
8. As an operator, I want the ruleset hash logged each cycle and printed
   by the dry run, so that I can correlate what was enforced across
   runs.
9. As an operator, I want an unchanged ruleset with a vanished
   enforcement point to reinstall, so that a recreated container or an
   external reset cannot hide behind an unchanged hash.
10. As an operator, I want per-rule counters with nonzero hits logged at
    each install, so that I can see whether a ban is firing.
11. As an operator, I want a startup test install that fails non-zero on
    a broken config, endpoint, missing privileges or unsupported
    kernel, so that problems surface at deploy time, not at ban time.
12. As an operator, I want a failed fetch to keep the last enforced
    rules with a loud log, so that an upstream outage never opens the
    floodgates.
13. As an operator, I want SIGINT and SIGTERM to reset the owned ruleset
    before exit, tolerating enforcement points that vanished, so that
    stale bans never outlive a clean shutdown.
14. As an operator, I want an unreachable enforcement point warned and
    skipped for the cycle while the others still enforce, so that one
    dead container cannot halt enforcement everywhere.
15. As an operator, I want the update interval to default to five
    minutes with a one-minute floor, so that bans and un-bans track
    report expiry within minutes without timer churn.
16. As an operator, I want the fetch surface unchanged — plain HTTP
    locally, mutual TLS remotely, bandaid's certificate flags and fetch
    timeout, no insecure mode — so that my PKI runbook keeps working.
17. As an operator, I want `--dry-run` to print the compiled ban rules
    and the selected driver's plan — effective rules, placement, what
    it declines, and the hash — without touching any enforcement
    surface or requiring privileges, so that I can audit anywhere.
18. As an operator, I want the tool named `splint` — binary, unit and
    docs — so that the name describes the tool, not the artifact it
    manages.
19. As an operator, I want bandage and splint to print their build
    identity the same way from the same source, so that neither looks
    like an afterthought.
20. As an operator, I want the one-instance-per-namespace discipline and
    stable-handle recipes documented under the nftables driver, so that
    deployment is copy-paste for the driver I actually run.
21. As a rule author, I want my report's Penalty applied exactly as
    stated, so that my enforcement stance reaches the enforcement
    surface faithfully or not at all.
22. As a rule author, I want `limit-req-rate` applied by drivers whose
    surface is the application layer and declined — logged and counted
    — by packet-layer drivers, so that request-rate intent is never
    faked at the packet layer and never silently lost.
23. As a rule author, I want overlapping reports resolved unchanged: the
    most specific Target wins even with a weaker stance, ties resolve
    strictest-first (`drop` > `reject` > limits, smaller rate stricter
    within one action), and dimensionally incomparable limits combine,
    so that conflicting advice resolves deterministically.
24. As a rule author, I want bans to expire with their reports through
    the full rebuild each cycle, so that un-bans happen without manual
    action.
25. As a developer, I want the report fetch and merge ignorant of the
    firewall driver — the engine imports no adapter — so that a new
    enforcement surface never touches engine code.
26. As a developer, I want adding a driver to mean implementing the
    firewall seam and registering its factory (its flags, its targets,
    its scope), so that the cost of a new backend is one module.
27. As a firewall-driver author, I want the engine to hand me ban rules
    carrying the Penalty as stated, so that I decide what my surface can
    honour and report the rest as declines.
28. As a firewall-driver author, I want the rolling hash, the
    skip-if-unchanged probe and the counters inside my driver, so that
    identity reflects my effective rules — what I actually installed,
    after what I dropped.
29. As a firewall-driver author, I want a generic unreachable-point
    error in the seam contract, so that the engine's warn-and-skip and
    reset-tolerance behaviour comes for free.
30. As a developer, I want the stub driver to remain the update-cycle
    test surface, so that lifecycle behaviour stays testable
    unprivileged.
31. As a developer, I want the nftables driver's plan/apply logic tested
    against a fake kernel, so that hash, skip, counters and batch
    construction are verified without privileges.
32. As a developer, I want the root-gated kernel test kept for encoding
    only — install, read back, reset, declines-install-nothing — so
    that the kernel surface is verified wherever privileges exist.
33. As a developer, I want tests to assert only which ban rules would be
    installed, when, and what outcomes are reported, so that compilers
    and drivers stay refactorable.

## Implementation Decisions

- **Rename**: the tool is `splint` everywhere operator-facing — binary,
  command, sample systemd unit, consumer doc. No compatibility shims for
  the old name or old flag spellings; the tool is unreleased. The
  compiled artifact keeps the name **Stance** (the GLOSSARY reserves
  Action for rule steps); the wire DTOs keep mirroring the contract's
  `penalty.action` naming.
- **Build identity**: the identity package exposes a per-name build
  value built from the four linker-injected stamps; both commands
  construct it with their own name and use the same accessors
  (summary, header). bandage's rendered identity output stays
  byte-identical; the name is passed at compile time, never stamped.
- **Module shape**: the engine (fetch, contract parsing, exclusion
  policy, merge policy, update lifecycle), a firewall seam package
  holding the shared vocabulary and the driver interface, adapters for
  nftables and a recording stub, and a thin command that wires a driver
  registry to flags. The engine and the adapters both depend on the
  seam; the engine never imports an adapter; a dependency rule test
  enforces it.
- **Ban rule across the seam**: Target prefixes plus the Penalty as
  stated (all five actions, rate exactly for the limits). Nothing else.
  Exclusions are subtracted engine-side before the seam (they override
  every report); enforcement scope and targeting are deliberately not
  part of the ban rule — they are driver configuration, because they
  are precisely what differs between enforcement surfaces (a web-server
  driver needs neither nsfs paths nor destination-port prefiltering).
- **Merge policy**: unchanged as policy, now expressed over the closed
  five-value Penalty vocabulary, with `limit-req-rate` a third limit
  dimension that combines at ties like the others and never loses to an
  invented ordering. Compilation remains canonical: permuted report
  order yields an identical ruleset.
- **Firewall-driver interface** (the seam): one method to plan — pure,
  no I/O, no privileges — returning the effective rules the driver
  would install (with an opaque placement label for logs), the ruleset
  hash, and the features it declines with reasons; one method to apply
  — replacing the wholly-owned ruleset in a single atomic rebuild,
  skipping the install when the plan's hash matches the last hash it
  applied and the owned ruleset still exists (a cheap probe), otherwise
  installing and returning the nonzero counters of the rules it
  replaced; and a tolerant reset. Plus a generic "enforcement point
  unreachable" error that drives the engine's warn-and-skip and
  reset-tolerance behaviour. Counter readings and declines reference
  the input rules by index so the engine can correlate logs.
- **Faithfulness**: a driver applies a Penalty exactly as stated or
  declines it. It never substitutes, weakens or tunes (no
  reject-to-drop fallback, no rate clamping); a decline is a first-class
  outcome, reported per rule and feature.
- **Driver factories**: each driver registers a factory exposing its
  name, flag binding (its own prefixed group), startup validation, and
  opening of its enforcement points. One driver per run; the factory
  expands its targets (e.g. nftables: one instance per nsfs path, or
  the current namespace when none is given) into driver instances the
  engine iterates. One fetch-compile serves all instances; skip state
  is per instance; each apply re-opens its target so a recreated
  container is picked up through a stable handle.
- **Identity lives in the driver**: the rolling-hash construction
  (bandaid's: seed 114514, per-item fresh FNV-1a 32-bit, previous hash
  big-endian, fields 0x00-delimited) ships as shared helpers on the
  seam; each driver folds its own **effective** rules — after declines,
  after whatever it drops. Skip-if-unchanged, the existence probe and
  the counter read-back are driver-internal. Changing driver
  configuration therefore re-enforces (the effective rules changed).
  The known limit stands: the probe is existence, not rule bodies.
- **nftables driver**: unchanged enforcement — wholly-owned inet table,
  ingress chain at `--nft-hook input|prerouting`, egress chain for
  bandwidth limits matched on destination, reject as inet-neutral
  admin-prohibited, packet/byte meters with the derived one-second
  burst, single atomic batch with the pre-delete existence probe
  (never a delete-then-rebuild window), interval encoding including the
  top-of-space null-end, counters placed after the match expressions so
  hits mean the ban fired, and `limit-req-rate` declined with reason
  (ADR 0012 narrows ADR 0011: non-application is this driver's
  decision, not a blanket policy).
- **Command surface**: `--firewall` (default nftables) selecting from
  the registry, unknown values listing the known drivers; the nftables
  group carries hook, nsfs paths (repeatable) and the service
  prefilter's destination ports and destination addresses; engine flags
  unchanged (report URL, certificate surface, fetch timeout, update
  interval, exclusion prefixes, private-space opt-out, dry run, log
  level, version). A flag set explicitly that belongs to another driver
  is a usage error. The usage output groups flags by owner.
- **Dry run**: prints the engine's compiled ban rules and the selected
  driver's plan — effective rules with placement and rate lines,
  declines, and `hash=<hex>` — from the pure planning step only.
- **Compatibility**: nftables enforcement is bit-for-bit preserved by
  this refactor; hash values may differ from older builds (the state is
  in-memory only). The known first-match nuance (a meter stance
  exceptioning a broader ban does not exempt in-rate traffic) stays a
  documented limitation — fixing it is a driver-policy question, not
  part of this work.
- **Consumer doc**: restructured around drivers — a general section
  (engine flags, merge policy, lifecycle, dry-run recipe) and one
  section per driver carrying its flags, targeting and scope recipes,
  its Penalty mapping table including its declines, and its caveats
  (for nftables: the reject-at-prerouting kernel floor, the
  namespace stable-handle recipes, one instance per namespace).

## Testing Decisions

- **What makes a good test here**: only external behavior — which ban
  rules reach a driver, what a driver reports installing or declining,
  and what the operator sees in logs and dry-run output. No assertions
  on compiler internals, hash internals, or netlink encoding outside
  the root-gated test.
- **Seam 1 — the update cycle at the firewall-driver seam** (existing,
  preferred): fake report endpoint plus the recording stub driver;
  observe the ban rules delivered and the outcomes the engine logs.
  Covers parse tolerances, exclusion subtraction, the merge matrix over
  five penalty values (exceptions both directions, tie-breaks,
  combined limits, order-independence), lifecycle (startup test
  install, keep-last on failed fetch, reset on exit, per-point fan-out,
  unreachable-point warn-and-skip), and dry-run text. The report
  document's canonical example remains the base fixture; the suite's
  failing-and-passing-case-per-validation convention holds.
- **Seam 2 — the nftables driver against a fake kernel** (new; the
  highest point at which driver-owned identity is observable without
  privileges): the driver's planning and apply logic — effective-rule
  derivation, hash folding, the skip matrix (identical twice, changed,
  missing ruleset, probe every cycle), decline reporting, counter
  parsing into hits, and batch construction including the pre-delete
  probe — driven through a private in-memory kernel stand-in that
  records what would be flushed. This replaces, not layers over, the
  real netlink path.
- **The command run seam is deliberately untested**: command behaviour
  is not frozen by tests. What would be asserted through the command is
  verified at the module that owns it — fetcher options, policy parsing,
  driver factories and the registry — and the existing run-seam tests
  are removed, not migrated, when the command is rebuilt; each
  validation that deserves one keeps a failing-and-passing pair at its
  owning module's seam.
- **Root-gated verification (not a seam)**: the existing kernel test
  install → read back → reset stays, extended with
  declines-install-nothing; it verifies the driver's encoding only and
  skips where privileges are absent.
- **Prior art**: the daemon's end-to-end tests against fakes, bandaid's
  fetch-and-generate loop test, and the current update-cycle suite's
  conventions.

## Out of Scope

- Any firewall driver beyond nftables — the seam exists so the next one
  is a new module, but nothing but the nftables driver ships here.
- Per-run mixing of drivers or per-enforcement-point driver selection.
- Any driver substituting, weakening or tuning a stated Penalty.
- Fixing the first-match meter exception nuance.
- In-kernel self-expiry of bans, rule-body tampering detection,
  machine-readable metrics, burst configurability, per-reason
  enforcement policy — unchanged from the original splint spec's
  exclusions.
- Any change to the bandage daemon or the published report document:
  the contract is untouched and stays the integration surface.
- Compatibility shims for the `splint-nft` name or the old flag
  spellings.

## Further Notes

- The domain docs already record this decision set: ADR 0012
  (enforcement through pluggable firewall drivers) and its
  superseded-in-part note on ADR 0011 landed during the design
  session, as did the GLOSSARY's Enforcement cluster (Ban rule,
  Firewall driver). Implementation must keep them true rather than
  re-litigate them; if the code wants to contradict them, that is a
  design conversation first.
- The design session's decision log lives beside this spec (the
  pre-grilling plan is superseded by this document).
- Reference DNA: fluxc's driver shape and bandaid's rolling hash and
  mTLS surface remain the construction DNA, in the repo's reference
  checkouts.
- Ban staleness remains bounded by the update interval; the
  enforcement-surface breadth of a driver (e.g. a web server seeing
  only its own traffic) is exactly why scope and targeting are its own
  configuration.
