# 03: Ban rules carry the Penalty as stated

**What to build:** the firewall vocabulary exists and the compiler stops
translating penalties away. A Ban rule carries the Penalty as stated —
all five values of the closed vocabulary, rate exactly for the limits —
and each firewall driver decides what it can honour. `limit-req-rate`
now survives compilation and reaches the nftables driver, which
**declines** it loudly (logged and counted, per rule and feature)
instead of the compiler silently losing it. The merge policy resolves
over the five values: most specific Target wins both ways, ties go
strictest-first (`drop` > `reject` > limits, smaller rate stricter
within one action), and dimensionally incomparable limits combine —
request rates now a third limit dimension that never loses to an
invented ordering. Enforcement on nftables is unchanged for every other
Penalty.

**Blocked by:** None (can start immediately)

**Status:** resolved

- [x] The firewall vocabulary exists: Ban rule (Target prefixes, the prefilter still engine-configured at this stage, Penalty as stated with all five values), and the skip/hit shapes the engine logs
- [x] The compiler keeps `limit-req-rate` reports; no penalty is dropped before a driver sees it
- [x] The merge policy operates over the five-value vocabulary (exceptions both directions, tie-breaks, combined limits including request rates) and stays canonical: permuted report order compiles to an identical ruleset
- [x] The nftables driver declines `limit-req-rate` with a reason; declines are reported per rule and feature and logged and counted by the engine — never faked at the packet layer, never silently lost
- [x] nftables enforcement for drop, reject, packet-rate and bandwidth Penalties is unchanged; exclusions still subtract engine-side before the seam
- [x] Seam tests cover the merge matrix over five values and the decline reporting, with a failing and a passing case per validation

Implemented on integration branch `feat/firewall-drivers` (commits `8614d78`, `ad7295b`; merge `8722793`). The firewall seam package (`splint/internal/firewall`) holds the vocabulary and a dependency-rule test; `limit-req-rate` survives compilation and is declined with a reason by the nftables driver, reported per rule and feature and logged and counted by the engine. The prefilter rode along as transitional engine-configured input and left the ban rule entirely in 05, as this ticket planned.

Context: spec `../spec.md` (merge policy, faithfulness); ADR 0012
narrows ADR 0011: `limit-req-rate` non-application is the nftables
driver's decline, not a blanket policy.

