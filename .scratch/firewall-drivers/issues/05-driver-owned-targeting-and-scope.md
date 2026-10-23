# 05: Driver-owned targeting and enforcement scope

**What to build:** everything that differs between enforcement surfaces
becomes driver configuration. A driver factory binds its own flags and
opens its enforcement points: the nftables driver takes repeatable
namespace paths and enforces in one point per path (the current
namespace by default), re-opening each point every apply so a recreated
container is picked up through a stable handle. One fetch-compile
serves all points; an unreachable point is warned and skipped while the
others enforce; a clean exit tolerates vanished points. The service
prefilter leaves the engine and becomes nftables configuration — bans
never reach traffic the operator never intended to touch stays true,
but the engine no longer knows what a prefilter is. The Ban rule slims
to Target prefixes plus the Penalty as stated.

**Blocked by:** 04

**Status:** resolved

- [x] Each driver factory binds its own flags and opens its enforcement points; the nftables factory expands its repeatable namespace-path flag into one driver instance per point, defaulting to the current namespace
- [x] One fetch-compile serves every enforcement point; per-point identity (skip-if-unchanged) follows each instance
- [x] An unreachable enforcement point is warned and skipped for the cycle while the others still enforce; reset on exit tolerates vanished points
- [x] The service prefilter (destination ports and destination addresses) is nftables configuration in the nftables flag group, folded into the driver's effective rules and therefore its hash — changing it re-enforces
- [x] The Ban rule is Target prefixes plus the Penalty as stated; the engine knows no targeting and no enforcement scope
- [x] Operator exclusions are still subtracted engine-side, overriding every report
- [x] Namespace-path and service port/address validations carry a failing and a passing pair at the factory's seam (re-homed here from the dropped run seam)
- [x] Fan-out, skip-and-warn and per-point skip-if-unchanged are covered at the update-cycle seam and the fake-kernel suite; nftables enforcement is unchanged

Implemented on integration branch `feat/firewall-drivers` (commits `ddcccba`, `238f625`, `33ec595`, `de99f78`, `a79f1ae`). The nftables factory expands its repeatable nsfs flag into one driver instance per enforcement point ("current" when none is given), the prefilter became driver configuration folded into the effective rules and their hash, and the ban rule slimmed to Target prefixes plus the Penalty as stated. The engine's log vocabulary went generic (`point=`) with factory-set labels carrying the nsfs paths; namespace-path and service port/address validation pairs live at the factory seam, re-homed here from the dropped run seam as planned.

Context: spec `../spec.md` (Driver factories; Enforcement scope
decisions); ADR 0012: targeting and scoping are driver-owned because
they are what differs between enforcement surfaces.

