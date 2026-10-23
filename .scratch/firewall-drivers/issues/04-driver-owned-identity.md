# 04: Driver-owned identity: plan, apply, reset

**What to build:** the firewall seam reaches its final shape and the
spec's core lands: the rolling hash, skip-if-unchanged and the counters
live **inside the firewall driver**, because only the driver knows which
Ban rules are actually effective and which it drops. A driver plans
(pure — no I/O, no privileges), applies (probe, then skip or atomically
rebuild, then read the counters of what it replaced) and resets. The
engine just logs what the driver reports: applied, or unchanged-skip
with the hash, the nonzero hits since the last change, and declines.
`--dry-run` prints the compiled Ban rules and the driver's plan —
effective rules, placement, declines, `hash=<hex>` — unprivileged. The
driver's logic is verified against a fake kernel without privileges.

**Blocked by:** 03

**Status:** resolved

- [x] The seam is plan/apply/reset plus a label and a generic "enforcement point unreachable" error: plan returns effective rules with placement labels, the ruleset hash and declines with reasons; apply returns applied-or-skipped, the hash, hits referencing input rules by index, and declines; reset tolerates an absent ruleset
- [x] The rolling hash (bandaid's construction as shared helpers on the seam) folds the driver's effective rules — after declines, after anything it drops; the install is skipped when the hash matches the last applied hash **and** the owned ruleset exists (probed every apply), otherwise it installs atomically
- [x] Counters are read at install and reported as nonzero hits covering the period since the last change; a skipped cycle logs the skip and no hits
- [x] The engine carries no hash, probe, skip or counter logic; skip state follows each driver instance
- [x] `--dry-run` prints the driver's plan from the pure planning step only, hash included
- [x] A driver suite runs against a fake kernel: effective-rule derivation, hash folding, the skip matrix (identical twice, changed, missing ruleset, probe every cycle), counter parsing, decline reporting, batch construction including the pre-delete existence probe
- [x] The root-gated kernel test keeps covering install → read back → reset and gains declines-install-nothing
- [x] The stub driver remains the update-cycle test surface; lifecycle behaviour (startup test install, keep-last on failed fetch, reset on exit) stays observable there

Implemented on integration branch `feat/firewall-drivers` (commit `0d6e95f`). "A label" landed as the opaque placement label on planned rules. The rolling hash folds each driver's effective rules (placement included, so changed driver configuration re-enforces); skip state follows each driver instance; the fake-kernel suite replaces the real netlink path in tests and the root-gated kernel test keeps install → read back → reset plus declines-install-nothing. Hash values may differ from older builds (in-memory state), as the spec allows. The hit-index correlation was clarified in the code-review fix pass: indices refer to the ruleset the driver replaced.

Context: spec `../spec.md` (Identity lives in the driver; Testing
Decisions seam 2); ADR 0012 records why identity sits in the driver.

