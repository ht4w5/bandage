# 06: Ruleset identity: rolling hash, skip-if-unchanged, counters

**What to build:** a quiet cycle costs nothing and the operator can see
whether bans are firing. The compiled ruleset carries bandaid-style rolling
hash; when the rules have not changed since the last install and the table
is still there, the install is skipped outright. Every ban rule carries a
counter, and nonzero hits are logged at installs so the operator sees what
the enforcement actually did.

**Blocked by:** 02 — Kernel install: the nftables driver; 05 — Merge policy

**Status:** ready-for-agent

- [ ] The compiled ruleset after exclusions and merge folds into an FNV-1a 32-bit rolling chain over canonical order with bandaid's seed construction
- [ ] Install is skipped when the hash matches the last installed hash for that namespace **and** the table exists (probed each cycle); otherwise it installs
- [ ] The skip holds for identical repeated documents; any change to the effective ruleset — a new Target, an expired Report's disappearance, a stance change — reinstalls
- [ ] A matching hash with a missing table reinstalls (recreated container namespace, external table reset); rule-body tampering under a surviving table is documented as undetected
- [ ] The hash is logged each cycle and printed by `--dry-run`
- [ ] Every ban rule carries a packet/byte counter; nonzero hits are logged at each install, covering the period since the last change; a skipped cycle logs the skip and no hits
- [ ] Seam tests assert skip/no-skip observably (install call counts) — identical twice, changed, and missing-table cases — never the hash's internals

Context: spec `../spec.md` (rolling hash, counters); bandaid's rolling
hash in the reference checkout is the construction DNA.
