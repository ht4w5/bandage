# 06: Ruleset identity: rolling hash, skip-if-unchanged, counters

**What to build:** a quiet cycle costs nothing and the operator can see
whether bans are firing. The compiled ruleset carries bandaid-style rolling
hash; when the rules have not changed since the last install and the table
is still there, the install is skipped outright. Every ban rule carries a
counter, and nonzero hits are logged at installs so the operator sees what
the enforcement actually did.

**Blocked by:** 02 — Kernel install: the nftables driver; 05 — Merge policy

**Status:** resolved

- [x] The compiled ruleset after exclusions and merge folds into an FNV-1a 32-bit rolling chain over canonical order with bandaid's seed construction
- [x] Install is skipped when the hash matches the last installed hash for that namespace **and** the table exists (probed each cycle); otherwise it installs
- [x] The skip holds for identical repeated documents; any change to the effective ruleset — a new Target, an expired Report's disappearance, a stance change — reinstalls
- [x] A matching hash with a missing table reinstalls (recreated container namespace, external table reset); rule-body tampering under a surviving table is documented as undetected
- [x] The hash is logged each cycle and printed by `--dry-run`
- [x] Every ban rule carries a packet/byte counter; nonzero hits are logged at each install, covering the period since the last change; a skipped cycle logs the skip and no hits
- [x] Seam tests assert skip/no-skip observably (install call counts) — identical twice, changed, and missing-table cases — never the hash's internals

Implemented on integration branch `feat/splint-nft` (merge commit `d483a93`; cross-ticket code-review fixes through `1879da4`). The review pass moved each rule's counter behind its match expressions, so a `ban rule hit` means the ban actually fired; the existence-only-probe limit is documented in `docs/splint-nft.md`.

Context: spec `../spec.md` (rolling hash, counters); bandaid's rolling
hash in the reference checkout is the construction DNA.
