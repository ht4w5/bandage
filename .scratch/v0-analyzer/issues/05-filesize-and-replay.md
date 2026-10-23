# 05: Filesize enrichment and Replay tracker

**What to build:** an operator detects clients replaying large objects: bandage learns each path's file size from observed transfers and a `replay` Tracker accumulates transferred fractions of the file per (Target, path), overflowing when a client keeps re-downloading beyond tolerance — with tolerance that scales with object size.

**Blocked by:** 04: Target aggregation (`target_prefix`)

**Status:** resolved

- [x] File-size enrichment estimates each path's size as a smoothed average over observed transfers (EWMA), stays "unknown" until a minimum number of samples has been seen, and persists in the cache store without TTL.
- [x] The `replay` Tracker keys state by (Target, path), increments by the transferred fraction of the estimated size (capped at 1 per Event), decays and Overflows per the leaky-bucket math, and skips Events whose size is unknown — no Match can occur during warm-up.
- [x] Replay volume methods `constant`, `clamped-linear`, `inverse-square`, and `step` (in file size) are configurable on the `replay` Tracker only; a volume method on `rate`/`bandwidth` is rejected at load.
- [x] The replay Tracker reading appears in Report evidence (value, leak, volume at trigger), and the Sample carries the size estimate.
- [x] The prior-art enrichment tests (EWMA, warm-up gating) and replay bucket semantics (including volume methods) are ported and pass.

## Answer

Implemented on `feat/v0-analyzer` (merge commit `075aced`).
`internal/bandage/enrichment`: webjail's integer EWMA + warm-up gate
(app-wiring constants period=5, minSamples=5, DECISIONS §3), state in the
shared cache store under `filesize` without TTL. `replay` tracker keyed
(Target, path), fraction increments `min(sent/size, 1)`, full skip while
the size is unknown (no Match during warm-up), generic leaky-bucket
decay/overflow. Volume methods `constant`/`clamped-linear`/`inverse-square`/
`step` on replay only (formulas/units per DECISIONS §8 — clamped-linear
slope is per decimal GB); scalar volume on replay = constant; method
blocks on rate/bandwidth rejected at load. Report evidence carries the
computed volume and `sample.size`.

Context: `/home/user2/Devel/bandage-impl-notes/{webjail-map,porting-notes,DECISIONS}.md`.
Prior-art suites did not exist (DECISIONS §2) — tests authored fresh.
