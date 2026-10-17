# 05: Filesize enrichment and Replay tracker

**What to build:** an operator detects clients replaying large objects: bandage learns each path's file size from observed transfers and a `replay` Tracker accumulates transferred fractions of the file per (Target, path), overflowing when a client keeps re-downloading beyond tolerance — with tolerance that scales with object size.

**Blocked by:** 04: Target aggregation (`target_prefix`)

**Status:** ready-for-agent

- [ ] File-size enrichment estimates each path's size as a smoothed average over observed transfers (EWMA), stays "unknown" until a minimum number of samples has been seen, and persists in the cache store without TTL.
- [ ] The `replay` Tracker keys state by (Target, path), increments by the transferred fraction of the estimated size (capped at 1 per Event), decays and Overflows per the leaky-bucket math, and skips Events whose size is unknown — no Match can occur during warm-up.
- [ ] Replay volume methods `constant`, `clamped-linear`, `inverse-square`, and `step` (in file size) are configurable on the `replay` Tracker only; a volume method on `rate`/`bandwidth` is rejected at load.
- [ ] The replay Tracker reading appears in Report evidence (value, leak, volume at trigger), and the Sample carries the size estimate.
- [ ] The prior-art enrichment tests (EWMA, warm-up gating) and replay bucket semantics (including volume methods) are ported and pass.
