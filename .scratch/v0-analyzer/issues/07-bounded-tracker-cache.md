# 07: Bounded tracker cache with capped-drop logging

**What to build:** an operator runs bandage under a fixed memory budget: tracker state is capped and evicts least-recently-used entries, and nothing resets silently — every capped drop is logged so an emptied bucket is always explainable.

**Blocked by:** 01: Walking skeleton — Event to Report list

**Status:** resolved

- [x] The cache entry cap is configurable with a default of 65536 and must be positive; invalid values are rejected at startup.
- [x] Under the cap, least-recently-used entries are evicted; every capped drop is logged with its tracker namespace and Target and counted in statistics.
- [x] TTL expiry is enforced lazily on access and by a periodic sweep (internal cadence); enrichment state shares the store without TTL.
- [x] Statistics (gets/sets/misses/evictions/size) are logged periodically; there is no debug endpoint.
- [x] Report behavior under eviction stays correct: an evicted bucket simply accumulates fresh state from zero — never a crash, never a stale Match.

## Answer

Implemented on `feat/v0-analyzer` (merge commit `28f9a97`). Per-shard LRU
under the global `cache.max_entries` cap (default 65536, positive at
load); every capped drop logged with its namespace and Target (post
code-review: true `target` + `path` attributes decoded from the shared
key convention, `filesize` namespace logs `path`) and counted; TTL
expiry lazy + periodic sweep (sub-second `volume/leak` clamps to a 1s
expiry — code-review fix); `filesize` namespace shares the store without
TTL; statistics (gets/sets/misses/evictions/size) in the periodic slog
line, no debug endpoint; evicted buckets re-accumulate fresh — e2e-proven.

Note: with enrichment sharing the store, the practical minimum cap is 2
entries (at 1, tracker and filesize records evict each other forever);
config still accepts 1 as the ticket specifies positivity only.
