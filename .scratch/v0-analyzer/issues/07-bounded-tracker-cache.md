# 07: Bounded tracker cache with capped-drop logging

**What to build:** an operator runs bandage under a fixed memory budget: tracker state is capped and evicts least-recently-used entries, and nothing resets silently — every capped drop is logged so an emptied bucket is always explainable.

**Blocked by:** 01: Walking skeleton — Event to Report list

**Status:** ready-for-agent

- [ ] The cache entry cap is configurable with a default of 65536 and must be positive; invalid values are rejected at startup.
- [ ] Under the cap, least-recently-used entries are evicted; every capped drop is logged with its tracker namespace and Target and counted in statistics.
- [ ] TTL expiry is enforced lazily on access and by a periodic sweep (internal cadence); enrichment state shares the store without TTL.
- [ ] Statistics (gets/sets/misses/evictions/size) are logged periodically; there is no debug endpoint.
- [ ] Report behavior under eviction stays correct: an evicted bucket simply accumulates fresh state from zero — never a crash, never a stale Match.
