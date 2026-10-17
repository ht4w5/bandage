package track

// Statistics is the tracker cache's operational surface: the counters
// logged periodically and served in GET /stats' tracker cache block
// (flux's Statistics precedent; ADR 0006).
type Statistics struct {
	// Gets counts Update lookups; Sets counts Update writes.
	Gets int64
	Sets int64
	// Misses counts lookups that found no live entry (absent or
	// TTL-expired).
	Misses int64
	// Evictions counts entries removed by the entry cap's LRU (GLOSSARY:
	// Eviction), each logged with its tracker namespace and Target.
	Evictions int64
	// Size is the current entry count (expired entries count until
	// lazily removed or swept).
	Size int64
	// EntryCap is the configured entry cap the store is bounded to.
	EntryCap int64
}
