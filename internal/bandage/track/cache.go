package track

// Statistics is the tracker cache's operational counters (ADR 0006).
type Statistics struct {
	// Gets counts Update lookups; Sets counts Update writes.
	Gets int64
	Sets int64
	// Misses counts lookups that found no live entry (absent or expired).
	Misses int64
	// Evictions counts entries removed by the entry cap's LRU (GLOSSARY: Eviction).
	Evictions int64
	// Size is the current entry count (expired entries count until removed).
	Size int64
	// EntryCap is the configured entry cap the store is bounded to.
	EntryCap int64
}
