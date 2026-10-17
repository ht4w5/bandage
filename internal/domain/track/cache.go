package track

// Statistics is the tracker cache's operational surface, logged
// periodically (flux's Statistics precedent; no debug endpoints).
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
	// lazily dropped or swept).
	Size int64
}
