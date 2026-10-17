package track

// Statistics is the tracker cache's operational surface, logged
// periodically via slog (flux's Statistics precedent; no debug
// endpoints).
type Statistics struct {
	// Gets counts Update lookups; Sets counts Update writes.
	Gets int64
	Sets int64
	// Misses counts lookups that found no live entry (absent or
	// TTL-expired).
	Misses int64
	// Evictions counts capped drops: entries removed by the entry cap's
	// LRU and logged with their tracker namespace and Target.
	Evictions int64
	// Size is the current entry count (expired entries count until
	// lazily dropped or swept).
	Size int64
}
