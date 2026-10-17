package track

import (
	"context"
	"time"
)

// TrackerCache stores records keyed by (ns, key); ns is the rule ID.
//
// Update atomically applies fn to the record for (ns, key) (a zero-valued
// record if none exists, or one whose TTL has passed) and returns it
// afterwards. fn runs under the store's per-key lock, so it must not
// perform I/O or use ctx. ttl is the sliding expiry for the entry; zero
// means no expiry.
type TrackerCache interface {
	Update(ctx context.Context, ns, key string, ttl time.Duration, fn func(*Record)) (Record, error)
}

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
