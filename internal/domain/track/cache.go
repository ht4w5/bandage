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
