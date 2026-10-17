package bandage

import (
	"math"
	"time"
)

// DefaultTTL is used for cache entries when leak is zero or negative.
const DefaultTTL = time.Hour

// MinTTL is the smallest cache-entry TTL. A positive volume/leak always
// yields a real expiry (a sub-second quotient truncates up to MinTTL):
// only leak <= 0 means DefaultTTL, and zero TTL is reserved for the
// filesize namespace (entries that never expire).
const MinTTL = time.Second

// maxDurationSecs is the maximum number of seconds representable as a
// time.Duration (flux's ttlFloat overflow guard).
const maxDurationSecs = int64(math.MaxInt64 / int64(time.Second))

// TTL derives a tracker cache entry's TTL from its leak and volume:
// volume/leak seconds truncated toward zero (never below MinTTL), or
// DefaultTTL when leak is zero or negative. Every cache update carries
// it (sliding expiry). Tracker entries always expire: ttl == 0 is
// reserved for the filesize namespace's no-expiry state.
func TTL(leak, volume float64) time.Duration {
	if leak <= 0 {
		return DefaultTTL
	}
	secs := volume / leak
	if secs > float64(maxDurationSecs) {
		return time.Duration(math.MaxInt64)
	}
	if d := time.Duration(secs) * time.Second; d >= MinTTL {
		return d
	}
	return MinTTL
}
