package track

import (
	"math"
	"time"
)

// DefaultTTL is used for cache entries when leak is zero or negative.
const DefaultTTL = time.Hour

// maxDurationSecs is the maximum number of seconds representable as a
// time.Duration (flux's ttlFloat overflow guard).
const maxDurationSecs = int64(math.MaxInt64 / int64(time.Second))

// TTL derives a tracker cache entry's TTL from its leak and volume:
// volume/leak seconds truncated toward zero, or DefaultTTL when leak is
// zero or negative. Every cache update carries it (sliding expiry).
func TTL(leak, volume float64) time.Duration {
	if leak <= 0 {
		return DefaultTTL
	}
	secs := volume / leak
	if secs > float64(maxDurationSecs) {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(secs) * time.Second
}
