package bandage

import (
	"math"
	"time"
)

// DefaultTTL is used for cache entries when leak is zero or negative.
const DefaultTTL = time.Hour

// MinTTL is the smallest cache-entry TTL: sub-second volume/leak
// truncates up to it; zero TTL is reserved for the filesize namespace.
const MinTTL = time.Second

// maxDurationSecs is the max seconds representable as a time.Duration.
const maxDurationSecs = int64(math.MaxInt64 / int64(time.Second))

// TTL derives a cache entry's TTL as volume/leak seconds truncated
// toward zero (never below MinTTL), or DefaultTTL when leak <= 0.
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
