// Package track holds leaky-bucket tracker configuration math: quantity
// parsing (DECISIONS §5), replay volume methods (DECISIONS §8) and
// tracker cache statistics. Tracker state (Record and the leaky-bucket
// math) is a shared value type on the domain core (PLAN §5), aliased
// here so the store contract reads naturally beside it.
package track

import (
	bandage "github.com/HT4w5/bandage/internal/domain"
)

// Record is leaky-bucket state for one key: the domain core's value
// type (with its Accumulate/Overflow math), aliased here so the
// tracker-cache store contract reads naturally beside the cache
// statistics.
type Record = bandage.Record
