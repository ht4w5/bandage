// Package track holds leaky-bucket tracker configuration math: quantity
// parsing, replay volume methods and tracker cache statistics.
package track

import (
	"github.com/HT4w5/bandage/internal/bandage"
)

// Record is leaky-bucket state for one key: the domain core's value type
// (with its Accumulate/Overflow math), aliased here.
type Record = bandage.Record
