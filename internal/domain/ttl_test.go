package bandage

import (
	"math"
	"testing"
	"time"
)

func TestTTL(t *testing.T) {
	tests := []struct {
		name   string
		leak   float64
		volume float64
		want   time.Duration
	}{
		{name: "volume over leak truncated toward zero", leak: 30, volume: 100, want: 3 * time.Second},
		{name: "exact division", leak: 10, volume: 100, want: 10 * time.Second},
		{name: "fractional leak", leak: 0.1, volume: 5, want: 50 * time.Second},
		{name: "sub-second quotient clamps to one second", leak: 10, volume: 1, want: time.Second},
		{name: "tiny quotient clamps to one second", leak: 1e9, volume: 1, want: time.Second},
		{name: "zero volume with positive leak clamps to one second", leak: 2, volume: 0, want: time.Second},
		{name: "zero leak defaults to one hour", leak: 0, volume: 100, want: time.Hour},
		{name: "negative leak defaults to one hour", leak: -1, volume: 100, want: time.Hour},
		{name: "overflow guarded", leak: 1e-300, volume: 1e300, want: time.Duration(math.MaxInt64)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TTL(tt.leak, tt.volume); got != tt.want {
				t.Errorf("TTL(%v, %v) = %v, want %v", tt.leak, tt.volume, got, tt.want)
			}
		})
	}
}
