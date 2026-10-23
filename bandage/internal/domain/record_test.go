package domain

import (
	"testing"
)

// Scenario values come from flux's bucket.yaml test vectors.

func TestRecordAccumulate(t *testing.T) {
	type step struct {
		eventTime    int64
		increment    float64
		wantValue    float64
		wantLast     int64
		wantOverflow bool
	}
	tests := []struct {
		name   string
		leak   float64
		volume float64
		steps  []step
	}{
		{
			// bucket.yaml: FREQ-BUCKET leak=0, volume=2 -> third request triggers.
			name:   "rate burst overflows on third event",
			leak:   0,
			volume: 2,
			steps: []step{
				{eventTime: 100, increment: 1, wantValue: 1, wantLast: 100},
				{eventTime: 100, increment: 1, wantValue: 2, wantLast: 100},
				{eventTime: 100, increment: 1, wantValue: 3, wantLast: 100, wantOverflow: true},
			},
		},
		{
			// bucket.yaml: BYTE-BUCKET leak=0, volume=1024, small volume.
			name:   "bandwidth overflow strictly above volume",
			leak:   0,
			volume: 1024,
			steps: []step{
				{eventTime: 100, increment: 600, wantValue: 600, wantLast: 100},
				{eventTime: 100, increment: 424, wantValue: 1024, wantLast: 100}, // == volume, no overflow
				{eventTime: 100, increment: 1, wantValue: 1025, wantLast: 100, wantOverflow: true},
			},
		},
		{
			// bucket.yaml: BYTE-BUCKET leak=512, volume=2048.
			name:   "decay between events",
			leak:   512,
			volume: 2048,
			steps: []step{
				{eventTime: 100, increment: 1000, wantValue: 1000, wantLast: 100},
				{eventTime: 102, increment: 1000, wantValue: 976, wantLast: 102},  // 2000 - 512*2
				{eventTime: 110, increment: 1000, wantValue: 0, wantLast: 110},    // floored at zero
				{eventTime: 111, increment: 2500, wantValue: 1988, wantLast: 111}, // 2500 - 512
				{eventTime: 111, increment: 100, wantValue: 2088, wantLast: 111, wantOverflow: true},
			},
		},
		{
			// bucket.yaml: FREQ-BUCKET leak=1, volume=4.
			name:   "steady single events drain",
			leak:   1,
			volume: 4,
			steps: []step{
				{eventTime: 100, increment: 1, wantValue: 1, wantLast: 100},
				{eventTime: 101, increment: 1, wantValue: 1, wantLast: 101}, // 2 - 1
				{eventTime: 102, increment: 1, wantValue: 1, wantLast: 102},
			},
		},
		{
			name:   "out-of-order events increment without decay",
			leak:   1,
			volume: 100,
			steps: []step{
				{eventTime: 100, increment: 5, wantValue: 5, wantLast: 100},
				{eventTime: 90, increment: 5, wantValue: 10, wantLast: 100}, // dt <= 0: no decay
				{eventTime: 100, increment: 5, wantValue: 15, wantLast: 100},
				{eventTime: 105, increment: 5, wantValue: 15, wantLast: 105}, // 20 - 1*5
			},
		},
		{
			name:   "first event sets last update",
			leak:   2,
			volume: 100,
			steps: []step{
				{eventTime: 500, increment: 3, wantValue: 3, wantLast: 500},
				{eventTime: 503, increment: 3, wantValue: 0, wantLast: 503}, // 6 - 2*3
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r Record
			for i, s := range tt.steps {
				r.Accumulate(s.increment, tt.leak, s.eventTime)
				if got := r.Value; got != s.wantValue {
					t.Errorf("step %d: value = %v, want %v", i, got, s.wantValue)
				}
				if got := r.LastUpdate; got != s.wantLast {
					t.Errorf("step %d: last update = %v, want %v", i, got, s.wantLast)
				}
				if got := r.Overflow(tt.volume); got != s.wantOverflow {
					t.Errorf("step %d: overflow = %v, want %v", i, got, s.wantOverflow)
				}
			}
		})
	}
}
