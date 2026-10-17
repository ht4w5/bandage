package track

import (
	"errors"
	"math"
	"testing"
	"time"
)

// Tracker math scenarios follow the numeric contract verified against
// .reference/flux/pkg/engine/bucket.go and its testdata/bucket.yaml
// parameter sets (freq/byte buckets), authored fresh per DECISIONS §2.

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
			// bucket.yaml: FREQ-BUCKET leak=0, volume=2 → third request triggers.
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
				{eventTime: 102, increment: 1000, wantValue: 976, wantLast: 102},  // 2000 − 512·2
				{eventTime: 110, increment: 1000, wantValue: 0, wantLast: 110},    // floored at zero
				{eventTime: 111, increment: 2500, wantValue: 1988, wantLast: 111}, // 2500 − 512
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
				{eventTime: 101, increment: 1, wantValue: 1, wantLast: 101}, // 2 − 1
				{eventTime: 102, increment: 1, wantValue: 1, wantLast: 102},
			},
		},
		{
			name:   "out-of-order events increment without decay",
			leak:   1,
			volume: 100,
			steps: []step{
				{eventTime: 100, increment: 5, wantValue: 5, wantLast: 100},
				{eventTime: 90, increment: 5, wantValue: 10, wantLast: 100}, // Δt ≤ 0: no decay
				{eventTime: 100, increment: 5, wantValue: 15, wantLast: 100},
				{eventTime: 105, increment: 5, wantValue: 15, wantLast: 105}, // 20 − 1·5
			},
		},
		{
			name:   "first event sets last update",
			leak:   2,
			volume: 100,
			steps: []step{
				{eventTime: 500, increment: 3, wantValue: 3, wantLast: 500},
				{eventTime: 503, increment: 3, wantValue: 0, wantLast: 503}, // 6 − 2·3
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

func TestParseNumber(t *testing.T) {
	tests := []struct {
		in      string
		want    float64
		wantErr bool
	}{
		{in: "10", want: 10},
		{in: "0", want: 0},
		{in: "0.1", want: 0.1},
		{in: "10/s", want: 10},
		{in: "0.1/s", want: 0.1},
		{in: "", wantErr: true},
		{in: "1MB", wantErr: true},
		{in: "-1", wantErr: true},
		{in: "10/x", wantErr: true},
		{in: "abc", wantErr: true},
		{in: "1e3", wantErr: true},
		{in: "inf", wantErr: true},
		{in: "NaN", wantErr: true},
		{in: ".5", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseNumber(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseNumber(%q) = %v, want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseNumber(%q) error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ParseNumber(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseBytes(t *testing.T) {
	tests := []struct {
		in      string
		want    float64
		wantErr bool
	}{
		{in: "10", want: 10},
		{in: "512", want: 512},
		{in: "0", want: 0},
		{in: "1kB", want: 1e3},
		{in: "1MB", want: 1e6},
		{in: "100GB", want: 1e11},
		{in: "1.5MB", want: 1.5e6},
		{in: "2m", want: 2e6},
		{in: "1MiB", want: 1e6},
		{in: "1TB", want: 1e12},
		{in: "1PB", want: 1e15},
		{in: "1MB/s", want: 1e6},
		{in: "0/s", want: 0},
		{in: "512/s", want: 512},
		{in: "", wantErr: true},
		{in: "-1MB", wantErr: true},
		{in: "1q", wantErr: true},
		{in: "1MB/x", wantErr: true},
		{in: "abc", wantErr: true},
		{in: "1.2.3", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseBytes(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseBytes(%q) = %v, want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseBytes(%q) error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ParseBytes(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseQuantityErrorsWrapValue(t *testing.T) {
	_, err := ParseBytes("1q")
	if err == nil {
		t.Fatal("want error")
	}
	var pe *QuantityError
	if !errors.As(err, &pe) {
		t.Fatalf("error %v is not a *QuantityError", err)
	}
	if pe.Value != "1q" {
		t.Errorf("QuantityError.Value = %q, want %q", pe.Value, "1q")
	}
}
