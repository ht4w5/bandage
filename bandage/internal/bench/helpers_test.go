package bench

import (
	"testing"
	"time"
)

// Helper contracts: the lines/s rate and the shape/distribution names.

func TestLinesPerSec(t *testing.T) {
	tests := []struct {
		name    string
		lines   int
		elapsed time.Duration
		want    float64
	}{
		{name: "100 lines over 2s is 50 lines/s", lines: 100, elapsed: 2 * time.Second, want: 50},
		{name: "500 lines over 250ms is 2000 lines/s", lines: 500, elapsed: 250 * time.Millisecond, want: 2000},
		{name: "no elapsed time reports zero, never +Inf", lines: 10, elapsed: 0, want: 0},
		{name: "no lines reports zero", lines: 0, elapsed: time.Second, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := linesPerSec(tt.lines, tt.elapsed); got != tt.want {
				t.Errorf("linesPerSec(%d, %v) = %v, want %v", tt.lines, tt.elapsed, got, tt.want)
			}
		})
	}
}

func TestShapeAndDistNames(t *testing.T) {
	// The names land in benchmark sub-names and committed baselines: keep them stable.
	tests := []struct{ got, want string }{
		{ShapeMinimal.String(), "minimal"},
		{ShapeFull.String(), "full"},
		{DistUniform.String(), "uniform"},
		{DistZipf.String(), "zipf"},
		{DistHot.String(), "hot"},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("name = %q, want %q", tt.got, tt.want)
		}
	}
}

func TestNewCorpusClampsSize(t *testing.T) {
	for _, n := range []int{0, -3} {
		if got := NewCorpus(Seed, ShapeMinimal, DistUniform, n).Len(); got != 1 {
			t.Errorf("NewCorpus(n=%d).Len() = %d, want 1", n, got)
		}
	}
}
