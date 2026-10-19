package track

import "testing"

// Replay volume methods: volume is "tolerated download equivalents" as a
// function of the estimated file size.

func TestConstantVolume(t *testing.T) {
	m := ConstantVolume(5)
	for _, size := range []float64{1, 1e3, 1e9, 1e12} {
		if got := m.Volume(size); got != 5 {
			t.Errorf("Volume(%g) = %g, want 5", size, got)
		}
	}
}

func TestClampedLinearVolume(t *testing.T) {
	// intercept 5, slope -1 per decimal GB, clamp [2, 5].
	m := ClampedLinearVolume{Intercept: 5, Slope: -1, Min: 2, Max: 5}
	tests := []struct {
		size float64
		want float64
	}{
		{0, 5},       // intercept clamped to max
		{0.5e9, 4.5}, // 5 - 0.5
		{1e9, 4},     // 5 - 1
		{2.5e9, 2.5}, // linear region
		{3e9, 2},     // 5 - 3
		{10e9, 2},    // 5 - 10 = -5 clamped to min
		{123e12, 2},  // huge files clamp to min
	}
	for _, tt := range tests {
		if got := m.Volume(tt.size); got != tt.want {
			t.Errorf("Volume(%g) = %g, want %g", tt.size, got, tt.want)
		}
	}
}

func TestInverseSquareVolume(t *testing.T) {
	// base 1, pivot 1GB: base + pivot^2/size^2.
	m := InverseSquareVolume{Base: 1, Pivot: 1e9}
	tests := []struct {
		size float64
		want float64
	}{
		{1e9, 2},     // 1 + 1
		{2e9, 1.25},  // 1 + 1/4
		{0.5e9, 5},   // 1 + 4
		{10e9, 1.01}, // 1 + 1/100
	}
	for _, tt := range tests {
		if got := m.Volume(tt.size); got != tt.want {
			t.Errorf("Volume(%g) = %g, want %g", tt.size, got, tt.want)
		}
	}
}

func TestStepVolume(t *testing.T) {
	// threshold 1GB: volume_low below, volume_high at or above.
	m := StepVolume{Threshold: 1e9, VolumeLow: 2, VolumeHigh: 5}
	tests := []struct {
		size float64
		want float64
	}{
		{0, 2},
		{1, 2},
		{0.999e9, 2},
		{1e9, 5}, // size >= threshold
		{1e12, 5},
	}
	for _, tt := range tests {
		if got := m.Volume(tt.size); got != tt.want {
			t.Errorf("Volume(%g) = %g, want %g", tt.size, got, tt.want)
		}
	}
}

// String renders the method for the --test plan.
func TestVolumeMethodString(t *testing.T) {
	tests := []struct {
		m    interface{ String() string }
		want string
	}{
		{ConstantVolume(5), "constant(value=5)"},
		{ClampedLinearVolume{Intercept: 5, Slope: -1, Min: 2, Max: 5}, "clamped-linear(intercept=5 slope=-1 min=2 max=5)"},
		{InverseSquareVolume{Base: 1, Pivot: 1e9}, "inverse-square(base=1 pivot=1000000000)"},
		{StepVolume{Threshold: 1e9, VolumeLow: 2, VolumeHigh: 5}, "step(threshold=1000000000 volume_low=2 volume_high=5)"},
	}
	for _, tt := range tests {
		if got := tt.m.String(); got != tt.want {
			t.Errorf("String() = %q, want %q", got, tt.want)
		}
	}
}
