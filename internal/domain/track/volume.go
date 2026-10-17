package track

import (
	"math"
	"strconv"
)

// Replay volume methods (DECISIONS §8): volume is "tolerated download
// equivalents" as a function of the estimated file size in bytes —
// overflow when the accumulated fractions exceed it. The formulas follow
// flux FILE-RATIO-BUCKET (.reference/flux/pkg/engine/bucket.go) with
// bandage's units: unlike flux, the method output IS the volume (it is
// not multiplied by the file size), clamped-linear's slope is per
// decimal GB, and inverse-square's pivot and step's threshold are byte
// sizes. Only the replay tracker configures one; rate and bandwidth use
// a constant volume. The types satisfy the domain core's VolumeMethod
// interface structurally.

// ConstantVolume tolerates value download equivalents regardless of
// file size (a plain scalar `volume:`).
type ConstantVolume float64

func (m ConstantVolume) Volume(sizeBytes float64) float64 { return float64(m) }

func (m ConstantVolume) String() string {
	return "constant(value=" + fmtNum(float64(m)) + ")"
}

// ClampedLinearVolume tolerates intercept + slope × sizeGB equivalents,
// clamped to [Min, Max]. Slope is per decimal GB (sizeGB = size/1e9).
type ClampedLinearVolume struct {
	Intercept float64
	Slope     float64 // per decimal GB
	Min       float64
	Max       float64
}

func (m ClampedLinearVolume) Volume(sizeBytes float64) float64 {
	v := m.Intercept + m.Slope*(sizeBytes/1e9)
	return math.Max(m.Min, math.Min(m.Max, v))
}

func (m ClampedLinearVolume) String() string {
	return "clamped-linear(intercept=" + fmtNum(m.Intercept) +
		" slope=" + fmtNum(m.Slope) +
		" min=" + fmtNum(m.Min) +
		" max=" + fmtNum(m.Max) + ")"
}

// InverseSquareVolume tolerates base + pivot²/size² equivalents: small
// objects get a large tolerance, huge objects approach base (flux's
// formula). Pivot is a byte size; Volume is only called with a known
// (positive) size — the replay tracker skips unknown sizes.
type InverseSquareVolume struct {
	Base  float64
	Pivot float64 // bytes
}

func (m InverseSquareVolume) Volume(sizeBytes float64) float64 {
	return m.Base + m.Pivot*m.Pivot/(sizeBytes*sizeBytes)
}

func (m InverseSquareVolume) String() string {
	return "inverse-square(base=" + fmtNum(m.Base) + " pivot=" + fmtNum(m.Pivot) + ")"
}

// StepVolume tolerates VolumeLow equivalents for files smaller than
// Threshold (a byte size) and VolumeHigh at or above it.
type StepVolume struct {
	Threshold  float64 // bytes
	VolumeLow  float64
	VolumeHigh float64
}

func (m StepVolume) Volume(sizeBytes float64) float64 {
	if sizeBytes >= m.Threshold {
		return m.VolumeHigh
	}
	return m.VolumeLow
}

func (m StepVolume) String() string {
	return "step(threshold=" + fmtNum(m.Threshold) +
		" volume_low=" + fmtNum(m.VolumeLow) +
		" volume_high=" + fmtNum(m.VolumeHigh) + ")"
}

// fmtNum renders a method parameter as a plain decimal number.
func fmtNum(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}
