package bench

import (
	"testing"
	"time"
)

// ReportLinesPerSec reports the benchmark's throughput as lines/s.
// Call it after the b.Loop() loop with the number of raw log lines the
// benchmark processed:
//
//	var lines int
//	for b.Loop() {
//		process(corpus.Line(lines))
//		lines++
//	}
//	bench.ReportLinesPerSec(b, lines)
//
// It is meaningful where one op is one raw log line (parse, whole
// pipeline); per-key microbenchmarks report ns/op instead.
func ReportLinesPerSec(b *testing.B, lines int) {
	b.Helper()
	b.ReportMetric(linesPerSec(lines, b.Elapsed()), "lines/s")
}

// linesPerSec is the rate ReportLinesPerSec reports: lines divided by
// elapsed benchmark time, zero when no time elapsed (never +Inf).
func linesPerSec(lines int, elapsed time.Duration) float64 {
	if elapsed <= 0 {
		return 0
	}
	return float64(lines) / elapsed.Seconds()
}
