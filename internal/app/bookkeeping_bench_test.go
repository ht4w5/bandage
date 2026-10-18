package app

import (
	"sync/atomic"
	"testing"

	"github.com/HT4w5/bandage/internal/bench"
)

// BenchmarkProgressBump measures the per-line bookkeeping alone (H2):
// progress.bump is one global mutex plus close(ch)/make(chan) per
// processed line — its serial cost, and its contention when every
// worker bumps concurrently. One op is one processed line.
func BenchmarkProgressBump(b *testing.B) {
	b.Run("serial", func(b *testing.B) {
		p := newProgress()
		var lines int
		for b.Loop() {
			p.bump()
			lines++
		}
		bench.ReportLinesPerSec(b, lines)
	})
	b.Run("parallel", func(b *testing.B) {
		p := newProgress()
		var lines atomic.Int64
		b.RunParallel(func(pb *testing.PB) {
			var n int
			for pb.Next() {
				p.bump()
				n++
			}
			lines.Add(int64(n))
		})
		bench.ReportLinesPerSec(b, int(lines.Load()))
	})
}
