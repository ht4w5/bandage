package memory

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/HT4w5/bandage/internal/bench"
	bandage "github.com/HT4w5/bandage/internal/domain"
	"github.com/HT4w5/bandage/internal/domain/track"
)

// BenchmarkStoreUpdate and BenchmarkStoreUpdateParallel measure
// Store.Update per call (H3): full-key concat and FNV hashing, shard
// lock and LRU bookkeeping, over the corpus's uniform, Zipfian and hot
// key distributions — sequential and contended. The cap (65536) is
// sized so the 256-key pools never evict (steady state without
// eviction skew); the deliberately evicting variant runs the uniform
// pool over a cap of 16 so nearly every update evicts. The clock is
// fixed and the eviction logger is zerolog.Nop(), so eviction log
// rendering is excluded. fn is the production accumulate step; one op
// is one tracker update (a per-key microbenchmark, so ns/op rather
// than lines/s).

const (
	benchNS  = "bench-rule"
	benchTTL = time.Hour
)

var benchNow = time.Unix(1734345934, 0)

// benchUpdateFn is the accumulate step a tracker rule runs under the
// shard lock.
func benchUpdateFn(r *track.Record) { r.Accumulate(1, 0, benchNow.Unix()) }

// benchKeys derives one tracker-cache key per corpus line: the line's
// client aggregated to its target prefix, the domain's key convention.
// The pools hold 256 distinct keys (one, for the hot distribution).
func benchKeys(b *testing.B, dist bench.KeyDist) []string {
	b.Helper()
	corpus := bench.NewCorpus(bench.Seed, bench.ShapeFull, dist, 1024)
	keys := make([]string, corpus.Len())
	for i := range keys {
		ev := corpus.Event(i)
		keys[i] = bandage.DefaultTargetPrefix.Aggregate(ev.RemoteAddr).String()
	}
	return keys
}

// benchStoreCases names the key distributions and the store cap: the
// steady-state cap keeps every distribution eviction-free, the
// evicting case deliberately thrashes the cap.
var benchStoreCases = []struct {
	name string
	dist bench.KeyDist
	cap  int
}{
	{"uniform", bench.DistUniform, 65536},
	{"zipf", bench.DistZipf, 65536},
	{"hot", bench.DistHot, 65536},
	{"evicting", bench.DistUniform, 16},
}

func BenchmarkStoreUpdate(b *testing.B) {
	for _, tc := range benchStoreCases {
		b.Run(tc.name, func(b *testing.B) {
			keys := benchKeys(b, tc.dist)
			s := New(tc.cap, func() time.Time { return benchNow }, zerolog.Nop())
			ctx := context.Background()
			for i := 0; b.Loop(); i++ {
				if _, err := s.Update(ctx, benchNS, keys[i%len(keys)], benchTTL, benchUpdateFn); err != nil {
					b.Fatalf("Update: %v", err)
				}
			}
		})
	}
}

func BenchmarkStoreUpdateParallel(b *testing.B) {
	for _, tc := range benchStoreCases {
		b.Run(tc.name, func(b *testing.B) {
			keys := benchKeys(b, tc.dist)
			s := New(tc.cap, func() time.Time { return benchNow }, zerolog.Nop())
			ctx := context.Background()
			var offsets atomic.Int64
			b.RunParallel(func(pb *testing.PB) {
				// Each goroutine starts at a distinct stride offset so
				// goroutines do not march through the key pool in
				// lockstep (257 is coprime with the 1024-line corpus).
				i := int(offsets.Add(257))
				for pb.Next() {
					if _, err := s.Update(ctx, benchNS, keys[i%len(keys)], benchTTL, benchUpdateFn); err != nil {
						b.Errorf("Update: %v", err)
						return
					}
					i++
				}
			})
		})
	}
}
