package memory

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/HT4w5/webmedkit/bandage/internal/bench"
	"github.com/HT4w5/webmedkit/bandage/internal/domain"
	"github.com/HT4w5/webmedkit/bandage/internal/domain/track"
)

// Benchmarks measure Store.Update per call (sequential and contended over the
// uniform, Zipfian and hot key distributions) plus the sweep and stats snapshot.

const (
	benchNS  = "bench-rule"
	benchTTL = time.Hour
)

// benchNow is the fixed wall clock the store runs on (internal/bench.Epoch).
var benchNow = bench.Epoch

// benchUpdateFn is the accumulate step a tracker rule runs under the shard lock.
func benchUpdateFn(r *track.Record) { r.Accumulate(1, 0, benchNow.Unix()) }

// benchKeys derives one tracker-cache key per corpus line (client aggregated to
// its target prefix); the pools hold 256 distinct keys (one for DistHot).
func benchKeys(b *testing.B, dist bench.KeyDist) []string {
	b.Helper()
	corpus := bench.NewCorpus(bench.Seed, bench.ShapeFull, dist, 1024)
	keys := make([]string, corpus.Len())
	for i := range keys {
		ev := corpus.Event(i)
		keys[i] = domain.DefaultTargetPrefix.Aggregate(ev.RemoteAddr).String()
	}
	return keys
}

// benchStoreCases names the key distributions and the store cap: the steady-state
// cap keeps every distribution eviction-free, "evicting" deliberately thrashes it.
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
				// Distinct stride offset per goroutine so they do not
				// march through the key pool in lockstep (257 is coprime with 1024).
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

// seedStore fills s with n distinct tracker entries at ttl (fixture setup).
func seedStore(tb testing.TB, s *Store, n int, ttl time.Duration) {
	tb.Helper()
	ctx := context.Background()
	for i := range n {
		if _, err := s.Update(ctx, benchNS, fmt.Sprintf("bench-target-%d", i), ttl, benchUpdateFn); err != nil {
			tb.Fatalf("Update: %v", err)
		}
	}
}

// BenchmarkStoreSweepExpired measures one expiry sweep over all shards' LRU
// lists; the expiring case re-seeds expired entries with the timer stopped.
func BenchmarkStoreSweepExpired(b *testing.B) {
	const entries = 256
	for _, tc := range []struct {
		name     string
		ttl      time.Duration // negative: already expired at the fixed clock
		expiring bool
	}{
		{"live", benchTTL, false},
		{"expiring", -benchTTL, true},
	} {
		b.Run(tc.name, func(b *testing.B) {
			s := New(65536, func() time.Time { return benchNow }, zerolog.Nop())
			seedStore(b, s, entries, tc.ttl)
			for b.Loop() {
				if tc.expiring {
					b.StopTimer()
					seedStore(b, s, entries, tc.ttl)
					b.StartTimer()
				}
				s.SweepExpired()
			}
		})
	}
}

// BenchmarkStoreStatistics measures one Statistics() snapshot over a populated
// store: atomic counter reads plus a locked walk of every shard's LRU length.
func BenchmarkStoreStatistics(b *testing.B) {
	s := New(65536, func() time.Time { return benchNow }, zerolog.Nop())
	seedStore(b, s, 1024, benchTTL)
	for b.Loop() {
		_ = s.Statistics()
	}
}
