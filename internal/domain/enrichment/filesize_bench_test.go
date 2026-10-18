package enrichment

import (
	"context"
	"fmt"
	"testing"

	bandage "github.com/HT4w5/bandage/internal/domain"
)

// BenchmarkEnrich measures FilesizeEnricher.Enrich per event (spec
// hot-path inventory, stage 3): the EWMA update, the warm-up gate and
// the SizeBytes write. The domain lint (internal/domain/deps_test.go)
// keeps the real memory store out of this package, so this variant
// runs over a stub FilesizeCache and the production variant over the
// real store lives in internal/app/enrich_bench_test.go; the store's
// own per-call cost is BenchmarkStoreUpdate in
// internal/infra/cache/memory. One op is one event, i.e. one log line.

// benchCache is a map-backed FilesizeCache double: per-path update
// without locking and LRU.
type benchCache struct{ records map[string]FilesizeRecord }

func newBenchCache() *benchCache {
	return &benchCache{records: make(map[string]FilesizeRecord)}
}

func (c *benchCache) Update(_ context.Context, path string, fn func(*FilesizeRecord)) (FilesizeRecord, error) {
	r := c.records[path]
	fn(&r)
	c.records[path] = r
	return r, nil
}

// benchEvents builds the pre-parsed event pool: n events cycling 256
// paths — the domain-lint-safe stand-in for the internal/bench corpus
// (sibling domain modules cannot share fixtures; see deps_test.go).
func benchEvents(n int) []bandage.Event {
	events := make([]bandage.Event, n)
	for i := range events {
		events[i] = bandage.Event{
			Path:      fmt.Sprintf("/files/obj-%04d.bin", i%256),
			SentBytes: 6000,
		}
	}
	return events
}

func BenchmarkEnrich(b *testing.B) {
	fe, err := NewFilesizeEnricher(newBenchCache(), 5, 5)
	if err != nil {
		b.Fatalf("NewFilesizeEnricher: %v", err)
	}
	events := benchEvents(1024)
	ctx := context.Background()
	var lines int
	for b.Loop() {
		ev := events[lines%len(events)]
		if err := fe.Enrich(ctx, &ev); err != nil {
			b.Fatalf("Enrich: %v", err)
		}
		lines++
	}
	// One op is one log line (the shared bench helper is unreachable
	// under the domain lint; this mirrors bench.ReportLinesPerSec's
	// zero-elapsed guard).
	var rate float64
	if elapsed := b.Elapsed(); elapsed > 0 {
		rate = float64(lines) / elapsed.Seconds()
	}
	b.ReportMetric(rate, "lines/s")
}
