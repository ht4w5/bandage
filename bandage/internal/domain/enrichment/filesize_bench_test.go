package enrichment

import (
	"context"
	"fmt"
	"testing"

	"github.com/HT4w5/webmedkit/bandage/internal/domain"
)

// BenchmarkEnrich measures FilesizeEnricher.Enrich per event over a stub
// FilesizeCache (the domain lint keeps the real store out of this package).

// benchCache is a map-backed FilesizeCache double (no locking).
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

// benchEvents builds n events cycling 256 paths.
func benchEvents(n int) []domain.Event {
	events := make([]domain.Event, n)
	for i := range events {
		events[i] = domain.Event{
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
	// One op is one event, i.e. one log line.
	var rate float64
	if elapsed := b.Elapsed(); elapsed > 0 {
		rate = float64(lines) / elapsed.Seconds()
	}
	b.ReportMetric(rate, "lines/s")
}
