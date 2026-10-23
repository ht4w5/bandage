package app

import (
	"context"
	"testing"

	"github.com/rs/zerolog"

	"github.com/HT4w5/webmedkit/bandage/internal/bench"
	"github.com/HT4w5/webmedkit/bandage/internal/domain/enrichment"
	"github.com/HT4w5/webmedkit/bandage/internal/infra/cache/memory"
)

// BenchmarkEnrichMemory measures FilesizeEnricher.Enrich over the real memory
// tracker store; one op is one pre-parsed corpus event (one log line).
func BenchmarkEnrichMemory(b *testing.B) {
	corpus := bench.NewCorpus(bench.Seed, bench.ShapeFull, bench.DistZipf, 1024)
	store := memory.New(benchCacheRoomy, benchClock, zerolog.Nop())
	fe, err := enrichment.NewFilesizeEnricher(memory.NewFilesize(store), filesizePeriod, filesizeMinSamples)
	if err != nil {
		b.Fatalf("NewFilesizeEnricher: %v", err)
	}
	ctx := context.Background()
	var lines int
	for b.Loop() {
		ev := benchEvent(corpus, lines)
		if err := fe.Enrich(ctx, &ev); err != nil {
			b.Fatalf("Enrich: %v", err)
		}
		lines++
	}
	bench.ReportLinesPerSec(b, lines)
}
