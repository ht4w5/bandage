package app

import (
	"context"
	"testing"

	"github.com/rs/zerolog"

	"github.com/HT4w5/bandage/internal/bench"
	"github.com/HT4w5/bandage/internal/domain/enrichment"
	"github.com/HT4w5/bandage/internal/infra/cache/memory"
)

// BenchmarkEnrichMemory is the production variant of BenchmarkEnrich
// (spec hot-path inventory, stage 3): FilesizeEnricher.Enrich over the
// real memory tracker store behind the FilesizeCache port
// (memory.NewFilesize) — the stage's per-line cost as the pipeline pays
// it. The stub-port variant lives beside the domain code in
// domain/enrichment; the domain lint keeps this adapter out of that
// package. One op is one pre-parsed corpus event, i.e. one log line.
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
