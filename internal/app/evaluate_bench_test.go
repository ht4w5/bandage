package app

import (
	"context"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/HT4w5/bandage/internal/bench"
	bandage "github.com/HT4w5/bandage/internal/domain"
	"github.com/HT4w5/bandage/internal/domain/evaluation"
	"github.com/HT4w5/bandage/internal/domain/report"
	"github.com/HT4w5/bandage/internal/infra/cache/memory"
	"github.com/HT4w5/bandage/internal/infra/persistence/sqlite"
)

// The integration variants of BenchmarkEvaluate (spec Phase 1): full
// chain evaluation over pre-parsed corpus events with the real memory
// tracker store, first against an in-memory report sink (the production
// path minus sqlite) and then against the sqlite sink to expose the
// write-path cost (H4, H6). The stub-port variant lives beside the
// domain code in domain/evaluation; the domain lint keeps these
// adapters out of that package.

// benchFireRules and benchQuietRules are the chain fixtures: tracker
// rules with real filters matching every corpus event, one rule per
// chain. A report rule is terminal, so single-rule chains keep the
// fires/never-fires paths doing identical filter and tracker work and
// differing only in the report writes. The fire rules overflow on every
// event (rate, leak 0, volume 0.5 — one request always exceeds half a
// request), so every event exercises the report write path. The quiet
// rules decay at 10/s (rate) and 1GB/s (bandwidth, against increments
// below 8MB) and, at benchEvent's one-second event spacing, never
// overflow, so the write path never runs. The split isolates write-path
// cost; TestEvaluateBenchScenarios pins both behaviors.
const benchFireRules = `
version: 0
chains:
  - name: download-abuse
    rules:
      - id: egress-flood
        filter: 'src 198.51.100.0/24 or src 203.0.113.0/24'
        tracker: {track: rate, leak: 0, volume: 0.5}
        actions: [{report: {reason: egress-overflow, ttl: 1h}}]
  - name: request-flood
    rules:
      - id: request-flood
        filter: 'method GET or method HEAD or method POST'
        tracker: {track: rate, leak: 0, volume: 0.5}
        actions: [{report: {reason: request-flood, ttl: 1h}}]
  - name: scanning
    rules:
      - id: probe-flood
        filter: 'path prefix "/files/" or path prefix "/releases/"'
        tracker: {track: rate, leak: 0, volume: 0.5}
        actions: [{report: {reason: probe-scan, ttl: 1h}}]
  - name: error-scanning
    rules:
      - id: error-flood
        filter: 'status class 2 or status class 3 or status class 4 or status class 5'
        tracker: {track: rate, leak: 0, volume: 0.5}
        actions: [{report: {reason: error-probe, ttl: 1h}}]
`

const benchQuietRules = `
version: 0
chains:
  - name: download-abuse
    rules:
      - id: sustained-egress
        filter: 'src 198.51.100.0/24 or src 203.0.113.0/24'
        tracker: {track: bandwidth, leak: 1GB, volume: 100GB}
        actions: [{report: {reason: egress-overflow, ttl: 1h}}]
  - name: request-flood
    rules:
      - id: rapid-requests
        filter: 'method GET or method HEAD or method POST'
        tracker: {track: rate, leak: 10, volume: 200}
        actions: [{report: {reason: request-flood, ttl: 1h}}]
  - name: scanning
    rules:
      - id: probe-paths
        filter: 'path prefix "/files/" or path prefix "/releases/"'
        tracker: {track: rate, leak: 10, volume: 200}
        actions: [{report: {reason: probe-scan, ttl: 1h}}]
  - name: error-scanning
    rules:
      - id: error-scan
        filter: 'status class 2 or status class 3 or status class 4 or status class 5'
        tracker: {track: rate, leak: 10, volume: 200}
        actions: [{report: {reason: error-probe, ttl: 1h}}]
`

// benchClock is the fixed wall clock the benchmarks evaluate on.
func benchClock() time.Time { return time.Unix(1734345934, 0).UTC() }

// benchEvent returns corpus event i with its timestamp at the i-th
// second of the fixture epoch. Evaluation time must march forward per
// op: cycling the corpus timestamps would freeze the leaky bucket's
// LastUpdate and let the quiet rules' value creep past their volume.
// The same step drives the benchmark loops and the fixture test.
func benchEvent(corpus *bench.Corpus, i int) bandage.Event {
	ev := corpus.Event(i)
	ev.Time = benchClock().Add(time.Duration(i) * time.Second)
	return ev
}

// memSink is the in-memory report sink variant: one report retained per
// (rule, target), the sqlite row shape without the write path. Serial
// use only — the benchmarks and their fixture test drive one event at
// a time.
type memSink struct {
	reports  map[string]bandage.Report
	triggers int
}

func newMemSink() *memSink {
	return &memSink{reports: make(map[string]bandage.Report)}
}

func (s *memSink) Trigger(_ context.Context, rec bandage.Report) error {
	s.reports[rec.Rule+bandage.KeySep+rec.Target] = rec
	s.triggers++
	return nil
}

// benchRules loads a fixture's chains or fails b.
func benchRules(b *testing.B, rules string) []bandage.Chain {
	b.Helper()
	chains, err := ParseRules([]byte(rules))
	if err != nil {
		b.Fatalf("ParseRules error: %v", err)
	}
	return chains
}

// TestEvaluateBenchScenarios verifies the benchmark fixtures fire the
// scenario they name (the H4 measurements rest on it): over several
// corpus passes the fire rules trigger a report on every event and the
// quiet rules trigger none.
func TestEvaluateBenchScenarios(t *testing.T) {
	tests := []struct {
		name     string
		rules    string
		perEvent int // report triggers per event: one per single-rule chain
	}{
		{"fires", benchFireRules, 4},
		{"never-fires", benchQuietRules, 0},
	}
	corpus := bench.NewCorpus(bench.Seed, bench.ShapeFull, bench.DistZipf, 1024)
	const passes = 10
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chains, err := ParseRules([]byte(tt.rules))
			if err != nil {
				t.Fatalf("ParseRules error: %v", err)
			}
			sink := newMemSink()
			svc := evaluation.NewService(chains, memory.New(65536, benchClock, zerolog.Nop()), sink, benchClock, nil)
			ctx := context.Background()
			var events int
			for i := 0; i < passes*corpus.Len(); i++ {
				ev := benchEvent(corpus, i)
				if err := svc.Evaluate(ctx, &ev); err != nil {
					t.Fatalf("Evaluate error: %v", err)
				}
				events++
			}
			want := tt.perEvent * events
			if sink.triggers != want {
				t.Fatalf("triggers = %d, want %d (%d per event over %d events)", sink.triggers, want, tt.perEvent, events)
			}
		})
	}
}

// benchEvaluate runs the shared evaluate loop against a prepared
// service. One op is one pre-parsed corpus event, i.e. one log line.
func benchEvaluate(b *testing.B, svc *evaluation.Service) {
	b.Helper()
	corpus := bench.NewCorpus(bench.Seed, bench.ShapeFull, bench.DistZipf, 1024)
	ctx := context.Background()
	var lines int
	for b.Loop() {
		ev := benchEvent(corpus, lines)
		if err := svc.Evaluate(ctx, &ev); err != nil {
			b.Fatalf("Evaluate: %v", err)
		}
		lines++
	}
	bench.ReportLinesPerSec(b, lines)
}

// BenchmarkEvaluateMemory is BenchmarkEvaluate with the real memory
// tracker store and the in-memory report sink: the production path
// minus the sqlite write (H4, H6).
func BenchmarkEvaluateMemory(b *testing.B) {
	for _, tc := range []struct{ name, rules string }{
		{"fires", benchFireRules},
		{"never-fires", benchQuietRules},
	} {
		b.Run(tc.name, func(b *testing.B) {
			store := memory.New(65536, benchClock, zerolog.Nop())
			svc := evaluation.NewService(benchRules(b, tc.rules), store, newMemSink(), benchClock, nil)
			benchEvaluate(b, svc)
		})
	}
}

// BenchmarkEvaluateSQLite is BenchmarkEvaluate with the sqlite report
// sink (:memory: database): the write-path cost the in-memory variant
// excludes (H4).
func BenchmarkEvaluateSQLite(b *testing.B) {
	for _, tc := range []struct{ name, rules string }{
		{"fires", benchFireRules},
		{"never-fires", benchQuietRules},
	} {
		b.Run(tc.name, func(b *testing.B) {
			repo, err := sqlite.Open(":memory:")
			if err != nil {
				b.Fatalf("sqlite.Open: %v", err)
			}
			b.Cleanup(func() { repo.Close() })
			store := memory.New(65536, benchClock, zerolog.Nop())
			svc := evaluation.NewService(benchRules(b, tc.rules), store, report.NewService(repo), benchClock, nil)
			benchEvaluate(b, svc)
		})
	}
}
