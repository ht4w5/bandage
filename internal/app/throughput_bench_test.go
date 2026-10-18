package app

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"runtime/metrics"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/HT4w5/bandage/internal/bench"
	"github.com/HT4w5/bandage/internal/domain/report"
	"github.com/HT4w5/bandage/internal/infra/persistence/sqlite"
)

// Pipeline throughput and worker-scaling benchmarks (spec v0-benchmarks
// Phase 2, ticket 03): the assembled runPipeline chain — parse →
// enrich → evaluate → report write → per-line bookkeeping — driven with
// a pre-generated corpus at pipeline.workers = 1/2/4/8, plus an
// ingest-inclusive variant over real loopback syslog sockets (tcp and
// unixgram) that adds go-syslog parsing and the channel handoff (H5).
//
// Method: one op is one raw log line. The corpus is built once before
// b.Loop() (fixed bench.Seed, ShapeFull/DistZipf), the wall clock is
// frozen at benchWall (WithClock — nothing expires or time-stamps
// differently between runs), and the pipeline-only variant hands lines
// straight to the daemon's line channel: no socket anywhere in that
// path. The timed region covers the processing of every counted line:
// the feed is back-pressured by the unbuffered line channel, the
// harness drains every drainEvery lines, and the final drain runs
// inside the timed region (runPipelineBench), so lines/s never counts
// a line whose processing finished after the timer stopped. Throughput
// is reported as lines/s via bench.ReportLinesPerSec; run with -benchmem
// for ns/op, B/op and allocs/op; gc-cpu-frac and evictions/op and the
// /stats snapshot are recorded beside them (reportBenchStats).
//
// The scenarios vary the match path (GLOSSARY: Match, Trigger) and the
// tracker-cache cap. The write side is the v0-hot-path episode
// re-modeling (spec stories 30–31): the retired overflow-every-event
// trick — a report write per event — is gone, and the scenarios model
// report episodes instead (one write per (rule, Target) per report
// lifetime, visible in the baseline as writes/op):
//
//   - first-trigger / rearm-delete run the episode fixture: every
//     accumulation episode Triggers the rule's report action, but one
//     write lands per (rule, Target) per report lifetime.
//     first-trigger's lifetime is the whole run (the write falls
//     silent after every Target's first Trigger), while rearm-delete
//     deletes the scenario's reports at every drain boundary — the
//     operator's re-arm lever (spec story 9) — so every episode writes
//     again. Both are read against the retired trick's per-event write
//     ceiling (≈23k lines/s, findings.md).
//   - match-never is the fast-path floor: the same filter and tracker
//     work per event with a volume nothing ever reaches, so no rule
//     Matches and neither the Trigger nor the write path runs (H4).
//   - *-evicting runs the same rules with a cache cap below the
//     corpus's key cardinality (~512 distinct filesize paths plus
//     tracker Targets), so the store evicts instead of holding state.
//
// These benchmarks measure, they do not assert: nothing here runs
// under make test (no -bench flag). The scenario contracts are pinned
// by TestBenchPipelineScenariosMatchTheirNames below.

// benchWorkers are the pipeline.workers values the scaling curve
// samples (spec Phase 2).
var benchWorkers = [...]int{1, 2, 4, 8}

const (
	// benchCorpusLines is the pre-generated corpus size; corpus.Line
	// cycles it, so the timed region never builds fixtures.
	benchCorpusLines = 4096

	// drainEvery bounds the backlog the feed can build ahead of the
	// pipeline: every drainEvery lines the harness waits for the
	// pipeline to catch up inside the timed region. The wait's own
	// stall (at most one line's processing per batch) is far below one
	// percent.
	drainEvery = 1024

	// benchCacheRoomy is the default entry cap: no evictions at the
	// corpus's key cardinality. benchCacheEvicting sits below the ~512
	// distinct keys (filesize paths + tracker Targets), forcing churn.
	benchCacheRoomy    = 65536
	benchCacheEvicting = 256
)

// benchWall is the frozen wall clock every benchmark runs at: report
// timestamps, cache expiry and /stats all see this instant.
var benchWall = time.Date(2025, 10, 17, 18, 0, 0, 0, time.UTC)

func benchNow() time.Time { return benchWall }

// benchEpisodeRules is the episode fixture (the retired
// overflow-every-event trick is not the episode model): a rate tracker
// with volume above the per-event increment, so a Target accumulates
// one episode per benchEpisodeLen events (Overflow is strictly above
// volume; leak 0 pins the bucket against decay). Every episode
// Triggers (GLOSSARY) and runs the report action — the Trigger empties
// the tracker, so episodes recur at that cadence — while its write
// lands once per report lifetime (benchScenarios).
const benchEpisodeRules = `
version: 0
chains:
  - name: throughput
    rules:
      - id: bench-episode
        tracker: {track: rate, leak: 0, volume: 3}
        actions: [{report: {reason: bench-overflow, ttl: 24h}}]
`

// benchMatchNeverRules is the same rule shape with the volume far above
// anything the corpus accumulates: the filter and tracker-update paths
// run per event exactly as in benchEpisodeRules, but no event
// overflows, so no rule ever Matches and no report is ever written.
// The delta between it and the episode scenarios is the Trigger path
// alone.
const benchMatchNeverRules = `
version: 0
chains:
  - name: throughput
    rules:
      - id: bench-never
        tracker: {track: rate, leak: 0, volume: 1000000000000}
        actions: [{report: {reason: bench-overflow, ttl: 24h}}]
`

// benchScenario is one throughput scenario: rules shaping the match
// path, the tracker-cache entry cap, the fixture's rule IDs (the
// re-arm delete's filters) and the report-lifetime episode (nil for
// match-never).
type benchScenario struct {
	name     string
	rules    string
	ruleIDs  []string
	cacheMax int
	ep       *benchEpisode
}

// benchScenarios is the scenario matrix every worker count runs
// against. Names are stable: they are the benchmark sub-names.
var benchScenarios = []benchScenario{
	{name: "first-trigger", rules: benchEpisodeRules, ruleIDs: []string{"bench-episode"}, cacheMax: benchCacheRoomy, ep: &benchEpisodes[0]},
	{name: "first-trigger-evicting", rules: benchEpisodeRules, ruleIDs: []string{"bench-episode"}, cacheMax: benchCacheEvicting, ep: &benchEpisodes[0]},
	{name: "rearm-delete", rules: benchEpisodeRules, ruleIDs: []string{"bench-episode"}, cacheMax: benchCacheRoomy, ep: &benchEpisodes[1]},
	{name: "match-never", rules: benchMatchNeverRules, ruleIDs: []string{"bench-never"}, cacheMax: benchCacheRoomy},
	{name: "match-never-evicting", rules: benchMatchNeverRules, ruleIDs: []string{"bench-never"}, cacheMax: benchCacheEvicting},
}

// benchParams is the run-parameter clump every bench helper threads
// through: the scenario (rules + tracker-cache cap), the pipeline
// worker count, and the ingest socket (network and listen address —
// empty for the no-socket pipeline variant). name renders the stable
// benchmark sub-name from it.
type benchParams struct {
	sc      benchScenario
	workers int
	network string // ingest socket network: "tcp" or "unixgram"; "" = no socket
	listen  string // ingest socket address (bench.ListenAddr fills it)
}

func (p benchParams) name() string {
	if p.network == "" {
		return fmt.Sprintf("%s/workers=%d", p.sc.name, p.workers)
	}
	return fmt.Sprintf("%s/%s/workers=%d", p.network, p.sc.name, p.workers)
}

// benchConfig is the canonical test config with the scenario's cache
// cap and worker count (the e2e_config literal, parameterized).
func benchConfig(p benchParams) Config {
	return Config{
		Ingest:   Ingest{Driver: "syslog", Parser: "nginx", Syslog: Syslog{Network: p.network, Listen: p.listen}},
		DB:       DB{Driver: "sqlite", SQLite: SQLite{Path: ":memory:"}},
		Cache:    Cache{MaxEntries: p.sc.cacheMax},
		Pipeline: Pipeline{Workers: p.workers},
		API:      API{Listen: "127.0.0.1:0"},
	}
}

// newBenchDaemon assembles the daemon for a run: real rules, parser,
// enricher, evaluation, in-memory tracker store and sqlite :memory:
// report repository, with the frozen clock and a nop logger (no logging
// in the measured path, no eviction record rendering). Teardown is
// registered on tb and runs after the timed region.
func newBenchDaemon(tb testing.TB, p benchParams) *Daemon {
	tb.Helper()
	chains, err := ParseRules([]byte(p.sc.rules))
	if err != nil {
		tb.Fatalf("ParseRules: %v", err)
	}
	// The report store sits behind a write ledger so every run's
	// writes/op is measurable — the episode write-rate evidence lives
	// in the baseline itself.
	repo, err := sqlite.Open(":memory:")
	if err != nil {
		tb.Fatalf("sqlite.Open: %v", err)
	}
	d, err := New(benchConfig(p), chains,
		WithClock(benchNow), WithLogger(zerolog.Nop()),
		withStore(&writeLedger{reportStore: repo}))
	if err != nil {
		tb.Fatalf("New: %v", err)
	}
	return d
}

// startBenchPipeline starts the real runPipeline chain with no socket
// at all: the benchmark feeds the daemon's line channel directly — the
// handoff the syslog source feeds in production (H5's second half).
// stopBenchPipeline is registered for teardown.
func startBenchPipeline(tb testing.TB, p benchParams) *Daemon {
	tb.Helper()
	p.network, p.listen = "unixgram", "unused" // no socket runs; config shape only
	d := newBenchDaemon(tb, p)
	d.ctx, d.cancel = context.WithCancel(context.Background())
	d.startedAt = d.now()
	d.wg.Add(d.workers)
	for range d.workers {
		go d.runPipeline()
	}
	tb.Cleanup(func() { stopBenchPipeline(tb, d) })
	return d
}

// stopBenchPipeline closes the line channel, joins the workers and the
// report repository. The daemon never started sockets, so the full
// Shutdown path does not apply.
func stopBenchPipeline(tb testing.TB, d *Daemon) {
	tb.Helper()
	close(d.lines)
	d.wg.Wait()
	d.cancel()
	if err := d.repo.Close(); err != nil {
		tb.Errorf("close report store: %v", err)
	}
}

// startBenchIngest starts the full daemon — syslog source, pipeline
// workers, sweeper, HTTP API — and dials the ingest socket, like the
// binary wires it (the e2e seam, driven by benchmarks). The caller
// owns the returned conn; daemon teardown is registered on tb.
func startBenchIngest(tb testing.TB, p benchParams) (*Daemon, net.Conn) {
	tb.Helper()
	p.listen = bench.ListenAddr(tb, p.network)
	d := newBenchDaemon(tb, p)
	if err := d.Start(context.Background()); err != nil {
		tb.Fatalf("Start: %v", err)
	}
	conn, err := net.Dial(p.network, p.listen)
	if err != nil {
		tb.Fatalf("dial %s: %v", p.network, err)
	}
	tb.Cleanup(func() {
		conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := d.Shutdown(ctx); err != nil {
			tb.Errorf("Shutdown: %v", err)
		}
	})
	return d, conn
}

// benchWire pre-renders the corpus as it goes on the wire: tcp frames
// one line per write with a trailing newline (the e2e send convention),
// unixgram sends one datagram per line. Pre-rendered before the timed
// region so no []byte conversion happens per iteration.
func benchWire(corpus *bench.Corpus, network string) [][]byte {
	wire := make([][]byte, corpus.Len())
	for i := range wire {
		line := corpus.Line(i)
		if network == "tcp" {
			line += "\n"
		}
		wire[i] = []byte(line)
	}
	return wire
}

// waitLines blocks until n lines are fully processed (parsed and
// evaluated, or dropped).
func waitLines(tb testing.TB, d *Daemon, n int) {
	tb.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := d.waitProcessed(ctx, int64(n)); err != nil {
		tb.Fatalf("waitProcessed(%d): %v", n, err)
	}
}

// benchRearm returns the run's re-arm step at a drain boundary — a
// report-lifetime boundary for the re-arm scenarios (spec stories
// 9–10). rearm-delete deletes the scenario's reports like the API's
// delete-by-filter — the operator's re-arm lever, so the next episode
// writes again — and rolls the write ledger's report lifetime with it.
// first-trigger and match-never never re-arm inside a run (nil step).
func benchRearm(tb testing.TB, sc benchScenario, d *Daemon) func() {
	tb.Helper()
	if sc.ep == nil || sc.ep.kind != rearmDelete {
		return nil
	}
	ledger := d.repo.(*writeLedger)
	return func() {
		for _, id := range sc.ruleIDs {
			if _, err := d.reports.Delete(context.Background(), report.Query{Rule: id, Now: d.now()}); err != nil {
				tb.Fatalf("re-arm delete %q: %v", id, err)
			}
		}
		ledger.newLifetime()
	}
}

// runPipelineBench is the timed feed: send hands line i to the daemon
// (blocking on the unbuffered handoff, so the feed rate is the
// pipeline's sustained rate), draining every drainEvery lines and
// after the loop so the processed count always catches up. rearm runs
// at every drain boundary — the episode scenario's report-lifetime
// boundary — and is timed like everything else in the modeled
// workload. The final drain runs inside the timed region (Loop stops
// the timer when it returns, so it is restarted around the drain):
// every line counted in lines/s and in ns/op, B/op, allocs/op is fully
// processed before the timer stops. Returns the lines fed (one op
// each).
func runPipelineBench(b *testing.B, d *Daemon, send func(i int), rearm func()) int {
	b.Helper()
	var lines int
	for b.Loop() {
		send(lines)
		lines++
		if lines%drainEvery == 0 {
			waitLines(b, d, lines)
			if rearm != nil {
				rearm()
			}
		}
	}
	b.StartTimer()
	waitLines(b, d, lines)
	b.StopTimer()
	return lines
}

// benchGC is the runtime's GC accounting over the measured region:
// cpu-seconds and GC cycles, read through runtime/metrics.
type benchGC struct {
	gcSeconds  float64 // /cpu/classes/gc/total:cpu-seconds
	cpuSeconds float64 // /cpu/classes/total:cpu-seconds
	cycles     float64 // /gc/cycles/total:gc-cycles
}

// readGC snapshots the GC counters behind gc-cpu-frac.
func readGC() benchGC {
	samples := []metrics.Sample{
		{Name: "/cpu/classes/gc/total:cpu-seconds"},
		{Name: "/cpu/classes/total:cpu-seconds"},
		{Name: "/gc/cycles/total:gc-cycles"},
	}
	metrics.Read(samples)
	return benchGC{
		gcSeconds:  samples[0].Value.Float64(),
		cpuSeconds: samples[1].Value.Float64(),
		cycles:     float64(samples[2].Value.Uint64()),
	}
}

// reportBenchStats records throughput and the bookkeeping beside it:
// evictions/op and gc-cpu-frac as metrics (the allocs/op and B/op come
// from -benchmem), and the full /stats snapshot in the log. gc-cpu-frac
// is the GC's share of total CPU capacity (GOMAXPROCS × wall) over the
// measured region: Δ /cpu/classes/gc/total over Δ /cpu/classes/total
// (runtime/metrics) — marking, assist and scavenge work included, not
// just stop-the-world pauses (the earlier gc-pause-frac substitution).
func reportBenchStats(b *testing.B, d *Daemon, lines int, before, after benchGC) {
	b.Helper()
	bench.ReportLinesPerSec(b, lines)
	st := d.Stats()
	writes := d.repo.(*writeLedger).total()
	if lines > 0 {
		b.ReportMetric(float64(st.TrackerCache.Evictions)/float64(lines), "evictions/op")
		// writes/op is the episode evidence in the baseline itself:
		// one write per (rule, Target) per report lifetime, never one
		// per overflowing event.
		b.ReportMetric(float64(writes)/float64(lines), "writes/op")
	}
	if dCPU := after.cpuSeconds - before.cpuSeconds; dCPU > 0 {
		b.ReportMetric((after.gcSeconds-before.gcSeconds)/dCPU, "gc-cpu-frac")
	}
	b.Logf("/stats workers=%d received=%d parsed=%d dropped=%d writes=%d cache={gets:%d sets:%d misses:%d evictions:%d size:%d cap:%d} gc=%d gomaxprocs=%d",
		st.Pipeline.Workers, st.Pipeline.Received, st.Pipeline.Parsed, st.Pipeline.Dropped, writes,
		st.TrackerCache.Gets, st.TrackerCache.Sets, st.TrackerCache.Misses,
		st.TrackerCache.Evictions, st.TrackerCache.Size, st.TrackerCache.EntryCap,
		int(after.cycles-before.cycles), runtime.GOMAXPROCS(0))
}

// BenchmarkPipeline measures sustained throughput of the assembled
// runPipeline chain per worker count and scenario, with no network in
// the timed path: corpus lines go straight onto the daemon's line
// channel. The worker-scaling curve and its flatten point come from
// comparing the workers=N sub-benchmarks of one scenario.
func BenchmarkPipeline(b *testing.B) {
	for _, sc := range benchScenarios {
		for _, w := range benchWorkers {
			p := benchParams{sc: sc, workers: w}
			b.Run(p.name(), func(b *testing.B) {
				corpus := bench.NewCorpus(bench.Seed, bench.ShapeFull, bench.DistZipf, benchCorpusLines)
				d := startBenchPipeline(b, p)
				rearm := benchRearm(b, sc, d)
				before := readGC()
				lines := runPipelineBench(b, d, func(i int) { d.lines <- corpus.Line(i) }, rearm)
				after := readGC()
				reportBenchStats(b, d, lines, before, after)
			})
		}
	}
}

// BenchmarkPipelineIngest is the ingest-inclusive variant: the same
// pipeline driven over a real loopback syslog socket (tcp or unixgram),
// capturing go-syslog's format detection and the parts→lines channel
// handoff on top of the pipeline (H5). Real-socket timing is not
// perfectly deterministic — the lines/s numbers carry run-to-run
// variance the deterministic corpus and frozen clock cannot remove.
func BenchmarkPipelineIngest(b *testing.B) {
	for _, network := range []string{"tcp", "unixgram"} {
		for _, sc := range benchScenarios {
			for _, w := range benchWorkers {
				p := benchParams{sc: sc, workers: w, network: network}
				b.Run(p.name(), func(b *testing.B) {
					corpus := bench.NewCorpus(bench.Seed, bench.ShapeFull, bench.DistZipf, benchCorpusLines)
					d, conn := startBenchIngest(b, p)
					wire := benchWire(corpus, network)
					rearm := benchRearm(b, sc, d)
					before := readGC()
					lines := runPipelineBench(b, d, func(i int) {
						if _, err := conn.Write(wire[i%len(wire)]); err != nil {
							b.Fatalf("send: %v", err)
						}
					}, rearm)
					after := readGC()
					reportBenchStats(b, d, lines, before, after)
				})
			}
		}
	}
}

// TestBenchPipelineScenariosMatchTheirNames pins the benchmark
// scenario contracts at the assembled seam: every line is counted
// exactly once (received = parsed, nothing dropped), the roomy cap
// never evicts and the evicting cap does, and the write cells follow
// the episode contract — one write per (rule, Target) per report
// lifetime, exactly where the fixture's episodes Trigger. Expected
// Triggers and write cells are derived from the fixture events alone
// (episodeOracle), so they can disagree with the pipeline. Under the
// evicting cap cache churn resets accumulation episodes mid-flight, so
// only the write contract and its bounds stay deterministic — the
// exact counts live on the roomy cells.
func TestBenchPipelineScenariosMatchTheirNames(t *testing.T) {
	const batches = 2
	lines := int64(batches * drainEvery)
	// Distinct keys exercise both cache namespaces: ~250 filesize
	// paths plus ~250 tracker Targets — above benchCacheEvicting.
	corpus := bench.NewCorpus(bench.Seed, bench.ShapeFull, bench.DistUniform, drainEvery)

	tests := []struct {
		name        string
		sc          benchScenario
		wantEvicted bool
	}{
		{name: "first-trigger", sc: benchScenarios[0]},
		{name: "first-trigger-evicting", sc: benchScenarios[1], wantEvicted: true},
		{name: "rearm-delete", sc: benchScenarios[2]},
		{name: "match-never", sc: benchScenarios[3]},
		{name: "match-never-evicting", sc: benchScenarios[4], wantEvicted: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := startBenchPipeline(t, benchParams{sc: tt.sc, workers: 4})
			ledger := d.repo.(*writeLedger)

			var oracle *episodeOracle
			if tt.sc.ep != nil {
				oracle = newEpisodeOracle(benchRules(t, tt.sc.rules))
			}
			rearm := benchRearm(t, tt.sc, d)
			for batch := range batches {
				for i := range drainEvery {
					j := batch*drainEvery + i
					if oracle != nil {
						oracle.event(corpus.Event(j), benchWall)
					}
					d.lines <- corpus.Line(j)
				}
				waitLines(t, d, (batch+1)*drainEvery)
				if rearm != nil && batch < batches-1 {
					rearm()
					oracle.boundary()
				}
			}

			c := d.counters()
			if c.Received != lines || c.Parsed != lines || c.Dropped != 0 {
				t.Errorf("counters = %+v, want {Received:%d Parsed:%d Dropped:0}", c, lines, lines)
			}

			switch {
			case oracle == nil:
				if n := ledger.total(); n != 0 {
					t.Errorf("report writes = %d, want 0 (match-never never writes)", n)
				}
			case tt.wantEvicted:
				// Cache churn resets accumulation episodes mid-flight:
				// exact counts are gone, the write contract is not — one
				// write per (rule, Target) per report lifetime, and never
				// more writes than the un-evicting episodes have Triggers.
				for cell, n := range ledger.counts() {
					if n != 1 {
						t.Errorf("write cell %+v = %d, want 1 (one write per (rule, Target) per report lifetime)", cell, n)
					}
				}
				if got, want := ledger.total(), oracle.triggers; got > want {
					t.Errorf("report writes = %d, want at most %d (one write per Trigger at most)", got, want)
				}
			default:
				assertWrites(t, ledger, oracle.writes)
			}

			recs, err := d.repo.List(context.Background(), report.Query{Now: benchWall})
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			// What GET /reports serves after the run: the final report
			// lifetime's writes (earlier lifetimes' rows were deleted).
			wantRecs := 0
			if oracle != nil {
				for cell := range oracle.writes {
					if cell.life == oracle.life {
						wantRecs++
					}
				}
			}
			if tt.wantEvicted {
				if len(recs) > wantRecs {
					t.Errorf("reports = %d, want at most %d (the final lifetime's writes)", len(recs), wantRecs)
				}
			} else if len(recs) != wantRecs {
				t.Errorf("reports = %d, want %d (the final report lifetime's writes)", len(recs), wantRecs)
			}

			evicted := d.Stats().TrackerCache.Evictions > 0
			if evicted != tt.wantEvicted {
				t.Errorf("evicted = %v (%d), want %v",
					evicted, d.Stats().TrackerCache.Evictions, tt.wantEvicted)
			}
		})
	}
}
