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
// tracker-cache cap:
//
//   - match-every / match-never differ only in the leaky-bucket
//     volume: both run the filter and the tracker update per event, but
//     match-every overflows on every event and so Triggers a report
//     upsert per event while match-never never overflows. The delta
//     between the two curves isolates the match/write path (H4).
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

// benchMatchEveryRules triggers a report on every event: a rate tracker
// that overflows from the first event on (volume must be positive at
// load, and Overflow is strictly above it, so 0.5 overflows on the
// increment of 1 every event carries). leak 0 pins the bucket against
// decay, so every event Matches and Triggers (GLOSSARY).
const benchMatchEveryRules = `
version: 0
chains:
  - name: throughput
    rules:
      - id: bench-every
        tracker: {track: rate, leak: 0, volume: 0.5}
        actions: [{report: {reason: bench-overflow, ttl: 24h}}]
`

// benchMatchNeverRules is the same rule shape with the volume far above
// anything the corpus accumulates: the filter and tracker-update paths
// run per event exactly as in benchMatchEveryRules, but no event
// overflows, so no rule ever Matches and no report is ever written.
// The delta between the two scenarios is the match/write path alone.
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
// path plus the tracker-cache entry cap.
type benchScenario struct {
	name     string
	rules    string
	cacheMax int
}

// benchScenarios is the scenario matrix every worker count runs
// against. Names are stable: they are the benchmark sub-names.
var benchScenarios = []benchScenario{
	{name: "match-every", rules: benchMatchEveryRules, cacheMax: benchCacheRoomy},
	{name: "match-every-evicting", rules: benchMatchEveryRules, cacheMax: benchCacheEvicting},
	{name: "match-never", rules: benchMatchNeverRules, cacheMax: benchCacheRoomy},
	{name: "match-never-evicting", rules: benchMatchNeverRules, cacheMax: benchCacheEvicting},
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
	d, err := New(benchConfig(p), chains,
		WithClock(benchNow), WithLogger(zerolog.Nop()))
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

// feedLines hands n corpus lines to the pipeline and waits until every
// one is processed — the correctness-test driver.
func feedLines(tb testing.TB, d *Daemon, corpus *bench.Corpus, n int) {
	tb.Helper()
	for i := range n {
		d.lines <- corpus.Line(i)
	}
	waitLines(tb, d, n)
}

// runPipelineBench is the timed feed: send hands line i to the daemon
// (blocking on the unbuffered handoff, so the feed rate is the
// pipeline's sustained rate), draining every drainEvery lines and
// after the loop so the processed count always catches up. The final
// drain runs inside the timed region (Loop stops the timer when it
// returns, so it is restarted around the drain): every line counted in
// lines/s and in ns/op, B/op, allocs/op is fully processed before the
// timer stops. Returns the lines fed (one op each).
func runPipelineBench(b *testing.B, d *Daemon, send func(i int)) int {
	b.Helper()
	var lines int
	for b.Loop() {
		send(lines)
		lines++
		if lines%drainEvery == 0 {
			waitLines(b, d, lines)
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
	if lines > 0 {
		b.ReportMetric(float64(st.TrackerCache.Evictions)/float64(lines), "evictions/op")
	}
	if dCPU := after.cpuSeconds - before.cpuSeconds; dCPU > 0 {
		b.ReportMetric((after.gcSeconds-before.gcSeconds)/dCPU, "gc-cpu-frac")
	}
	b.Logf("/stats workers=%d received=%d parsed=%d dropped=%d cache={gets:%d sets:%d misses:%d evictions:%d size:%d cap:%d} gc=%d gomaxprocs=%d",
		st.Pipeline.Workers, st.Pipeline.Received, st.Pipeline.Parsed, st.Pipeline.Dropped,
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
				before := readGC()
				lines := runPipelineBench(b, d, func(i int) { d.lines <- corpus.Line(i) })
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
					before := readGC()
					lines := runPipelineBench(b, d, func(i int) {
						if _, err := conn.Write(wire[i%len(wire)]); err != nil {
							b.Fatalf("send: %v", err)
						}
					})
					after := readGC()
					reportBenchStats(b, d, lines, before, after)
				})
			}
		}
	}
}

// TestBenchPipelineScenariosMatchTheirNames pins the benchmark
// scenario contracts at the assembled seam: match-every Triggers one
// report per event Target and match-never none, every line is counted
// exactly once (received = parsed, nothing dropped), the roomy cap
// never evicts and the evicting cap does. The expected report count is
// derived from the fixture events alone, so it can disagree with the
// pipeline.
func TestBenchPipelineScenariosMatchTheirNames(t *testing.T) {
	const lines = 1024
	// Distinct keys exercise both cache namespaces: ~250 filesize
	// paths plus ~250 tracker Targets — above benchCacheEvicting.
	corpus := bench.NewCorpus(bench.Seed, bench.ShapeFull, bench.DistUniform, lines)
	targets := make(map[string]bool)
	for i := range lines {
		targets[corpus.Event(i).RemoteAddr.String()] = true
	}

	tests := []struct {
		name        string
		sc          benchScenario
		wantReports int
		wantEvicted bool
	}{
		{name: "match-every", sc: benchScenarios[0], wantReports: len(targets)},
		{name: "match-every-evicting", sc: benchScenarios[1], wantReports: len(targets), wantEvicted: true},
		{name: "match-never", sc: benchScenarios[2], wantReports: 0},
		{name: "match-never-evicting", sc: benchScenarios[3], wantReports: 0, wantEvicted: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := startBenchPipeline(t, benchParams{sc: tt.sc, workers: 4})
			feedLines(t, d, corpus, lines)

			c := d.counters()
			if c.Received != lines || c.Parsed != lines || c.Dropped != 0 {
				t.Errorf("counters = %+v, want {Received:%d Parsed:%d Dropped:0}", c, lines, lines)
			}

			recs, err := d.repo.List(context.Background(), report.Query{Now: benchWall})
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(recs) != tt.wantReports {
				t.Errorf("reports = %d, want %d (one per event Target for match-every, none for match-never)",
					len(recs), tt.wantReports)
			}

			evicted := d.Stats().TrackerCache.Evictions > 0
			if evicted != tt.wantEvicted {
				t.Errorf("evicted = %v (%d), want %v",
					evicted, d.Stats().TrackerCache.Evictions, tt.wantEvicted)
			}
		})
	}
}
