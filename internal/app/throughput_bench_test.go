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
	"github.com/HT4w5/bandage/internal/identity"
	"github.com/HT4w5/bandage/internal/infra/persistence/sqlite"
)

// Pipeline throughput and worker-scaling benchmarks over the assembled
// runPipeline chain and real syslog sockets; one op is one raw log line.

// benchWorkers are the pipeline.workers values the scaling curve samples.
var benchWorkers = [...]int{1, 2, 4, 8}

const (
	// benchCorpusLines is the pre-generated corpus size (corpus.Line
	// cycles it, so the timed region never builds fixtures).
	benchCorpusLines = 4096

	// drainEvery bounds the backlog the feed can build ahead of the pipeline.
	drainEvery = 1024

	// benchCacheRoomy never evicts at the corpus's key cardinality;
	// benchCacheEvicting sits below it, forcing churn.
	benchCacheRoomy    = 65536
	benchCacheEvicting = 256
)

// benchWall is the frozen wall clock every benchmark runs at.
var benchWall = time.Date(2025, 10, 17, 18, 0, 0, 0, time.UTC)

func benchNow() time.Time { return benchWall }

// benchEpisodeRules is the episode fixture: a Target accumulates one episode
// per benchEpisodeLen events; each episode Triggers and its write lands once.
const benchEpisodeRules = `
version: 0
chains:
  - name: throughput
    rules:
      - id: bench-episode
        tracker: {track: rate, leak: 0, volume: 3}
        actions: [{report: {reason: bench-overflow, ttl: 24h, penalty: limit-req-rate, rate: 200}}]
`

// benchMatchNeverRules is the same rule shape with a volume nothing reaches:
// no event overflows, so the Trigger and write paths never run.
const benchMatchNeverRules = `
version: 0
chains:
  - name: throughput
    rules:
      - id: bench-never
        tracker: {track: rate, leak: 0, volume: 1000000000000}
        actions: [{report: {reason: bench-overflow, ttl: 24h, penalty: limit-req-rate, rate: 200}}]
`

// benchScenario is one throughput scenario: rules, tracker-cache cap, rule
// IDs (the re-arm delete's filters) and the report-lifetime episode.
type benchScenario struct {
	name     string
	rules    string
	ruleIDs  []string
	cacheMax int
	ep       *benchEpisode
}

// benchScenarios is the scenario matrix; names are the benchmark sub-names.
var benchScenarios = []benchScenario{
	{name: "first-trigger", rules: benchEpisodeRules, ruleIDs: []string{"bench-episode"}, cacheMax: benchCacheRoomy, ep: &benchEpisodes[0]},
	{name: "first-trigger-evicting", rules: benchEpisodeRules, ruleIDs: []string{"bench-episode"}, cacheMax: benchCacheEvicting, ep: &benchEpisodes[0]},
	{name: "rearm-delete", rules: benchEpisodeRules, ruleIDs: []string{"bench-episode"}, cacheMax: benchCacheRoomy, ep: &benchEpisodes[1]},
	{name: "match-never", rules: benchMatchNeverRules, ruleIDs: []string{"bench-never"}, cacheMax: benchCacheRoomy},
	{name: "match-never-evicting", rules: benchMatchNeverRules, ruleIDs: []string{"bench-never"}, cacheMax: benchCacheEvicting},
}

// benchParams is the run-parameter clump every bench helper threads through;
// name renders the stable benchmark sub-name from it.
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

// benchConfig is the canonical test config with the scenario's cache cap and
// worker count.
func benchConfig(p benchParams) Config {
	return Config{
		Ingest:   Ingest{Driver: "syslog", Parser: "nginx", Syslog: Syslog{Network: p.network, Listen: p.listen}},
		DB:       DB{Driver: "sqlite", SQLite: SQLite{Path: ":memory:"}},
		Cache:    Cache{MaxEntries: p.sc.cacheMax},
		Pipeline: Pipeline{Workers: p.workers},
		API:      API{Listen: "127.0.0.1:0"},
	}
}

// newBenchDaemon assembles the daemon for a run with the frozen clock and a
// nop logger; teardown is registered on tb.
func newBenchDaemon(tb testing.TB, p benchParams) *Daemon {
	tb.Helper()
	chains, err := ParseRules([]byte(p.sc.rules))
	if err != nil {
		tb.Fatalf("ParseRules: %v", err)
	}
	// The report store sits behind a write ledger so every run's
	// writes/op is measurable.
	repo, err := sqlite.Open(":memory:")
	if err != nil {
		tb.Fatalf("sqlite.Open: %v", err)
	}
	d, err := New(benchConfig(p), chains, identity.For("bandage"),
		WithClock(benchNow), WithLogger(zerolog.Nop()),
		withStore(&writeLedger{reportStore: repo}))
	if err != nil {
		tb.Fatalf("New: %v", err)
	}
	return d
}

// startBenchPipeline starts the runPipeline chain with no socket: the feed
// hands lines straight to the daemon's line channel.
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

// stopBenchPipeline closes the line channel and joins the workers.
func stopBenchPipeline(tb testing.TB, d *Daemon) {
	tb.Helper()
	close(d.lines)
	d.wg.Wait()
	d.cancel()
	if err := d.repo.Close(); err != nil {
		tb.Errorf("close report store: %v", err)
	}
}

// startBenchIngest starts the full daemon and dials the ingest socket, like
// the binary wires it. The caller owns the returned conn.
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

// benchWire pre-renders the corpus as it goes on the wire: tcp frames one
// line per write, unixgram sends one datagram per line.
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

// benchRearm returns the run's re-arm step at a drain boundary: rearm-delete
// deletes the scenario's reports; first-trigger and match-never return nil.
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

// runPipelineBench is the timed feed, draining every drainEvery lines and
// after the loop inside the timed region so no counted line is left running.
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

// benchGC is the runtime's GC accounting over the measured region.
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

// reportBenchStats records throughput plus evictions/op, gc-cpu-frac and the
// /stats snapshot beside it.
func reportBenchStats(b *testing.B, d *Daemon, lines int, before, after benchGC) {
	b.Helper()
	bench.ReportLinesPerSec(b, lines)
	st := d.Stats()
	writes := d.repo.(*writeLedger).total()
	if lines > 0 {
		b.ReportMetric(float64(st.TrackerCache.Evictions)/float64(lines), "evictions/op")
		// writes/op should show one write per (rule, Target) per report
		// lifetime, never one per overflowing event.
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
// runPipeline chain per worker count and scenario, with no network.
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

// BenchmarkPipelineIngest is the ingest-inclusive variant over a real loopback
// syslog socket (tcp or unixgram); socket timing carries run-to-run variance.
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

// TestBenchPipelineScenariosMatchTheirNames pins the scenario contracts:
// exact line accounting and one write per (rule, Target) per report lifetime.
func TestBenchPipelineScenariosMatchTheirNames(t *testing.T) {
	const batches = 2
	lines := int64(batches * drainEvery)
	// Distinct keys exercise both cache namespaces, above benchCacheEvicting.
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
				// Cache churn resets episodes mid-flight: only the write
				// contract stays deterministic.
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
			// Only the final report lifetime's writes remain (earlier
			// lifetimes' rows were deleted).
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
