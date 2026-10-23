package app

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/HT4w5/webmedkit/bandage/internal/bench"
	"github.com/HT4w5/webmedkit/bandage/internal/domain"
	"github.com/HT4w5/webmedkit/bandage/internal/domain/evaluation"
	"github.com/HT4w5/webmedkit/bandage/internal/domain/report"
	"github.com/HT4w5/webmedkit/bandage/internal/infra/cache/memory"
	"github.com/HT4w5/webmedkit/bandage/internal/infra/persistence/sqlite"
)

// Integration variants of BenchmarkEvaluate: full chain evaluation with the
// real memory tracker store and production report service (memory and sqlite).

const (
	// benchEpisodeVolume is the episode fixture's tracker volume: a
	// Target accumulates benchEpisodeLen events per episode before Triggering.
	benchEpisodeVolume = 3.0
	benchEpisodeLen    = 4

	// benchRearmStep is the wall time one corpus pass advances in
	// rearm-expiry: past the 30m report TTL, below the 1h tracker cache TTL.
	benchRearmStep = 45 * time.Minute
)

// benchEpisodeChains is the episode fixture: four single-rule chains with
// benchEpisodeLen events per Target per episode.
const benchEpisodeChains = `
version: 0
chains:
  - name: download-abuse
    rules:
      - id: egress-flood
        filter: 'src 198.51.100.0/24 or src 203.0.113.0/24'
        tracker: {track: rate, leak: 0, volume: 3}
        actions: [{report: {reason: egress-overflow, ttl: 30m, penalty: limit-req-rate, rate: 200}}]
  - name: request-flood
    rules:
      - id: request-flood
        filter: 'method GET or method HEAD or method POST'
        tracker: {track: rate, leak: 0, volume: 3}
        actions: [{report: {reason: request-flood, ttl: 30m, penalty: limit-req-rate, rate: 200}}]
  - name: scanning
    rules:
      - id: probe-flood
        filter: 'path prefix "/files/" or path prefix "/releases/"'
        tracker: {track: rate, leak: 0, volume: 3}
        actions: [{report: {reason: probe-scan, ttl: 30m, penalty: limit-req-rate, rate: 200}}]
  - name: error-scanning
    rules:
      - id: error-flood
        filter: 'status class 2 or status class 3 or status class 4 or status class 5'
        tracker: {track: rate, leak: 0, volume: 3}
        actions: [{report: {reason: error-probe, ttl: 30m, penalty: limit-req-rate, rate: 200}}]
`

// benchMatchNeverChains decays fast enough that no event ever overflows:
// the fast-path floor the episode scenarios are read against.
const benchMatchNeverChains = `
version: 0
chains:
  - name: download-abuse
    rules:
      - id: sustained-egress
        filter: 'src 198.51.100.0/24 or src 203.0.113.0/24'
        tracker: {track: bandwidth, leak: 1GB, volume: 100GB}
        actions: [{report: {reason: egress-overflow, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
  - name: request-flood
    rules:
      - id: rapid-requests
        filter: 'method GET or method HEAD or method POST'
        tracker: {track: rate, leak: 10, volume: 200}
        actions: [{report: {reason: request-flood, ttl: 1h, penalty: limit-req-rate, rate: 200}}]
  - name: scanning
    rules:
      - id: probe-paths
        filter: 'path prefix "/files/" or path prefix "/releases/"'
        tracker: {track: rate, leak: 10, volume: 200}
        actions: [{report: {reason: probe-scan, ttl: 1h, penalty: limit-req-rate, rate: 200}}]
  - name: error-scanning
    rules:
      - id: error-scan
        filter: 'status class 2 or status class 3 or status class 4 or status class 5'
        tracker: {track: rate, leak: 10, volume: 200}
        actions: [{report: {reason: error-probe, ttl: 1h, penalty: limit-req-rate, rate: 200}}]
`

// benchClock is the fixture event-time origin the corpus timestamps march
// from.
func benchClock() time.Time { return bench.Epoch }

// benchEvent returns corpus event i at the i-th second of the fixture epoch;
// time must march forward per op or the leaky buckets creep past their volume.
func benchEvent(corpus *bench.Corpus, i int) domain.Event {
	ev := corpus.Event(i)
	ev.Time = benchClock().Add(time.Duration(i) * time.Second)
	return ev
}

// memRepo is the in-memory report store behind the report service; serial use
// only.
type memRepo struct {
	rows map[string]domain.Report
}

func newMemRepo() *memRepo {
	return &memRepo{rows: make(map[string]domain.Report)}
}

func (m *memRepo) Upsert(_ context.Context, rec domain.Report) error {
	key := rec.Rule + domain.KeySep + rec.Target
	if old, ok := m.rows[key]; ok {
		rec.CreatedAt = old.CreatedAt // preserved by the row's first insert
	}
	m.rows[key] = rec
	return nil
}

func (m *memRepo) List(_ context.Context, q report.Query) ([]domain.Report, error) {
	var rows []domain.Report
	for _, rec := range m.rows {
		if q.Rule != "" && rec.Rule != q.Rule {
			continue
		}
		if q.Target != "" && rec.Target != q.Target {
			continue
		}
		if !rec.ExpiresAt.After(q.Now) {
			continue
		}
		rows = append(rows, rec)
	}
	slices.SortFunc(rows, func(a, b domain.Report) int {
		return b.CreatedAt.Compare(a.CreatedAt)
	})
	return rows, nil
}

func (m *memRepo) Delete(_ context.Context, q report.Query) (int, error) {
	if q.Rule == "" && q.Target == "" {
		return 0, report.ErrUnfiltered
	}
	n := 0
	for key, rec := range m.rows {
		if q.Matches(rec.Rule, rec.Target) {
			delete(m.rows, key)
			n++
		}
	}
	return n, nil
}

func (m *memRepo) DeleteExpired(_ context.Context, now time.Time) (int, error) {
	n := 0
	for key, rec := range m.rows {
		if !rec.ExpiresAt.After(now) {
			delete(m.rows, key)
			n++
		}
	}
	return n, nil
}

func (m *memRepo) Close() error { return nil }

// writeLedger counts report writes per (rule, Target) per report lifetime;
// newLifetime rolls the ledger when the harness re-arms.
type writeLedger struct {
	reportStore
	mu    sync.Mutex
	n     int
	life  int
	cells map[ledgerCell]int
}

// ledgerCell is one (rule, Target) cell within a report lifetime; the
// contract is at most one write per cell.
type ledgerCell struct {
	rule   string
	target string
	life   int
}

func (l *writeLedger) Upsert(ctx context.Context, rec domain.Report) error {
	l.mu.Lock()
	if l.cells == nil {
		l.cells = make(map[ledgerCell]int)
	}
	l.n++
	l.cells[ledgerCell{rule: rec.Rule, target: rec.Target, life: l.life}]++
	l.mu.Unlock()
	return l.reportStore.Upsert(ctx, rec)
}

// newLifetime rolls the ledger to the next report lifetime.
func (l *writeLedger) newLifetime() {
	l.mu.Lock()
	l.life++
	l.mu.Unlock()
}

func (l *writeLedger) total() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.n
}

func (l *writeLedger) counts() map[ledgerCell]int {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[ledgerCell]int, len(l.cells))
	for cell, n := range l.cells {
		out[cell] = n
	}
	return out
}

// countingSink counts report actions run; the action runs on every Trigger
// even while the write is suppressed, so this is the episode cadence.
type countingSink struct {
	reports  *report.Service
	triggers int
}

func (s *countingSink) Trigger(ctx context.Context, rec domain.Report) error {
	s.triggers++
	return s.reports.Trigger(ctx, rec)
}

// rearmKind selects how a report lifetime ends: never, delete, or expiry.
type rearmKind int

const (
	rearmNone rearmKind = iota
	rearmDelete
	rearmExpiry
)

// benchEpisode is one report-lifetime scenario; name is the benchmark
// sub-name.
type benchEpisode struct {
	name string
	kind rearmKind
}

// benchEpisodes is the episode scenario vocabulary: first-trigger and re-arm
// after delete/expiry.
var benchEpisodes = []benchEpisode{
	{name: "first-trigger", kind: rearmNone},
	{name: "rearm-delete", kind: rearmDelete},
	{name: "rearm-expiry", kind: rearmExpiry},
}

// rearm performs the scenario's re-arm step at a report-lifetime boundary,
// returning whether the lifetime rolled (so ledger and oracle advance together).
func (ep benchEpisode) rearm(tb testing.TB, reports *report.Service, ruleIDs []string, clock *testClock) bool {
	tb.Helper()
	switch ep.kind {
	case rearmNone:
		return false
	case rearmDelete:
		for _, id := range ruleIDs {
			if _, err := reports.Delete(context.Background(), report.Query{Rule: id, Now: clock.Now()}); err != nil {
				tb.Fatalf("re-arm delete %q: %v", id, err)
			}
		}
	case rearmExpiry:
		clock.Advance(benchRearmStep)
	}
	return true
}

// benchEpisodeRun is one scenario run's wiring: evaluation service, report
// service behind a write ledger, and the wall clock the re-arm step moves.
type benchEpisodeRun struct {
	svc     *evaluation.Service
	sink    *countingSink
	reports *report.Service
	ledger  *writeLedger
	clock   *testClock
	rules   []domain.Chain
}

func newBenchEpisodeRun(tb testing.TB, rules string, repo reportStore) *benchEpisodeRun {
	tb.Helper()
	chains := benchRules(tb, rules)
	clock := newTestClock(bench.Epoch)
	ledger := &writeLedger{reportStore: repo}
	reports := report.NewService(ledger)
	sink := &countingSink{reports: reports}
	svc := evaluation.NewService(chains, memory.New(65536, clock.Now, zerolog.Nop()), sink, clock.Now, nil)
	return &benchEpisodeRun{svc: svc, sink: sink, reports: reports, ledger: ledger, clock: clock, rules: chains}
}

// rearm runs the scenario's re-arm step, rolling the ledger when the
// lifetime rolls.
func (r *benchEpisodeRun) rearm(tb testing.TB, ep benchEpisode) bool {
	tb.Helper()
	if ep.rearm(tb, r.reports, ruleIDs(r.rules), r.clock) {
		r.ledger.newLifetime()
		return true
	}
	return false
}

// ruleIDs lists the fixture's rule IDs in load order.
func ruleIDs(chains []domain.Chain) []string {
	var ids []string
	for _, c := range chains {
		for _, r := range c.Rules {
			ids = append(ids, r.ID)
		}
	}
	return ids
}

// episodeOracle is the episode contract simulated beside the run, so its
// expectations can disagree with the code under test.
type episodeOracle struct {
	chains   []domain.Chain
	life     int
	states   map[oracleKey]*oracleState
	triggers int
	writes   map[ledgerCell]int
}

type oracleKey struct {
	rule   string
	target string
}

type oracleState struct {
	value     int
	lastTouch time.Time
	touched   bool
	written   bool
}

func newEpisodeOracle(chains []domain.Chain) *episodeOracle {
	return &episodeOracle{
		chains: chains,
		states: make(map[oracleKey]*oracleState),
		writes: make(map[ledgerCell]int),
	}
}

// event feeds one fixture event at the given wall time to every rule.
func (o *episodeOracle) event(ev domain.Event, wall time.Time) {
	for ci := range o.chains {
		for ri := range o.chains[ci].Rules {
			rule := &o.chains[ci].Rules[ri]
			key := oracleKey{rule: rule.ID, target: rule.Tracker.TargetString(ev.RemoteAddr)}
			st := o.states[key]
			if st == nil {
				st = &oracleState{}
				o.states[key] = st
			}
			if st.touched && !wall.Before(st.lastTouch.Add(domain.DefaultTTL)) {
				st.value = 0 // the tracker record expired untouched
			}
			st.touched, st.lastTouch = true, wall
			st.value++
			if st.value > benchEpisodeVolume {
				st.value = 0 // the Trigger empties the tracker
				o.triggers++
				cell := ledgerCell{rule: key.rule, target: key.target, life: o.life}
				if !st.written {
					st.written = true
					o.writes[cell] = 1
				}
			}
		}
	}
}

// boundary rolls the report lifetime: the next Trigger for any (rule, Target)
// writes again.
func (o *episodeOracle) boundary() {
	o.life++
	for _, st := range o.states {
		st.written = false
	}
}

// assertWrites checks the ledger against the oracle's write cells: exactly
// one write per (rule, Target) per report lifetime that Triggered.
func assertWrites(t *testing.T, ledger *writeLedger, want map[ledgerCell]int) {
	t.Helper()
	got := ledger.counts()
	for cell, n := range got {
		if n != 1 {
			t.Errorf("write cell %+v = %d, want 1 (one write per (rule, Target) per report lifetime)", cell, n)
		}
		if _, ok := want[cell]; !ok {
			t.Errorf("unexpected write %+v (a suppressed Trigger must not write)", cell)
		}
	}
	for cell := range want {
		if got[cell] != 1 {
			t.Errorf("write cell %+v = %d, want 1 (the lifetime's first Trigger must write)", cell, got[cell])
		}
	}
}

// benchRules loads a fixture's chains or fails tb.
func benchRules(tb testing.TB, rules string) []domain.Chain {
	tb.Helper()
	chains, err := ParseRules([]byte(rules))
	if err != nil {
		tb.Fatalf("ParseRules error: %v", err)
	}
	return chains
}

// TestEvaluateBenchScenarios pins the episode fixtures: one write per
// (rule, Target) per report lifetime, and match-never does nothing.
func TestEvaluateBenchScenarios(t *testing.T) {
	corpus := bench.NewCorpus(bench.Seed, bench.ShapeFull, bench.DistZipf, 1024)
	const passes = 10

	tests := []struct {
		name  string
		rules string
		ep    *benchEpisode // nil = match-never (no Triggers, no writes)
	}{
		{"first-trigger", benchEpisodeChains, &benchEpisodes[0]},
		{"rearm-delete", benchEpisodeChains, &benchEpisodes[1]},
		{"rearm-expiry", benchEpisodeChains, &benchEpisodes[2]},
		{"match-never", benchMatchNeverChains, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run := newBenchEpisodeRun(t, tt.rules, newMemRepo())
			oracle := newEpisodeOracle(run.rules)
			ctx := context.Background()
			for pass := range passes {
				for i := range corpus.Len() {
					ev := benchEvent(corpus, pass*corpus.Len()+i)
					oracle.event(ev, run.clock.Now())
					if err := run.svc.Evaluate(ctx, &ev); err != nil {
						t.Fatalf("Evaluate error: %v", err)
					}
				}
				if tt.ep != nil && run.rearm(t, *tt.ep) {
					oracle.boundary()
				}
			}

			if tt.ep == nil {
				if run.sink.triggers != 0 {
					t.Errorf("triggers = %d, want 0 (match-never never overflows)", run.sink.triggers)
				}
				if n := run.ledger.total(); n != 0 {
					t.Errorf("report writes = %d, want 0 (match-never never writes)", n)
				}
				return
			}
			// The report action runs on every episode; the write lands per
			// the contract.
			if run.sink.triggers != oracle.triggers {
				t.Errorf("triggers = %d, want %d (one Trigger per %d-event episode)",
					run.sink.triggers, oracle.triggers, benchEpisodeLen)
			}
			assertWrites(t, run.ledger, oracle.writes)
		})
	}
}

// benchEvaluate runs the shared evaluate loop; one op is one pre-parsed
// corpus event (one log line).
func benchEvaluate(b *testing.B, run *benchEpisodeRun, ep *benchEpisode) {
	b.Helper()
	corpus := bench.NewCorpus(bench.Seed, bench.ShapeFull, bench.DistZipf, 1024)
	ctx := context.Background()
	var lines int
	for b.Loop() {
		if lines > 0 && lines%corpus.Len() == 0 && ep != nil {
			run.rearm(b, *ep)
		}
		ev := benchEvent(corpus, lines)
		if err := run.svc.Evaluate(ctx, &ev); err != nil {
			b.Fatalf("Evaluate: %v", err)
		}
		lines++
	}
	if lines > 0 {
		b.ReportMetric(float64(run.ledger.total())/float64(lines), "writes/op")
	}
	bench.ReportLinesPerSec(b, lines)
}

// benchEpisodeCases is the evaluate benchmarks' scenario matrix; names are
// the benchmark sub-names.
var benchEpisodeCases = []struct {
	name  string
	rules string
	ep    *benchEpisode
}{
	{"first-trigger", benchEpisodeChains, &benchEpisodes[0]},
	{"rearm-delete", benchEpisodeChains, &benchEpisodes[1]},
	{"rearm-expiry", benchEpisodeChains, &benchEpisodes[2]},
	{"match-never", benchMatchNeverChains, nil},
}

// BenchmarkEvaluateMemory is BenchmarkEvaluate with the real memory tracker
// store and the production report service over the in-memory report store.
func BenchmarkEvaluateMemory(b *testing.B) {
	for _, tc := range benchEpisodeCases {
		b.Run(tc.name, func(b *testing.B) {
			run := newBenchEpisodeRun(b, tc.rules, newMemRepo())
			benchEvaluate(b, run, tc.ep)
		})
	}
}

// BenchmarkEvaluateSQLite is BenchmarkEvaluate with the sqlite report store,
// exposing the write-path cost the in-memory variant excludes.
func BenchmarkEvaluateSQLite(b *testing.B) {
	for _, tc := range benchEpisodeCases {
		b.Run(tc.name, func(b *testing.B) {
			repo, err := sqlite.Open(":memory:")
			if err != nil {
				b.Fatalf("sqlite.Open: %v", err)
			}
			b.Cleanup(func() { repo.Close() })
			run := newBenchEpisodeRun(b, tc.rules, repo)
			benchEvaluate(b, run, tc.ep)
		})
	}
}
