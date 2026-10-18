package app

import (
	"context"
	"slices"
	"sync"
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
// tracker store and the production report service (report.Service),
// first over an in-memory report store (the production path minus
// sqlite) and then over the sqlite store to expose the write-path cost
// (H4, H6). The stub-port variant lives beside the domain code in
// domain/evaluation; the domain lint keeps these adapters out of that
// package.
//
// The scenarios are the v0-hot-path episode re-modeling (spec stories
// 30–31): the retired overflow-every-event trick — a report write per
// event — no longer models the world under the Trigger semantics (a
// Trigger empties the tracker and a live report suppresses its write),
// so the write scenarios model report episodes instead. The report
// lifetime is the episode: first-trigger measures the world where each
// (rule, Target) writes at its first Trigger and every later Trigger in
// the same lifetime is suppressed, while rearm-delete and rearm-expiry
// measure the re-arm episodes where the operator's delete (spec story
// 9) or report expiry (spec story 10) lets the next Trigger write over
// the old row again. Across all of them one write lands per (rule,
// Target) per report lifetime — the write-rate evidence is in the
// baseline itself as writes/op.

const (
	// benchEpisodeVolume is the episode fixture's tracker volume: with
	// the rate tracker's +1 per event and leak 0, a Target accumulates
	// benchEpisodeLen events per episode and every benchEpisodeLen-th
	// event Triggers (Overflow is strictly above volume). The Trigger
	// empties the tracker (GLOSSARY Trigger), so episodes recur at that
	// cadence however long the run is. Volume is deliberately above the
	// per-event increment: the retired overflow-every-event trick is
	// not the episode model.
	benchEpisodeVolume = 3.0
	benchEpisodeLen    = 4

	// benchRearmStep is the wall time one corpus pass advances in
	// rearm-expiry. The fixture's 30m report TTL sits below it (a
	// report is expired at the next lifetime boundary and the Trigger
	// writes over its row) while the tracker's cache TTL
	// (bandage.DefaultTTL, 1h, from leak 0) sits above it (a tracker
	// record touched during the pass survives the step and its
	// accumulation episode continues).
	benchRearmStep = 45 * time.Minute
)

// benchEpisodeChains is the episode fixture: the four single-rule
// chains of the retired match-every fixture (identical filter and
// tracker work per event) with an accumulation episode of
// benchEpisodeLen events per Target instead of the overflow-every-event
// trick. The 30m report TTL only matters for rearm-expiry (see
// benchRearmStep); under a frozen clock the report is alive for the
// whole run.
const benchEpisodeChains = `
version: 0
chains:
  - name: download-abuse
    rules:
      - id: egress-flood
        filter: 'src 198.51.100.0/24 or src 203.0.113.0/24'
        tracker: {track: rate, leak: 0, volume: 3}
        actions: [{report: {reason: egress-overflow, ttl: 30m}}]
  - name: request-flood
    rules:
      - id: request-flood
        filter: 'method GET or method HEAD or method POST'
        tracker: {track: rate, leak: 0, volume: 3}
        actions: [{report: {reason: request-flood, ttl: 30m}}]
  - name: scanning
    rules:
      - id: probe-flood
        filter: 'path prefix "/files/" or path prefix "/releases/"'
        tracker: {track: rate, leak: 0, volume: 3}
        actions: [{report: {reason: probe-scan, ttl: 30m}}]
  - name: error-scanning
    rules:
      - id: error-flood
        filter: 'status class 2 or status class 3 or status class 4 or status class 5'
        tracker: {track: rate, leak: 0, volume: 3}
        actions: [{report: {reason: error-probe, ttl: 30m}}]
`

// benchMatchNeverChains decays at 10/s (rate) and 1GB/s (bandwidth,
// against increments below 8MB) and, at benchEvent's one-second event
// spacing, never overflows, so no rule ever Matches and neither the
// Trigger path nor the write path runs. It is the fast-path floor the
// episode scenarios are read against.
const benchMatchNeverChains = `
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

// benchClock is the fixture event-time origin the corpus's timestamps
// march from (internal/bench.Epoch). Report timestamps and cache expiry
// run on the scenario's own wall clock (benchEpisodeRun.clock), which
// the re-arm steps move.
func benchClock() time.Time { return bench.Epoch }

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

// memRepo is the in-memory report store: the production report
// lifecycle (report.Service over a report.Repository) minus the sqlite
// write path — the rows a map holds. Serial use only: the evaluate
// benchmarks and their fixture test drive one event at a time.
type memRepo struct {
	rows map[string]bandage.Report
}

func newMemRepo() *memRepo {
	return &memRepo{rows: make(map[string]bandage.Report)}
}

func (m *memRepo) Upsert(_ context.Context, rec bandage.Report) error {
	key := rec.Rule + bandage.KeySep + rec.Target
	if old, ok := m.rows[key]; ok {
		rec.CreatedAt = old.CreatedAt // preserved by the row's first insert
	}
	m.rows[key] = rec
	return nil
}

func (m *memRepo) List(_ context.Context, q report.Query) ([]bandage.Report, error) {
	var rows []bandage.Report
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
	slices.SortFunc(rows, func(a, b bandage.Report) int {
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

// writeLedger counts report writes at the store seam — the write is
// the observable unit of the episode contract ("one write per (rule,
// Target) per report lifetime"): every Upsert is recorded per
// (rule, Target) per report lifetime, and newLifetime rolls the ledger
// when the harness re-arms, so the scenario pins can read per-lifetime
// cells. total feeds the benchmarks' writes/op metric — the write-rate
// evidence lives in the baseline itself.
type writeLedger struct {
	reportStore
	mu    sync.Mutex
	n     int
	life  int
	cells map[ledgerCell]int
}

// ledgerCell is one report-lifetime cell: (rule, Target) within a
// lifetime. The contract is at most one write per cell.
type ledgerCell struct {
	rule   string
	target string
	life   int
}

func (l *writeLedger) Upsert(ctx context.Context, rec bandage.Report) error {
	l.mu.Lock()
	if l.cells == nil {
		l.cells = make(map[ledgerCell]int)
	}
	l.n++
	l.cells[ledgerCell{rule: rec.Rule, target: rec.Target, life: l.life}]++
	l.mu.Unlock()
	return l.reportStore.Upsert(ctx, rec)
}

// newLifetime rolls the ledger to the next report lifetime (one per
// re-arm boundary).
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

// countingSink counts report actions run — Trigger calls at the
// evaluation seam. The report action runs on every Trigger even while
// its write is suppressed (spec story 3), so this count is the episode
// cadence, not the write count (that lives on the writeLedger).
type countingSink struct {
	reports  *report.Service
	triggers int
}

func (s *countingSink) Trigger(ctx context.Context, rec bandage.Report) error {
	s.triggers++
	return s.reports.Trigger(ctx, rec)
}

// rearmKind selects how a report lifetime ends in the episode
// scenarios: not at all (first-trigger's lifetime is the whole run),
// the operator's delete, or report expiry.
type rearmKind int

const (
	rearmNone rearmKind = iota
	rearmDelete
	rearmExpiry
)

// benchEpisode is one report-lifetime scenario. The benchmark
// sub-names are the scenario names; the scenario contract is pinned by
// TestEvaluateBenchScenarios.
type benchEpisode struct {
	name string
	kind rearmKind
}

// benchEpisodes is the episode scenario vocabulary (spec stories 9–10,
// 30): first-Trigger vs re-arm after delete/expiry.
var benchEpisodes = []benchEpisode{
	{name: "first-trigger", kind: rearmNone},
	{name: "rearm-delete", kind: rearmDelete},
	{name: "rearm-expiry", kind: rearmExpiry},
}

// rearm performs the scenario's re-arm step at a report-lifetime
// boundary (one corpus pass in the pin and in the benchmark). A delete
// (rearm-delete) removes the fixture's reports like the API's
// delete-by-filter (spec story 9); expiry (rearm-expiry) advances the
// wall clock past the report TTL so the next Trigger finds the report
// expired and writes over its row — the write re-arms before any
// sweeper runs (spec story 10). first-trigger never re-arms. It
// reports whether the report lifetime rolled, so the ledger and the
// oracle advance together.
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

// benchEpisodeRun is one scenario run's wiring: the evaluation service
// over a real memory tracker store and the production report service
// over the run's report store behind a write ledger, plus the wall
// clock the re-arm step moves. The Memory and SQLite benchmark
// variants differ only in the report store.
type benchEpisodeRun struct {
	svc     *evaluation.Service
	sink    *countingSink
	reports *report.Service
	ledger  *writeLedger
	clock   *testClock
	rules   []bandage.Chain
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

// rearm runs the scenario's re-arm step at a report-lifetime boundary,
// rolls the ledger when the lifetime rolled, and reports whether it
// did.
func (r *benchEpisodeRun) rearm(tb testing.TB, ep benchEpisode) bool {
	tb.Helper()
	if ep.rearm(tb, r.reports, ruleIDs(r.rules), r.clock) {
		r.ledger.newLifetime()
		return true
	}
	return false
}

// ruleIDs lists the fixture's rule IDs in load order (the re-arm
// delete's filters).
func ruleIDs(chains []bandage.Chain) []string {
	var ids []string
	for _, c := range chains {
		for _, r := range c.Rules {
			ids = append(ids, r.ID)
		}
	}
	return ids
}

// episodeOracle is the episode contract, simulated beside the run so
// its expectations can disagree with the code under test (the suite's
// fixture-derived oracle convention: expectations come from the
// documented semantics, never from the implementation). It encodes the
// episode fixture only (rate, leak 0, volume benchEpisodeVolume, every
// rule matching): a Target accumulates one per event and Trigger at
// every benchEpisodeLen-th event since the last Trigger (the Trigger
// empties the tracker — GLOSSARY Trigger); a tracker record untouched
// for the cache TTL (bandage.DefaultTTL of wall time) expires and its
// next event starts from zero; and a Trigger writes once per (rule,
// Target) per report lifetime — the lifetime's first Trigger writes,
// later ones are suppressed (spec stories 2 and 9–10).
type episodeOracle struct {
	chains   []bandage.Chain
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

func newEpisodeOracle(chains []bandage.Chain) *episodeOracle {
	return &episodeOracle{
		chains: chains,
		states: make(map[oracleKey]*oracleState),
		writes: make(map[ledgerCell]int),
	}
}

// event feeds one fixture event at the given wall time to every rule.
func (o *episodeOracle) event(ev bandage.Event, wall time.Time) {
	for ci := range o.chains {
		for ri := range o.chains[ci].Rules {
			rule := &o.chains[ci].Rules[ri]
			key := oracleKey{rule: rule.ID, target: rule.Tracker.TargetString(ev.RemoteAddr)}
			st := o.states[key]
			if st == nil {
				st = &oracleState{}
				o.states[key] = st
			}
			if st.touched && !wall.Before(st.lastTouch.Add(bandage.DefaultTTL)) {
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

// boundary rolls the report lifetime (the re-arm step's effect): the
// next Trigger for any (rule, Target) writes again.
func (o *episodeOracle) boundary() {
	o.life++
	for _, st := range o.states {
		st.written = false
	}
}

// assertWrites checks the ledger against the oracle's write cells: the
// episode contract is exactly one write per (rule, Target) per report
// lifetime for every lifetime that Triggered and none for any other
// cell.
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
func benchRules(tb testing.TB, rules string) []bandage.Chain {
	tb.Helper()
	chains, err := ParseRules([]byte(rules))
	if err != nil {
		tb.Fatalf("ParseRules error: %v", err)
	}
	return chains
}

// TestEvaluateBenchScenarios verifies the episode fixtures measure the
// scenario they name (the write-path measurements rest on it): over
// several corpus passes with the scenario's re-arm cadence, every
// episode Trigger runs the report action but exactly one write lands
// per (rule, Target) per report lifetime — the lifetime's first Trigger
// writes and later Triggers in it are suppressed — while match-never
// does nothing at all. Expected Triggers and write cells come from the
// fixture events alone (episodeOracle), so they can disagree with the
// pipeline.
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
			// The report action runs on every episode (spec story 3),
			// and one write per (rule, Target) per report lifetime
			// lands exactly where the contract says (spec story 2).
			if run.sink.triggers != oracle.triggers {
				t.Errorf("triggers = %d, want %d (one Trigger per %d-event episode)",
					run.sink.triggers, oracle.triggers, benchEpisodeLen)
			}
			assertWrites(t, run.ledger, oracle.writes)
		})
	}
}

// benchEvaluate runs the shared evaluate loop against a prepared run.
// One op is one pre-parsed corpus event, i.e. one log line; ep's re-arm
// step runs at every corpus-pass boundary — the episode scenario's
// report-lifetime boundary (nil for match-never).
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

// benchEpisodeCases are the evaluate benchmarks' scenario matrix: the
// episode scenarios (first Trigger vs re-arm after delete/expiry) and
// the match-never floor. The names are stable: they are the benchmark
// sub-names.
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

// BenchmarkEvaluateMemory is BenchmarkEvaluate with the real memory
// tracker store and the production report service over the in-memory
// report store: the production path minus the sqlite write (H4, H6).
func BenchmarkEvaluateMemory(b *testing.B) {
	for _, tc := range benchEpisodeCases {
		b.Run(tc.name, func(b *testing.B) {
			run := newBenchEpisodeRun(b, tc.rules, newMemRepo())
			benchEvaluate(b, run, tc.ep)
		})
	}
}

// BenchmarkEvaluateSQLite is BenchmarkEvaluate with the sqlite report
// store (:memory: database): the write-path cost the in-memory variant
// excludes (H4).
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
