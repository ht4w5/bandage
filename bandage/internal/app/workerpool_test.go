package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HT4w5/webmedkit/bandage/internal/domain"
	"github.com/HT4w5/webmedkit/bandage/internal/domain/report"
	"github.com/HT4w5/webmedkit/bandage/internal/infra/persistence/sqlite"
	"github.com/HT4w5/webmedkit/internal/identity"
)

// Worker pool and daemon-lifetime context at the daemon seam: exact line
// accounting under -race, workers:1 determinism, bounded shutdown drain.

const poolRules = `
version: 0
chains:
  - name: abuse
    rules:
      - id: egress
        tracker: {track: bandwidth, leak: 0, volume: 1000}
        actions: [{report: {reason: egress-overflow, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
`

// TestNewRejectsNonPositiveWorkerCount: New rejects a worker count below 1
// before opening any resource.
func TestNewRejectsNonPositiveWorkerCount(t *testing.T) {
	chains, err := ParseRules([]byte(poolRules))
	if err != nil {
		t.Fatalf("ParseRules error: %v", err)
	}
	cfg := Config{
		Ingest: Ingest{
			Driver: "syslog",
			Parser: "nginx",
			Syslog: Syslog{Network: "unixgram", Listen: filepath.Join(t.TempDir(), "log.sock")},
		},
		DB:       DB{Driver: "sqlite", SQLite: SQLite{Path: ":memory:"}},
		Cache:    Cache{MaxEntries: 65536},
		Pipeline: Pipeline{Workers: 0},
		API:      API{Listen: "127.0.0.1:0"},
	}
	if _, err := New(cfg, chains, identity.For("bandage")); err == nil {
		t.Fatal("New(workers 0) succeeded, want an error")
	} else if !strings.Contains(err.Error(), "pipeline.workers") {
		t.Errorf("error %q does not name pipeline.workers", err)
	}
}

// TestWorkerPoolCountsEveryLineOnce: received equals parsed plus dropped,
// with no loss or duplication under -race.
func TestWorkerPoolCountsEveryLineOnce(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	d := startTestDaemonCfg(t, clock, "unixgram", ":memory:", poolRules, func(c *Config) {
		c.Pipeline = Pipeline{Workers: 8}
	})

	for i := range 8 {
		client := fmt.Sprintf("203.0.113.%d", i)
		d.send(nginxLine(eventTime1, client, "GET", "/small", 200, 10))
	}
	d.send("this is not json")
	d.send("this is also not json")
	d.send(`{"time":"1734345934","client":"203.0.113.7","method":"GET","url":"/","status":99,"sent":0}`)
	d.send(`{"time":"1734345934","client":"203.0.113.7","method":"GET","url":"/","status":200,"sent":-1}`)
	d.waitProcessed(t, 12)

	stats := d.counters()
	if stats.Received != 12 || stats.Parsed != 8 || stats.Dropped != 4 {
		t.Errorf("stats = %+v, want {Received:12 Parsed:8 Dropped:4}", stats)
	}
	if stats.Received != stats.Parsed+stats.Dropped {
		t.Errorf("received %d != parsed %d + dropped %d (every line counted exactly once)",
			stats.Received, stats.Parsed, stats.Dropped)
	}
}

// TestWorkerPoolConcurrentEventsOneTarget: concurrent events for one Target
// never corrupt tracker state.
func TestWorkerPoolConcurrentEventsOneTarget(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	d := startTestDaemonCfg(t, clock, "unixgram", ":memory:", poolRules, func(c *Config) {
		c.Pipeline = Pipeline{Workers: 4}
	})

	// Each event overflows on its own (2000 > 1000), so triggers race for
	// the same (rule, Target) report; timestamps alternate out of order.
	const events = 24
	times := []string{eventTime1, "1734346934.123"}
	for i := range events {
		d.send(nginxLine(times[i%2], "203.0.113.7", "GET", "/big", 200, 2000))
	}
	d.waitProcessed(t, events)

	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want exactly one (one live report per (rule, Target))", doc.Reports)
	}

	// After Delete the next events accumulate on the emptied bucket:
	// 5x100 + 600 = 1100 overflows on the last and reads the exact total.
	if _, n := d.del(t, url.Values{"rule": {"egress"}}); n != 1 {
		t.Fatalf("delete count = %d, want 1", n)
	}
	for range 5 {
		d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/small", 200, 100))
	}
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/small", 200, 600))
	d.waitProcessed(t, events+6)

	doc = d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want exactly one", doc.Reports)
	}
	if v := doc.Reports[0].Tracker.Value; v != 1100 {
		t.Errorf("tracker value = %v, want 1100 (atomic accumulation: every event counted once)", v)
	}
}

// TestWorkersOneProcessesInArrivalOrder: workers:1 processes events strictly
// in arrival order; the reading and sample pin that order exactly.
func TestWorkersOneProcessesInArrivalOrder(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: abuse
    rules:
      - id: egress
        tracker: {track: bandwidth, leak: 1, volume: 1500}
        actions: [{report: {reason: egress-overflow, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
`
	d := startTestDaemonCfg(t, clock, "unixgram", ":memory:", rules, func(c *Config) {
		c.Pipeline = Pipeline{Workers: 1}
	})

	// Arrival order t1 < t2 < t3 accumulates 1000 -> 2000-100 = 1900,
	// which overflows 1500 and empties the bucket; t3 stays quiet.
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 1000))
	d.send(nginxLine("1734346034.123", "203.0.113.7", "GET", "/big", 200, 1000))
	d.send(nginxLine("1734346134.123", "203.0.113.7", "GET", "/big", 200, 1000))
	d.waitProcessed(t, 3)

	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want exactly one", doc.Reports)
	}
	r := doc.Reports[0]
	if r.Tracker.Value != 1900 {
		t.Errorf("tracker value = %v, want 1900 (strict arrival order)", r.Tracker.Value)
	}
	wantTime := time.Unix(1734345934+100, 123000000).UTC().Format(time.RFC3339)
	if r.Sample.Time != wantTime {
		t.Errorf("sample time = %q, want %q (the triggering event's)", r.Sample.Time, wantTime)
	}
}

// storeGate wedges store calls on demand: every gated call signals enter()
// and blocks until release(), however long that takes.
type storeGate struct {
	entered chan struct{}
	gate    chan struct{}
	once    sync.Once
}

// newStoreGate returns a fresh gate with its own entry channel.
func newStoreGate() storeGate {
	return storeGate{entered: make(chan struct{}, 32), gate: make(chan struct{})}
}

// enter signals the wedge and blocks until release.
func (g *storeGate) enter() {
	g.entered <- struct{}{}
	<-g.gate
}

// release opens the gate once: every wedged call resumes and later calls pass
// straight through.
func (g *storeGate) release() {
	g.once.Do(func() { close(g.gate) })
}

// waitEntered blocks until n gated store calls are in flight (guard timeout
// only, never a sleep).
func waitEntered(t *testing.T, g *storeGate, n int) {
	t.Helper()
	for i := range n {
		select {
		case <-g.entered:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of %d store calls entered the wedge", i, n)
		}
	}
}

// blockingStore wedges the report write path on demand (storeGate).
// failErr, when set, fails exactly the first write that passes the gate.
type blockingStore struct {
	*sqlite.ReportRepository
	storeGate
	failErr  error
	failOnce sync.Once
}

func (b *blockingStore) Upsert(ctx context.Context, rec domain.Report) error {
	b.enter()
	var err error
	b.failOnce.Do(func() {
		if b.failErr != nil {
			err = b.failErr
		}
	})
	if err != nil {
		return err
	}
	return b.ReportRepository.Upsert(ctx, rec)
}

func (b *blockingStore) release() {
	b.once.Do(func() { close(b.gate) })
}

// wedgeDaemon is the daemon with a wedged report store and a real ingest
// listener.
type wedgeDaemon struct {
	*Daemon
	send   func(line string)
	store  *blockingStore
	dbPath string
}

func startWedgeDaemon(t *testing.T, clock *testClock, workers int) *wedgeDaemon {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "reports.db")
	inner, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	store := &blockingStore{
		ReportRepository: inner,
		storeGate:        newStoreGate(),
	}
	t.Cleanup(store.release)

	cfg := Config{
		Ingest: Ingest{
			Driver: "syslog",
			Parser: "nginx",
			Syslog: Syslog{Network: "unixgram", Listen: filepath.Join(t.TempDir(), "log.sock")},
		},
		DB:       DB{Driver: "sqlite", SQLite: SQLite{Path: dbPath}},
		Cache:    Cache{MaxEntries: 65536},
		Pipeline: Pipeline{Workers: workers},
		API:      API{Listen: "127.0.0.1:0"},
	}
	chains, err := ParseRules([]byte(poolRules))
	if err != nil {
		t.Fatalf("ParseRules error: %v", err)
	}
	d, err := New(cfg, chains, identity.For("bandage"), WithClock(clock.Now), withStore(store))
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	if err := d.Start(context.Background()); err != nil {
		t.Fatalf("Start error: %v", err)
	}

	conn, err := net.Dial("unixgram", cfg.Ingest.Syslog.Listen)
	if err != nil {
		t.Fatalf("dial unixgram: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return &wedgeDaemon{
		Daemon: d,
		send:   func(line string) { conn.Write([]byte(line)) },
		store:  store,
		dbPath: dbPath,
	}
}

// waitDone returns the error from a shutdown goroutine (guard timeout only,
// never a sleep).
func waitDone(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not complete within the guard deadline")
		return nil
	}
}

// TestShutdownCancelsLifetimeContext: Shutdown cancels the daemon-lifetime
// context once the drain is done, so no live context outlives a clean stop.
func TestShutdownCancelsLifetimeContext(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	d := startTestDaemon(t, clock, "unixgram", ":memory:", poolRules)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown error: %v", err)
	}
	select {
	case <-d.ctx.Done():
	default:
		t.Error("daemon lifetime context still live after clean Shutdown (leaked)")
	}
}

// TestShutdownDrainsInFlightReportUpserts: the shutdown drain contract --
// in-flight upserts complete before resources close and their reports survive.
func TestShutdownDrainsInFlightReportUpserts(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	w := startWedgeDaemon(t, clock, 2)

	// Two report-triggering events whose upserts wedge in the store.
	w.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 2000))
	w.send(nginxLine(eventTime1, "203.0.113.8", "GET", "/big", 200, 2000))
	waitEntered(t, &w.store.storeGate, 2)

	shutdownErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownErr <- w.Shutdown(ctx)
	}()
	w.store.release() // the in-flight upserts resume and finish during the drain
	if err := waitDone(t, shutdownErr); err != nil {
		t.Fatalf("Shutdown error: %v", err)
	}

	repo, err := sqlite.Open(w.dbPath)
	if err != nil {
		t.Fatalf("sqlite.Open after shutdown: %v", err)
	}
	defer repo.Close()
	reports, err := repo.List(context.Background(), report.Query{Now: clock.Now()})
	if err != nil {
		t.Fatalf("List after shutdown: %v", err)
	}
	if len(reports) != 2 {
		t.Errorf("reports after shutdown = %+v, want both in-flight upserts to have completed", reports)
	}
}

// TestShutdownIsBoundedWhenStoreCallHangs: Shutdown is bounded by the
// caller's deadline even when a store call never returns.
func TestShutdownIsBoundedWhenStoreCallHangs(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	w := startWedgeDaemon(t, clock, 2)

	w.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 2000))
	waitEntered(t, &w.store.storeGate, 1) // the store call is wedged in flight

	ctx, cancel := context.WithCancel(context.Background())
	shutdownErr := make(chan error, 1)
	go func() { shutdownErr <- w.Shutdown(ctx) }()
	cancel() // the caller's deadline expires with the call still hung

	if err := waitDone(t, shutdownErr); !errors.Is(err, context.Canceled) {
		t.Errorf("Shutdown error = %v, want the caller's deadline error", err)
	}
	// The gate is released only by the test cleanup, after Shutdown returned.
}
