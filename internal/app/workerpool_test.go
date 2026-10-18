package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	bandage "github.com/HT4w5/bandage/internal/domain"
	"github.com/HT4w5/bandage/internal/domain/report"
	"github.com/HT4w5/bandage/internal/infra/persistence/sqlite"
)

// The worker pool and daemon-lifetime context at the assembled daemon
// seam (spec: Testing Decisions — several workers under -race with
// every line accounted for, a workers:1 determinism case, and bounded
// shutdown where in-flight reports survive). Concurrency is proven by
// the race detector and exact accounting, never by timing.

const poolRules = `
version: 0
chains:
  - name: abuse
    rules:
      - id: egress
        tracker: {track: bandwidth, leak: 0, volume: 1000}
        actions: [{report: {reason: egress-overflow, ttl: 1h}}]
`

// New rejects a worker count below 1 before opening any resource: a
// broken config never reaches the running daemon (spec story 16).
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
	if _, err := New(cfg, chains); err == nil {
		t.Fatal("New(workers 0) succeeded, want an error")
	} else if !strings.Contains(err.Error(), "pipeline.workers") {
		t.Errorf("error %q does not name pipeline.workers", err)
	}
}

// With several workers every received line is counted exactly once:
// received equals parsed plus dropped, with no loss or duplication
// under -race (spec story 17).
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

	stats := d.stats()
	if stats.Received != 12 || stats.Parsed != 8 || stats.Dropped != 4 {
		t.Errorf("stats = %+v, want {Received:12 Parsed:8 Dropped:4}", stats)
	}
	if stats.Received != stats.Parsed+stats.Dropped {
		t.Errorf("received %d != parsed %d + dropped %d (every line counted exactly once)",
			stats.Received, stats.Parsed, stats.Dropped)
	}
}

// Concurrent Events for one Target never corrupt tracker state: the
// per-key update is atomic (no update lost or double-applied) and a
// duplicate concurrent trigger just refreshes the same (rule, Target)
// report (spec story 18, ADR 0007).
func TestWorkerPoolConcurrentEventsOneTarget(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	d := startTestDaemonCfg(t, clock, "unixgram", ":memory:", poolRules, func(c *Config) {
		c.Pipeline = Pipeline{Workers: 4}
	})

	// Every event past the tenth overflows on its own, so concurrent
	// triggers race to upsert the same (rule, Target) report. Timestamps
	// alternate out of order on purpose.
	const events = 24
	times := []string{eventTime1, "1734346934.123"}
	for i := range events {
		d.send(nginxLine(times[i%2], "203.0.113.7", "GET", "/big", 200, 100))
	}
	d.waitProcessed(t, events)

	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want exactly one (a duplicate concurrent trigger refreshes the same row)", doc.Reports)
	}

	// One more event reads back the exact accumulated total: every
	// concurrent update landed exactly once (leak 0, so the total is
	// order-independent).
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 100))
	d.waitProcessed(t, events+1)

	doc = d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want exactly one", doc.Reports)
	}
	if v := doc.Reports[0].Tracker.Value; v != (events+1)*100 {
		t.Errorf("tracker value = %v, want %v (atomic accumulation: every event counted once)", v, (events+1)*100)
	}
}

// pipeline.workers: 1 processes Events strictly in arrival order (spec
// story 19): the accumulated value and the last upserted sample pin
// the processing order exactly — every other order changes one of them.
func TestWorkersOneProcessesInArrivalOrder(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: abuse
    rules:
      - id: egress
        tracker: {track: bandwidth, leak: 1, volume: 500}
        actions: [{report: {reason: egress-overflow, ttl: 1h}}]
`
	d := startTestDaemonCfg(t, clock, "unixgram", ":memory:", rules, func(c *Config) {
		c.Pipeline = Pipeline{Workers: 1}
	})

	// Arrival order t1 < t2 < t3, each event overflowing. Strict
	// arrival order accumulates 1000 → 2000−100 → 2900−100 = 2800 and
	// the last upsert is t3's.
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 1000))
	d.send(nginxLine("1734346034.123", "203.0.113.7", "GET", "/big", 200, 1000))
	d.send(nginxLine("1734346134.123", "203.0.113.7", "GET", "/big", 200, 1000))
	d.waitProcessed(t, 3)

	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want exactly one", doc.Reports)
	}
	r := doc.Reports[0]
	if r.Tracker.Value != 2800 {
		t.Errorf("tracker value = %v, want 2800 (strict arrival order)", r.Tracker.Value)
	}
	wantTime := time.Unix(1734345934+200, 123000000).UTC().Format(time.RFC3339)
	if r.Sample.Time != wantTime {
		t.Errorf("sample time = %q, want %q (the last-arriving event's)", r.Sample.Time, wantTime)
	}
}

// blockingStore wedges the report write path on demand: every Upsert
// signals entry and then blocks until the test releases it, however
// long that takes. It stands in both for in-flight report upserts
// observed mid-write and for a store call that never returns (spec
// stories 31–32).
type blockingStore struct {
	*sqlite.ReportRepository
	entered chan struct{}
	gate    chan struct{}
	once    sync.Once
}

func (b *blockingStore) Upsert(ctx context.Context, rec bandage.Report) error {
	b.entered <- struct{}{}
	<-b.gate
	return b.ReportRepository.Upsert(ctx, rec)
}

func (b *blockingStore) release() {
	b.once.Do(func() { close(b.gate) })
}

// wedgeDaemon is the assembled daemon with a wedged report store: raw
// lines in at a real ingest listener, reports out through the store.
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
		entered:          make(chan struct{}, 32),
		gate:             make(chan struct{}),
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
	d, err := New(cfg, chains, WithClock(clock.Now), withStore(store))
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

// waitEntered blocks until n report upserts are in flight inside the
// wedged store (guard timeout only — never a sleep).
func waitEntered(t *testing.T, s *blockingStore, n int) {
	t.Helper()
	for i := range n {
		select {
		case <-s.entered:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of %d report upserts entered the store", i, n)
		}
	}
}

// waitDone returns the error from a shutdown goroutine (guard timeout
// only — never a sleep).
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

// Shutdown cancels the daemon-lifetime context once the drain is done,
// so no live context outlives a clean stop (context hygiene — the
// context threading contract of the daemon seam).
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

// Shutdown drains the pipeline first: report upserts already in flight
// when shutdown begins complete before the resources close, and the
// reports survive (spec story 32).
func TestShutdownDrainsInFlightReportUpserts(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	w := startWedgeDaemon(t, clock, 2)

	// Two report-triggering events (distinct Targets) whose upserts are
	// in flight inside the store when shutdown begins.
	w.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 2000))
	w.send(nginxLine(eventTime1, "203.0.113.8", "GET", "/big", 200, 2000))
	waitEntered(t, w.store, 2)

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

// Shutdown is bounded by the caller's deadline even when a store call
// never returns: it completes without waiting for the hung call (spec
// story 31).
func TestShutdownIsBoundedWhenStoreCallHangs(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	w := startWedgeDaemon(t, clock, 2)

	w.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 2000))
	waitEntered(t, w.store, 1) // the store call is wedged in flight

	ctx, cancel := context.WithCancel(context.Background())
	shutdownErr := make(chan error, 1)
	go func() { shutdownErr <- w.Shutdown(ctx) }()
	cancel() // the caller's deadline expires with the call still hung

	if err := waitDone(t, shutdownErr); !errors.Is(err, context.Canceled) {
		t.Errorf("Shutdown error = %v, want the caller's deadline error", err)
	}
	// Shutdown returned while the store call was still in flight: the
	// gate is released only after this point, by the test cleanup.
}
