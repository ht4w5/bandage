package app

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/HT4w5/bandage/internal/infra/persistence/sqlite"
)

// Trigger write contention at the daemon seam: concurrent Triggers agree on
// the write, and a failed write never loses the episode's detection.

// errWriteFailed is the wedged store's injected report write failure.
var errWriteFailed = errors.New("stub report write failure")

// contendRules overflows on any single 2000-byte event and logs a MARK per
// Trigger: report count is the detection, mark count is the Trigger cadence.
const contendRules = `
version: 0
chains:
  - name: abuse
    rules:
      - id: egress
        tracker: {track: bandwidth, leak: 0, volume: 1000}
        actions: [{report: {reason: egress-overflow, ttl: 1h}}, {log: "debug,MARK:CONTEND"}]
`

// mustStayPending asserts no line finishes within the settle window: a Trigger
// whose write is still pending must wait for the write's outcome.
func mustStayPending(t *testing.T, d *testDaemon, n int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := d.Daemon.waitProcessed(ctx, n); err == nil {
		t.Fatalf("%d lines finished while the report write was still pending: a concurrent Trigger must wait for the write's outcome", n)
	}
}

// TestE2EFailedConcurrentWriteDoesNotLoseTheDetection: a pending write is not
// a live report, and the waiting Trigger carries the write after a failure.
func TestE2EFailedConcurrentWriteDoesNotLoseTheDetection(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	dbPath := filepath.Join(t.TempDir(), "reports.db")
	inner, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	store := &blockingStore{
		ReportRepository: inner,
		storeGate:        newStoreGate(),
		failErr:          errWriteFailed,
	}
	t.Cleanup(store.release)
	d := startTestDaemonCfg(t, clock, "unixgram", dbPath, contendRules, func(c *Config) {
		c.Pipeline = Pipeline{Workers: 2}
	}, withStore(store))

	// The first event's report write wedges in flight.
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 2000))
	waitEntered(t, &store.storeGate, 1)

	// The second Trigger must not finish while the first write is pending.
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 2000))
	mustStayPending(t, d, 1)

	// Released, the wedged write fails.
	store.release()
	d.waitProcessed(t, 2)

	// The waiting Trigger retried the failed write itself: the
	// episode's detection survived.
	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want exactly one (a failed concurrent write must not lose the detection)", doc.Reports)
	}

	// Exactly one retry entered the store, nothing more.
	if n := len(store.entered); n != 1 {
		t.Fatalf("%d write retries entered the store, want 1 (the waiting Trigger carried the write itself)", n)
	}

	// The live report suppresses the next write; the suppressed Trigger
	// still empties the tracker.
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 2000))
	d.waitProcessed(t, 3)
	if n := len(store.entered); n != 1 {
		t.Fatalf("%d writes after the live report, want 1 (at most one write per live (rule, Target))", n)
	}
	if doc := d.getReports(t, nil); len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want still exactly one", doc.Reports)
	}

	// The probe adds exactly the volume: it must not Trigger over the
	// emptied bucket.
	clock.Advance(10 * time.Minute)
	d.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/big", 200, 1000))
	d.waitProcessed(t, 4)
	if got := marks(d); len(got) != 2 {
		t.Errorf("log-action marks = %v, want 2 (the landed and the suppressed Trigger; the probe must not Trigger over a cleared bucket)", got)
	}
}
