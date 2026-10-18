package app

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/HT4w5/bandage/internal/infra/persistence/sqlite"
)

// Trigger write contention at the assembled daemon seam (spec stories
// 4, 5 and 14): concurrent Triggers for one (rule, Target) agree on
// the write, a failed write never loses the episode's detection and
// the tracker empties exactly for the Triggers whose write landed or
// was suppressed by a live report. Wall time is driven by the injected
// clock and progress by processed-line waiting; never by sleeping.

// errWriteFailed is the wedged store's injected report write failure.
var errWriteFailed = errors.New("stub report write failure")

// contendRules overflows on any single 2000-byte event (bandwidth
// volume 1000) and logs a MARK per Trigger: the report count is the
// detection and the mark count is the Trigger cadence, both readable
// from outside the daemon.
const contendRules = `
version: 0
chains:
  - name: abuse
    rules:
      - id: egress
        tracker: {track: bandwidth, leak: 0, volume: 1000}
        actions: [{report: {reason: egress-overflow, ttl: 1h}}, {log: "debug,MARK:CONTEND"}]
`

// mustStayPending asserts that no line finishes processing within the
// settle window: a Trigger whose write is still pending inside the
// store must not complete — its suppression decision has to wait for
// the write's outcome (the hole this test pins is exactly a Trigger
// that finishes early and clears the tracker). The window is pure
// settle margin over microsecond-scale pipeline work, never a progress
// dependency: a slow machine can only weaken the assertion, never
// make it wrong.
func mustStayPending(t *testing.T, d *testDaemon, n int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := d.Daemon.waitProcessed(ctx, n); err == nil {
		t.Fatalf("%d lines finished while the report write was still pending: a concurrent Trigger must wait for the write's outcome", n)
	}
}

// A Trigger whose write is pending is not a live report: a concurrent
// Trigger must not let it suppress-and-empty while the write may still
// fail (the story 4/5 hole), and when that pending write does fail the
// waiting Trigger carries the write itself — the episode's detection
// survives (story 5 under story 14's contention), the failed write
// leaves no suppression behind, and the live report bounds later
// writes to one (story 14) while every landed or suppressed Trigger
// empties the tracker (story 4).
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

	// The first event's report write wedges in flight: its (rule,
	// Target) write is pending inside the store.
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 2000))
	waitEntered(t, &store.storeGate, 1)

	// The second event overflows on its own and Triggers while the
	// first write is still pending — and must not finish while it is:
	// treating the pending write as a live report is the hole (the
	// suppressed Trigger would clear the tracker and lose the episode's
	// detection when the write then fails).
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 2000))
	mustStayPending(t, d, 1)

	// Released, the wedged write fails.
	store.release()
	d.waitProcessed(t, 2)

	// The episode's detection survived: the second Trigger waited out
	// the pending write, retried it itself after the failure and landed
	// it. Without the retry the report is lost entirely — the failed
	// write's Trigger keeps its tracker record, but the story is over.
	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want exactly one (a failed concurrent write must not lose the detection)", doc.Reports)
	}

	// Exactly one write attempt retried the failure — the store saw
	// the wedged write (counted before) and one retry, nothing more.
	if n := len(store.entered); n != 1 {
		t.Fatalf("%d write retries entered the store, want 1 (the waiting Trigger carried the write itself)", n)
	}

	// The live report suppresses the next overflowing event's write
	// (story 14) and the suppressed Trigger still empties the tracker
	// (story 4): the actions run and nothing more is written.
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 2000))
	d.waitProcessed(t, 3)
	if n := len(store.entered); n != 1 {
		t.Fatalf("%d writes after the live report, want 1 (at most one write per live (rule, Target))", n)
	}
	if doc := d.getReports(t, nil); len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want still exactly one", doc.Reports)
	}

	// The probe adds exactly the volume: over the emptied bucket it
	// must not Trigger at all — every Trigger so far emptied the
	// tracker, so the bucket restarted from zero.
	clock.Advance(10 * time.Minute)
	d.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/big", 200, 1000))
	d.waitProcessed(t, 4)
	if got := marks(d); len(got) != 2 {
		t.Errorf("log-action marks = %v, want 2 (the landed and the suppressed Trigger; the probe must not Trigger over a cleared bucket)", got)
	}
}
