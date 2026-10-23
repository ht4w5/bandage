package app

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HT4w5/bandage/internal/bandage"
	"github.com/HT4w5/bandage/internal/infra/persistence/sqlite"
)

// Report write suppression while a report for (rule, Target) is alive: further
// Triggers write nothing but actions keep running; delete/expiry re-arms writes.

// nginxLineAgent is nginxLine with the optional agent field.
func nginxLineAgent(t, client, method, path string, status int, sent int64, agent string) string {
	return fmt.Sprintf(`{"time":%q,"client":%q,"method":%q,"url":%q,"status":%d,"sent":%d,"agent":%q}`,
		t, client, method, path, status, sent, agent)
}

// marks returns the captured MARK log-action messages in emission order.
func marks(d *testDaemon) []string {
	var out []string
	for _, msg := range d.logs.messages() {
		if strings.HasPrefix(msg, "MARK:") {
			out = append(out, msg)
		}
	}
	return out
}

// stickyRules is a one-rule fixture that overflows on any single 150-byte
// event (bandwidth volume 100) and reports for an hour.
const stickyRules = `
version: 0
chains:
  - name: abuse
    rules:
      - id: sticky
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: sticky, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
`

// tripwireRules is the tracker-less tripwire: an agent keyword filter with a
// report action and no tracker; suppression alone bounds its writes.
const tripwireRules = `
version: 0
chains:
  - name: trip
    rules:
      - id: ua-trip
        filter: 'agent keyword "curl"'
        actions: [{report: {reason: ua-trip, ttl: 1h, penalty: drop}}]
`

// TestE2ESuppressedTriggersFreezeReportButRunActions: while the report is
// alive further Triggers write nothing, but actions run and the report freezes.
func TestE2ESuppressedTriggersFreezeReportButRunActions(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: abuse
    rules:
      - id: flood
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: flood, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}, {log: "debug,MARK:FLOOD"}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)

	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d.waitProcessed(t, 1)
	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want 1", doc.Reports)
	}
	first := doc.Reports[0]
	if first.UpdatedAt != wallBase || first.ExpiresAt != "2025-10-17T19:00:00Z" {
		t.Fatalf("first write updated_at/expires_at = %q/%q", first.UpdatedAt, first.ExpiresAt)
	}

	// A fresh episode Triggers again, but the report is alive: nothing is written.
	clock.Advance(10 * time.Minute)
	d.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/big2", 200, 150))
	d.waitProcessed(t, 2)
	doc = d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want still 1 (the live report's write is suppressed)", doc.Reports)
	}
	r := doc.Reports[0]
	if r.CreatedAt != wallBase || r.UpdatedAt != wallBase || r.ExpiresAt != "2025-10-17T19:00:00Z" {
		t.Errorf("created_at/updated_at/expires_at = %q/%q/%q, want all frozen at the first write",
			r.CreatedAt, r.UpdatedAt, r.ExpiresAt)
	}
	if r.Tracker.Value != 150 {
		t.Errorf("tracker value = %v, want 150 (the Trigger-time reading is frozen)", r.Tracker.Value)
	}
	if r.Sample.Time != eventTime1At || r.Sample.Path != "/big" {
		t.Errorf("sample = %+v, want the first Trigger's event frozen", r.Sample)
	}

	// The rule kept matching and its actions ran for every event.
	if got := marks(d); len(got) != 2 {
		t.Errorf("log-action marks = %v, want one per event (actions run while the write is silent)", got)
	}
}

// TestE2ESuppressedTriggersStillEmptyTheTracker: each Trigger empties the
// tracker even while the write is suppressed.
func TestE2ESuppressedTriggersStillEmptyTheTracker(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: abuse
    rules:
      - id: sticky
        tracker: {track: bandwidth, leak: 0, volume: 200}
        actions: [{report: {reason: sticky, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)

	// 150 + 150 = 300 > 200 overflows on every second event: event 2
	// writes, event 4 is suppressed. Both Triggers empty the bucket.
	for range 4 {
		d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	}
	d.waitProcessed(t, 4)
	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 || doc.Reports[0].Tracker.Value != 300 || doc.Reports[0].UpdatedAt != wallBase {
		t.Fatalf("reports = %+v, want one frozen report at reading 300", doc.Reports)
	}

	if _, n := d.del(t, url.Values{"rule": {"sticky"}}); n != 1 {
		t.Fatalf("delete count = %d, want 1", n)
	}

	// The suppressed Trigger emptied the bucket: a fresh 150-byte event
	// must stay quiet.
	clock.Advance(10 * time.Minute) // 18:10
	d.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/big", 200, 150))
	d.waitProcessed(t, 5)
	if doc := d.getReports(t, nil); len(doc.Reports) != 0 {
		t.Fatalf("reports after one fresh event = %+v, want none (a fresh episode, not a running total)", doc.Reports)
	}

	// One full volume later the re-armed write lands with a fresh episode's
	// reading: 150 kept + 150 new.
	d.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/big", 200, 150))
	d.waitProcessed(t, 6)
	doc = d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want the re-armed write", doc.Reports)
	}
	r := doc.Reports[0]
	if r.Tracker.Value != 300 {
		t.Errorf("tracker value = %v, want 300 (150 kept from the quiet event + 150 new)", r.Tracker.Value)
	}
	if r.CreatedAt != "2025-10-17T18:10:00Z" || r.UpdatedAt != "2025-10-17T18:10:00Z" {
		t.Errorf("created_at/updated_at = %q/%q, want a fresh 18:10 write", r.CreatedAt, r.UpdatedAt)
	}
}

// TestE2ETrackerlessTripwireWritesOncePerTarget: every matching event
// Triggers, but suppression bounds the writes to one per Target.
func TestE2ETrackerlessTripwireWritesOncePerTarget(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	d := startTestDaemon(t, clock, "unixgram", ":memory:", tripwireRules)

	d.send(nginxLineAgent(eventTime1, "203.0.113.7", "GET", "/", 200, 0, "curl/8.0"))
	d.waitProcessed(t, 1)
	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 || doc.Reports[0].Target != "203.0.113.7/32" {
		t.Fatalf("reports = %+v, want one for 203.0.113.7/32", doc.Reports)
	}

	// Every further curl event Triggers but the live report suppresses its write.
	clock.Advance(10 * time.Minute)
	d.send(nginxLineAgent(eventTime2, "203.0.113.7", "GET", "/", 200, 0, "curl/8.0"))
	d.send(nginxLineAgent(eventTime2, "203.0.113.8", "GET", "/", 200, 0, "curl/8.0"))
	d.waitProcessed(t, 3)
	doc = d.getReports(t, nil)
	if len(doc.Reports) != 2 {
		t.Fatalf("reports = %+v, want one per Target", doc.Reports)
	}
	byTarget := map[string]reportEntry{}
	for _, r := range doc.Reports {
		byTarget[r.Target] = r
	}
	if r := byTarget["203.0.113.7/32"]; r.UpdatedAt != wallBase {
		t.Errorf("203.0.113.7/32 updated_at = %q, want frozen %q (write suppressed)", r.UpdatedAt, wallBase)
	}
	if r := byTarget["203.0.113.8/32"]; r.UpdatedAt != "2025-10-17T18:10:00Z" {
		t.Errorf("203.0.113.8/32 updated_at = %q, want a fresh 18:10 write", r.UpdatedAt)
	}
}

// TestE2ESuppressionIsPerRuleAndTarget: one rule's report never silences
// another rule's write, and deleting re-arms only that rule.
func TestE2ESuppressionIsPerRuleAndTarget(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: abuse-one
    rules:
      - id: rule-one
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: one, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
  - name: abuse-two
    rules:
      - id: rule-two
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: two, ttl: 2h, penalty: limit-bandwidth, rate: 1MB}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)

	// Both rules report the same Target on the first event: one report per
	// (rule, Target).
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d.waitProcessed(t, 1)
	doc := d.getReports(t, nil)
	if len(doc.Reports) != 2 {
		t.Fatalf("reports = %+v, want one per rule for the shared Target", doc.Reports)
	}

	// Both rules Trigger again; both writes are suppressed at their own
	// live reports.
	clock.Advance(10 * time.Minute)
	d.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/big", 200, 150))
	d.waitProcessed(t, 2)
	doc = d.getReports(t, nil)
	if len(doc.Reports) != 2 {
		t.Fatalf("reports = %+v, want still 2 (both writes suppressed)", doc.Reports)
	}
	for _, r := range doc.Reports {
		if r.UpdatedAt != wallBase {
			t.Errorf("%s updated_at = %q, want frozen %q", r.Rule, r.UpdatedAt, wallBase)
		}
	}

	// Deleting rule-one's report re-arms rule-one only.
	if _, n := d.del(t, url.Values{"rule": {"rule-one"}}); n != 1 {
		t.Fatalf("delete count = %d, want 1", n)
	}
	clock.Advance(10 * time.Minute) // 18:20
	d.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/big", 200, 150))
	d.waitProcessed(t, 3)
	doc = d.getReports(t, nil)
	if len(doc.Reports) != 2 {
		t.Fatalf("reports = %+v, want 2", doc.Reports)
	}
	byRule := map[string]reportEntry{}
	for _, r := range doc.Reports {
		byRule[r.Rule] = r
	}
	if r := byRule["rule-one"]; r.UpdatedAt != "2025-10-17T18:20:00Z" {
		t.Errorf("rule-one updated_at = %q, want the re-armed 18:20 write", r.UpdatedAt)
	}
	if r := byRule["rule-two"]; r.UpdatedAt != wallBase {
		t.Errorf("rule-two updated_at = %q, want still frozen %q", r.UpdatedAt, wallBase)
	}
}

// TestE2EDeleteRearmsTrackerlessOnNextEvent: the next matching event writes
// (there is no episode to re-accumulate).
func TestE2EDeleteRearmsTrackerlessOnNextEvent(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	d := startTestDaemon(t, clock, "unixgram", ":memory:", tripwireRules)

	d.send(nginxLineAgent(eventTime1, "203.0.113.7", "GET", "/", 200, 0, "curl/8.0"))
	d.waitProcessed(t, 1)
	clock.Advance(10 * time.Minute)
	d.send(nginxLineAgent(eventTime2, "203.0.113.7", "GET", "/", 200, 0, "curl/8.0"))
	d.waitProcessed(t, 2)
	if doc := d.getReports(t, nil); len(doc.Reports) != 1 || doc.Reports[0].UpdatedAt != wallBase {
		t.Fatalf("reports = %+v, want the one frozen report", doc.Reports)
	}

	if _, n := d.del(t, url.Values{"rule": {"ua-trip"}}); n != 1 {
		t.Fatalf("delete count = %d, want 1", n)
	}

	// The very next matching event writes again.
	clock.Advance(10 * time.Minute) // 18:20
	d.send(nginxLineAgent(eventTime2, "203.0.113.7", "GET", "/", 200, 0, "curl/8.0"))
	d.waitProcessed(t, 3)
	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 || doc.Reports[0].UpdatedAt != "2025-10-17T18:20:00Z" {
		t.Fatalf("reports = %+v, want the re-armed 18:20 write", doc.Reports)
	}
}

// TestE2EExpiryRearmsWriting: a report is alive only until expiry or deletion,
// so expiry re-arms writing even before the sweeper removes its row.
func TestE2EExpiryRearmsWriting(t *testing.T) {
	t.Run("the sweeper re-arms", func(t *testing.T) {
		clock := newTestClock(mustTime(t, wallBase))
		d := startTestDaemon(t, clock, "unixgram", ":memory:", stickyRules)

		d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
		d.waitProcessed(t, 1)

		clock.Advance(90 * time.Minute) // 19:30 - past the 19:00 expiry
		if n, err := d.sweepOnce(context.Background()); err != nil || n != 1 {
			t.Fatalf("sweepOnce = (%d, %v), want (1, nil)", n, err)
		}

		d.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/big", 200, 150))
		d.waitProcessed(t, 2)
		doc := d.getReports(t, nil)
		if len(doc.Reports) != 1 {
			t.Fatalf("reports = %+v, want the re-armed write", doc.Reports)
		}
		r := doc.Reports[0]
		if r.CreatedAt != "2025-10-17T19:30:00Z" || r.UpdatedAt != "2025-10-17T19:30:00Z" {
			t.Errorf("created_at/updated_at = %q/%q, want a fresh 19:30 write", r.CreatedAt, r.UpdatedAt)
		}
	})

	t.Run("expiry alone re-arms before the sweeper runs", func(t *testing.T) {
		clock := newTestClock(mustTime(t, wallBase))
		d := startTestDaemon(t, clock, "unixgram", ":memory:", stickyRules)

		d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
		d.waitProcessed(t, 1)

		clock.Advance(90 * time.Minute) // 19:30 - past expiry, nothing swept
		d.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/big", 200, 150))
		d.waitProcessed(t, 2)
		doc := d.getReports(t, nil)
		if len(doc.Reports) != 1 {
			t.Fatalf("reports = %+v, want the re-armed write over the stored row", doc.Reports)
		}
		r := doc.Reports[0]
		// The stored row keeps its identity: created_at stays fixed at the
		// row's first insert.
		if r.CreatedAt != wallBase {
			t.Errorf("created_at = %q, want fixed %q (upsert over the stored row)", r.CreatedAt, wallBase)
		}
		if r.UpdatedAt != "2025-10-17T19:30:00Z" || r.ExpiresAt != "2025-10-17T20:30:00Z" {
			t.Errorf("updated_at/expires_at = %q/%q, want the 19:30 write's", r.UpdatedAt, r.ExpiresAt)
		}
	})
}

// TestE2ERestartSuppressesForAliveReports: suppression is rebuilt from the
// report table, so a still-alive report suppresses the next Trigger's write.
func TestE2ERestartSuppressesForAliveReports(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	dbPath := filepath.Join(t.TempDir(), "reports.db")

	d1 := startTestDaemon(t, clock, "unixgram", dbPath, stickyRules)
	d1.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d1.waitProcessed(t, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := d1.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	cancel()

	clock.Advance(10 * time.Minute) // 18:10 - the report is alive until 19:00
	d2 := startTestDaemon(t, clock, "unixgram", dbPath, stickyRules)
	d2.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/big", 200, 150))
	d2.waitProcessed(t, 1)
	doc := d2.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want 1", doc.Reports)
	}
	r := doc.Reports[0]
	if r.UpdatedAt != wallBase || r.Tracker.Value != 150 || r.Sample.Time != eventTime1At {
		t.Errorf("report = %+v, want it frozen at the pre-restart write (suppression rebuilt)", r)
	}
}

// TestE2ERestartDoesNotSuppressDeletedReports: the next Trigger writes.
func TestE2ERestartDoesNotSuppressDeletedReports(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	dbPath := filepath.Join(t.TempDir(), "reports.db")

	d1 := startTestDaemon(t, clock, "unixgram", dbPath, stickyRules)
	d1.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d1.waitProcessed(t, 1)
	if _, n := d1.del(t, url.Values{"rule": {"sticky"}}); n != 1 {
		t.Fatalf("delete count = %d, want 1", n)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := d1.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	cancel()

	clock.Advance(10 * time.Minute) // 18:10
	d2 := startTestDaemon(t, clock, "unixgram", dbPath, stickyRules)
	d2.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/big", 200, 150))
	d2.waitProcessed(t, 1)
	doc := d2.getReports(t, nil)
	if len(doc.Reports) != 1 || doc.Reports[0].UpdatedAt != "2025-10-17T18:10:00Z" {
		t.Fatalf("reports = %+v, want the 18:10 write (the deleted report does not suppress)", doc.Reports)
	}
}

// TestE2ERestartDoesNotSuppressExpiredReports: an expired report no longer
// suppresses even while its row is still stored (unswept).
func TestE2ERestartDoesNotSuppressExpiredReports(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	dbPath := filepath.Join(t.TempDir(), "reports.db")

	d1 := startTestDaemon(t, clock, "unixgram", dbPath, stickyRules)
	d1.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d1.waitProcessed(t, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := d1.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	cancel()

	clock.Advance(90 * time.Minute) // 19:30 - the report expired at 19:00
	d2 := startTestDaemon(t, clock, "unixgram", dbPath, stickyRules)
	d2.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/big", 200, 150))
	d2.waitProcessed(t, 1)
	doc := d2.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want the re-armed write", doc.Reports)
	}
	r := doc.Reports[0]
	// The stored (unswept) row keeps its identity through the upsert.
	if r.CreatedAt != wallBase || r.UpdatedAt != "2025-10-17T19:30:00Z" {
		t.Errorf("created_at/updated_at = %q/%q, want fixed %q and the 19:30 write",
			r.CreatedAt, r.UpdatedAt, wallBase)
	}
}

// countingStore counts report writes at the store seam.
type countingStore struct {
	*sqlite.ReportRepository
	writes atomic.Int64
}

func (c *countingStore) Upsert(ctx context.Context, rec bandage.Report) error {
	c.writes.Add(1)
	return c.ReportRepository.Upsert(ctx, rec)
}

// TestE2EConcurrentTriggersAtMostOneWrite: a storm of simultaneously
// overflowing events produces at most one write under the worker pool.
func TestE2EConcurrentTriggersAtMostOneWrite(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	inner, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	store := &countingStore{ReportRepository: inner}

	d := startTestDaemonCfg(t, clock, "unixgram", ":memory:", stickyRules,
		func(c *Config) { c.Pipeline = Pipeline{Workers: 4} }, withStore(store))

	const events = 16
	for range events {
		d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	}
	d.waitProcessed(t, events)

	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want one live report", doc.Reports)
	}
	if w := store.writes.Load(); w != 1 {
		t.Errorf("report writes = %d, want 1 (at most one write per live report)", w)
	}
}

// TestE2EFlaggedTargetEventsKeepFeedingAnalysis: nothing is dropped from
// analysis once a report is alive; other rules' trackers keep feeding.
func TestE2EFlaggedTargetEventsKeepFeedingAnalysis(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: flag
    rules:
      - id: egress
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: egress-overflow, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}, {log: "debug,MARK:FLAG"}]
  - name: replay
    rules:
      - id: iso-replay
        tracker: {track: replay, leak: 0, volume: 1}
        actions: [{report: {reason: iso-replay, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)

	// The bandwidth rule Triggers every event (1000 > 100) but writes only
	// the first; the replay rule overflows on the sixth (value 2 > 1).
	const events = 6
	for i := range events {
		d.send(nginxLine(fmt.Sprintf("%d", 1734345934+i), "203.0.113.7", "GET", "/releases/24.04.iso", 200, 1000))
	}
	d.waitProcessed(t, events)

	doc := d.getReports(t, nil)
	byRule := map[string]reportEntry{}
	for _, r := range doc.Reports {
		byRule[r.Rule] = r
	}
	if len(doc.Reports) != 2 {
		t.Fatalf("reports = %+v, want one per rule", doc.Reports)
	}
	// The flagging rule's report froze at its first write...
	if r := byRule["egress"]; r.UpdatedAt != wallBase || r.Sample.Time != "2024-12-16T10:45:34Z" {
		t.Errorf("egress report = %+v, want it frozen at the first Trigger's write", r)
	}
	// ...while the flagged Target's events still fed Filesize and the replay
	// tracker.
	r := byRule["iso-replay"]
	if r.Tracker.Track != "replay" || r.Tracker.Value != 2 || r.Tracker.Volume != 1 {
		t.Errorf("iso-replay tracker = %+v, want {replay 2 0 1}", r.Tracker)
	}
	if r.Sample.Size != 1000 || r.Sample.Sent != 1000 {
		t.Errorf("iso-replay sample = %+v, want the triggering transfer with enriched size 1000", r.Sample)
	}

	// The flagging rule ran its actions for every event; nothing was dropped.
	if got := marks(d); len(got) != events {
		t.Errorf("log-action marks = %v, want %d (one per event)", got, events)
	}
	c := d.counters()
	if c.Received != events || c.Parsed != events || c.Dropped != 0 {
		t.Errorf("counters = %+v, want {%d %d 0} (nothing dropped)", c, events, events)
	}
}

// TestE2EReplaySuppressionGrainIsRuleAndTarget: per-path episodes keep
// Triggering, but one live report per (rule, Target) suppresses the rest.
func TestE2EReplaySuppressionGrainIsRuleAndTarget(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: download-abuse
    rules:
      - id: iso-replay
        tracker: {track: replay, leak: 0, volume: 1}
        actions: [{report: {reason: iso-replay, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}, {log: "debug,MARK:REPLAY"}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)

	// Two paths, one Target: each path overflows on its sixth transfer;
	// the second path's Trigger is suppressed at (rule, Target) grain.
	for i := range 6 {
		d.send(nginxLine(fmt.Sprintf("%d", 1734345934+i), "203.0.113.7", "GET", "/a.iso", 200, 1000))
	}
	d.waitProcessed(t, 6)
	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 || doc.Reports[0].Sample.Path != "/a.iso" {
		t.Fatalf("reports = %+v, want one for /a.iso", doc.Reports)
	}

	for i := 6; i < 12; i++ {
		d.send(nginxLine(fmt.Sprintf("%d", 1734345934+i), "203.0.113.7", "GET", "/b.iso", 200, 1000))
	}
	d.waitProcessed(t, 12)
	doc = d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want still 1 ((rule, Target) grain, not per path)", doc.Reports)
	}
	r := doc.Reports[0]
	if r.UpdatedAt != wallBase || r.Sample.Path != "/a.iso" {
		t.Errorf("report = %+v, want it frozen at the first path's write", r)
	}
	// Both paths Triggered while only one write landed.
	if got := marks(d); len(got) != 2 {
		t.Errorf("log-action marks = %v, want one per Triggering path", got)
	}
}
