package app

import (
	"context"
	"net/url"
	"path/filepath"
	"testing"
	"time"
)

// The Penalty travels from the rules' report action into every report
// the document serves: nested on the entry, frozen with its report
// while alive (always matching its Sample), re-armed with the
// then-loaded rules' penalty, persisted across a store reopen.

// floodRules overflows on any single 150-byte event and reports for an
// hour with the given report-action penalty fragment.
func floodRules(penalty string) string {
	return `
version: 0
chains:
  - name: abuse
    rules:
      - id: flood
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: flood, ttl: 1h, ` + penalty + `}}]
`
}

// wantPenalty asserts the entry's nested penalty against the expected
// action and rate (nil for drop and reject).
func wantPenalty(t *testing.T, r reportEntry, want penaltyEntry) {
	t.Helper()
	if r.Penalty == nil {
		t.Fatalf("report %s carries no penalty, want %+v", r.Rule, want)
	}
	if r.Penalty.Action != want.Action {
		t.Errorf("penalty action = %q, want %q", r.Penalty.Action, want.Action)
	}
	switch {
	case want.Rate == nil && r.Penalty.Rate != nil:
		t.Errorf("penalty rate = %d, want none for %q", *r.Penalty.Rate, want.Action)
	case want.Rate != nil && r.Penalty.Rate == nil:
		t.Errorf("penalty rate = none, want %d", *want.Rate)
	case want.Rate != nil && *r.Penalty.Rate != *want.Rate:
		t.Errorf("penalty rate = %d, want %d", *r.Penalty.Rate, *want.Rate)
	}
}

// TestE2EReportsCarryPenalty: every report entry carries its nested
// penalty; rate is present exactly for a limit action.
func TestE2EReportsCarryPenalty(t *testing.T) {
	t.Run("a limit penalty carries its rate", func(t *testing.T) {
		clock := newTestClock(mustTime(t, wallBase))
		d := startTestDaemon(t, clock, "unixgram", ":memory:",
			floodRules("penalty: limit-bandwidth, rate: 1MB"))

		d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
		d.waitProcessed(t, 1)

		doc := d.getReports(t, nil)
		if len(doc.Reports) != 1 {
			t.Fatalf("reports = %+v, want 1", doc.Reports)
		}
		rate := int64(1000000) // 1MB, in response-payload bytes per second
		wantPenalty(t, doc.Reports[0], penaltyEntry{Action: "limit-bandwidth", Rate: &rate})
	})

	t.Run("drop carries no rate", func(t *testing.T) {
		clock := newTestClock(mustTime(t, wallBase))
		d := startTestDaemon(t, clock, "unixgram", ":memory:", tripwireRules)

		d.send(nginxLineAgent(eventTime1, "203.0.113.7", "GET", "/", 200, 0, "curl/8.0"))
		d.waitProcessed(t, 1)

		doc := d.getReports(t, nil)
		if len(doc.Reports) != 1 {
			t.Fatalf("reports = %+v, want 1", doc.Reports)
		}
		wantPenalty(t, doc.Reports[0], penaltyEntry{Action: "drop"})
	})
}

// shutdownDaemon stops a daemon under test ahead of its cleanup (restart
// tests then start another daemon on the same store).
func shutdownDaemon(t *testing.T, d *testDaemon) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// TestE2EPenaltySurvivesRestart: the penalty persists with its report
// across a store reopen (a daemon restart).
func TestE2EPenaltySurvivesRestart(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	dbPath := filepath.Join(t.TempDir(), "reports.db")
	rules := floodRules("penalty: limit-bandwidth, rate: 1MB")

	d1 := startTestDaemon(t, clock, "unixgram", dbPath, rules)
	d1.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d1.waitProcessed(t, 1)
	shutdownDaemon(t, d1)

	d2 := startTestDaemon(t, clock, "unixgram", dbPath, rules)
	doc := d2.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want the persisted report", doc.Reports)
	}
	rate := int64(1000000)
	wantPenalty(t, doc.Reports[0], penaltyEntry{Action: "limit-bandwidth", Rate: &rate})
}

// TestE2EAliveReportFreezesPenaltyWithItsSample: while a report is alive
// its penalty freezes with it, always matching the Sample that justified
// it - a restart on rules with a different penalty rewrites neither.
func TestE2EAliveReportFreezesPenaltyWithItsSample(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	dbPath := filepath.Join(t.TempDir(), "reports.db")

	d1 := startTestDaemon(t, clock, "unixgram", dbPath, floodRules("penalty: limit-bandwidth, rate: 1MB"))
	d1.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d1.waitProcessed(t, 1)
	shutdownDaemon(t, d1)

	// The report is alive until 19:00. The new run's rules recommend a
	// different penalty (penalty/tracker coherence is the consumer's
	// judgment, ADR 0010), but the suppressed Trigger writes nothing.
	clock.Advance(10 * time.Minute) // 18:10
	d2 := startTestDaemon(t, clock, "unixgram", dbPath, floodRules("penalty: limit-pkt-rate, rate: 200"))
	d2.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/big2", 200, 150))
	d2.waitProcessed(t, 1)

	doc := d2.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want 1", doc.Reports)
	}
	r := doc.Reports[0]
	rate := int64(1000000)
	wantPenalty(t, r, penaltyEntry{Action: "limit-bandwidth", Rate: &rate})
	if r.Sample.Time != eventTime1At || r.Sample.Path != "/big" {
		t.Errorf("sample = %+v, want the first Trigger's event frozen (the penalty always matches its Sample)", r.Sample)
	}
	if r.UpdatedAt != wallBase {
		t.Errorf("updated_at = %q, want frozen %q", r.UpdatedAt, wallBase)
	}
}

// TestE2ERearmedWriteCarriesThenLoadedPenalty: a re-armed write after
// deletion or expiry carries the penalty of the rules loaded at write
// time, never the old report's stale advice.
func TestE2ERearmedWriteCarriesThenLoadedPenalty(t *testing.T) {
	oldRules := floodRules("penalty: limit-bandwidth, rate: 1MB")
	newRules := floodRules("penalty: limit-pkt-rate, rate: 200")

	t.Run("after DELETE /reports", func(t *testing.T) {
		clock := newTestClock(mustTime(t, wallBase))
		dbPath := filepath.Join(t.TempDir(), "reports.db")

		d1 := startTestDaemon(t, clock, "unixgram", dbPath, oldRules)
		d1.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
		d1.waitProcessed(t, 1)
		if _, n := d1.del(t, url.Values{"rule": {"flood"}}); n != 1 {
			t.Fatalf("delete count = %d, want 1", n)
		}
		shutdownDaemon(t, d1)

		clock.Advance(10 * time.Minute) // 18:10
		d2 := startTestDaemon(t, clock, "unixgram", dbPath, newRules)
		d2.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/big", 200, 150))
		d2.waitProcessed(t, 1)

		doc := d2.getReports(t, nil)
		if len(doc.Reports) != 1 || doc.Reports[0].UpdatedAt != "2025-10-17T18:10:00Z" {
			t.Fatalf("reports = %+v, want the 18:10 replacement write", doc.Reports)
		}
		rate := int64(200)
		wantPenalty(t, doc.Reports[0], penaltyEntry{Action: "limit-pkt-rate", Rate: &rate})
	})

	t.Run("after expiry", func(t *testing.T) {
		clock := newTestClock(mustTime(t, wallBase))
		dbPath := filepath.Join(t.TempDir(), "reports.db")

		d1 := startTestDaemon(t, clock, "unixgram", dbPath, oldRules)
		d1.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
		d1.waitProcessed(t, 1)
		shutdownDaemon(t, d1)

		clock.Advance(90 * time.Minute) // 19:30 - past the 19:00 expiry
		d2 := startTestDaemon(t, clock, "unixgram", dbPath, newRules)
		d2.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/big", 200, 150))
		d2.waitProcessed(t, 1)

		doc := d2.getReports(t, nil)
		if len(doc.Reports) != 1 || doc.Reports[0].UpdatedAt != "2025-10-17T19:30:00Z" {
			t.Fatalf("reports = %+v, want the 19:30 replacement write", doc.Reports)
		}
		rate := int64(200)
		wantPenalty(t, doc.Reports[0], penaltyEntry{Action: "limit-pkt-rate", Rate: &rate})
	})
}
