package app

import (
	"testing"
	"time"
)

// Trigger empties the rule's tracker at the assembled daemon seam
// (spec Testing Decisions — the daemon is the primary seam; ticket 02):
// a Trigger empties the matched rule's tracker for the match's key, so
// a flagged Target accumulates a full volume of abuse again before the
// next Trigger — once per accumulation episode, not per event. While
// the report is alive the Triggers write nothing (ticket 03), so the
// rule's log action is the observable that a Trigger ran. Wall time is
// driven by the injected clock and progress by processed-line waiting;
// never by sleeping.

// A continuously abusive Target Triggers once per volume of traffic,
// not per event: every Trigger empties the bucket, so between Triggers
// the traffic must re-accumulate past the rule's volume from zero — and
// while the report is alive those Triggers write nothing (ADR 0008).
func TestE2ETriggerOncePerVolumeOfTraffic(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: abuse
    rules:
      - id: egress
        tracker: {track: bandwidth, leak: 0, volume: 10000}
        actions: [{report: {reason: egress-overflow, ttl: 1h}}, {log: "debug,MARK:EPISODE"}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)

	// Each event carries 6000 bytes: 6000 + 6000 = 12000 > 10000
	// overflows on every second event — the Trigger empties the bucket,
	// so events one and three of each pair stay quiet. The wall clock
	// steps between events so every write would leave its own updated_at
	// were it not suppressed.
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 6000))
	d.waitProcessed(t, 1)
	if doc := d.getReports(t, nil); len(doc.Reports) != 0 {
		t.Fatalf("after 1 event: %+v, want none (6000 ≤ 10000)", doc.Reports)
	}

	clock.Advance(10 * time.Minute) // 18:10
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 6000))
	d.waitProcessed(t, 2)
	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 || doc.Reports[0].UpdatedAt != "2025-10-17T18:10:00Z" {
		t.Fatalf("after the first full volume: %+v, want one report at 18:10", doc.Reports)
	}
	if v := doc.Reports[0].Tracker.Value; v != 12000 {
		t.Errorf("tracker value = %v, want 12000 (the Trigger-time reading, pre-reset)", v)
	}

	// The next event is the start of a fresh episode: it must not
	// Trigger — the report would be refreshed were the write not gated.
	clock.Advance(10 * time.Minute) // 18:20
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 6000))
	d.waitProcessed(t, 3)
	if doc := d.getReports(t, nil); len(doc.Reports) != 1 || doc.Reports[0].UpdatedAt != "2025-10-17T18:10:00Z" {
		t.Fatalf("after event 3: %+v, want the 18:10 report untouched (not per event)", doc.Reports)
	}

	// One full volume of traffic later the Target Triggers again — the
	// log action runs — but while the report is alive the write is
	// suppressed (ADR 0008): the row freezes at the first episode's
	// write, its reading included.
	clock.Advance(10 * time.Minute) // 18:30
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 6000))
	d.waitProcessed(t, 4)
	doc = d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("after event 4: %+v, want still one report", doc.Reports)
	}
	r := doc.Reports[0]
	if r.CreatedAt != "2025-10-17T18:10:00Z" || r.UpdatedAt != "2025-10-17T18:10:00Z" {
		t.Errorf("created_at/updated_at = %q/%q, want the 18:10 write frozen (suppressed)",
			r.CreatedAt, r.UpdatedAt)
	}
	if r.Tracker.Value != 12000 {
		t.Errorf("tracker value = %v, want 12000 (the first episode's reading, frozen)", r.Tracker.Value)
	}
	// Two Triggers ran the actions (one per volume of traffic) while
	// only one write landed.
	if got := marks(d); len(got) != 2 {
		t.Errorf("log-action marks = %v, want 2 (one per Trigger)", got)
	}
}

// Concurrently overflowing events leave the tracker consistent with a
// cleared bucket (ADR 0007's relaxed ordering): every concurrent
// Trigger empties the record atomically, so after the storm one event
// of exactly the volume must not Trigger — any leftover accumulation
// would push it over and run the rule's actions again (the write would
// be suppressed while the report is alive, so the observable is the
// log action).
func TestE2EConcurrentTriggersLeaveClearedBucket(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: abuse
    rules:
      - id: egress
        tracker: {track: bandwidth, leak: 0, volume: 1000}
        actions: [{report: {reason: egress-overflow, ttl: 1h}}, {log: "debug,MARK:STORM"}]
`
	d := startTestDaemonCfg(t, clock, "unixgram", ":memory:", rules, func(c *Config) {
		c.Pipeline = Pipeline{Workers: 4}
	})

	// 24 events of 2000 bytes, timestamps out of order on purpose: each
	// event overflows volume 1000 on its own, so all of them Trigger
	// concurrently and empty the bucket.
	const events = 24
	times := []string{eventTime1, "1734346934.123"}
	for i := range events {
		d.send(nginxLine(times[i%2], "203.0.113.7", "GET", "/big", 200, 2000))
	}
	d.waitProcessed(t, events)

	if got := marks(d); len(got) != events {
		t.Fatalf("log-action marks = %d, want %d (every storm event Triggered)", len(got), events)
	}

	// The probe adds exactly the volume: over an empty bucket it sums to
	// 1000, which is not above volume 1000 — no Trigger. Over any
	// leftover accumulation it would overflow and run the actions.
	clock.Advance(10 * time.Minute)
	d.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/big", 200, 1000))
	d.waitProcessed(t, events+1)

	if got := marks(d); len(got) != events {
		t.Errorf("log-action marks = %d, want %d (the probe must not Trigger over a cleared bucket)", len(got), events)
	}
	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want exactly one", doc.Reports)
	}
	if doc.Reports[0].UpdatedAt != wallBase {
		t.Errorf("updated_at = %q, want %q (the probe must not Trigger over a cleared bucket)",
			doc.Reports[0].UpdatedAt, wallBase)
	}
}
