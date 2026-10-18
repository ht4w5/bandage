package app

import (
	"testing"
	"time"
)

// Trigger empties the rule's tracker at the assembled daemon seam
// (spec Testing Decisions — the daemon is the primary seam; ticket 02):
// a Trigger empties the matched rule's tracker for the match's key, so
// a flagged Target accumulates a full volume of abuse again before the
// next Trigger — once per accumulation episode, not per event. Wall
// time is driven by the injected clock and progress by processed-line
// waiting; never by sleeping.

// A continuously abusive Target Triggers once per volume of traffic,
// not per event: every Trigger empties the bucket, so between reports
// the traffic must re-accumulate past the rule's volume from zero.
func TestE2ETriggerOncePerVolumeOfTraffic(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: abuse
    rules:
      - id: egress
        tracker: {track: bandwidth, leak: 0, volume: 10000}
        actions: [{report: {reason: egress-overflow, ttl: 1h}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)

	// Each event carries 6000 bytes: 6000 + 6000 = 12000 > 10000
	// overflows on every second event — the Trigger empties the bucket,
	// so events one and three of each pair stay quiet. The wall clock
	// steps between events so every write leaves its own updated_at.
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
	// Trigger — the write would bump updated_at to 18:20.
	clock.Advance(10 * time.Minute) // 18:20
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 6000))
	d.waitProcessed(t, 3)
	if doc := d.getReports(t, nil); len(doc.Reports) != 1 || doc.Reports[0].UpdatedAt != "2025-10-17T18:10:00Z" {
		t.Fatalf("after event 3: %+v, want the 18:10 report untouched (not per event)", doc.Reports)
	}

	// One full volume of traffic later the Target Triggers again: the
	// row is upserted with a fresh episode's reading.
	clock.Advance(10 * time.Minute) // 18:30
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 6000))
	d.waitProcessed(t, 4)
	doc = d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("after event 4: %+v, want still one report (upsert identity)", doc.Reports)
	}
	r := doc.Reports[0]
	if r.CreatedAt != "2025-10-17T18:10:00Z" || r.UpdatedAt != "2025-10-17T18:30:00Z" {
		t.Errorf("created_at/updated_at = %q/%q, want 18:10 (first write) and 18:30 (second episode)",
			r.CreatedAt, r.UpdatedAt)
	}
	if r.Tracker.Value != 12000 {
		t.Errorf("tracker value = %v, want 12000 (a fresh full volume)", r.Tracker.Value)
	}
}

// Concurrently overflowing events leave the tracker consistent with a
// cleared bucket (ADR 0007's relaxed ordering): every concurrent
// Trigger empties the record atomically, so after the storm one event
// of exactly the volume must not overflow — any leftover accumulation
// would push it over and refresh the row.
func TestE2EConcurrentTriggersLeaveClearedBucket(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: abuse
    rules:
      - id: egress
        tracker: {track: bandwidth, leak: 0, volume: 1000}
        actions: [{report: {reason: egress-overflow, ttl: 1h}}]
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

	// The probe adds exactly the volume: over an empty bucket it sums to
	// 1000, which is not above volume 1000 — no Trigger, no refreshed
	// updated_at. Over any leftover accumulation it would overflow and
	// bump updated_at to 18:10.
	clock.Advance(10 * time.Minute)
	d.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/big", 200, 1000))
	d.waitProcessed(t, events+1)

	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want exactly one", doc.Reports)
	}
	if doc.Reports[0].UpdatedAt != wallBase {
		t.Errorf("updated_at = %q, want %q (the probe must not Trigger over a cleared bucket)",
			doc.Reports[0].UpdatedAt, wallBase)
	}
}
