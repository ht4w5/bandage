package app

import (
	"testing"
	"time"
)

// Trigger tests: a Trigger empties the matched rule's tracker at the daemon
// seam, once per accumulation episode; the log action observes each Trigger.

// TestE2ETriggerOncePerVolumeOfTraffic: a Target Triggers once per volume of
// traffic, not per event; writes are suppressed while the report is alive.
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

	// Every second event overflows volume 10000 and Triggers, emptying
	// the bucket; the clock steps so each write would have its own updated_at.
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 6000))
	d.waitProcessed(t, 1)
	if doc := d.getReports(t, nil); len(doc.Reports) != 0 {
		t.Fatalf("after 1 event: %+v, want none (6000 <= 10000)", doc.Reports)
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

	// The next event starts a fresh episode: it must not Trigger.
	clock.Advance(10 * time.Minute) // 18:20
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 6000))
	d.waitProcessed(t, 3)
	if doc := d.getReports(t, nil); len(doc.Reports) != 1 || doc.Reports[0].UpdatedAt != "2025-10-17T18:10:00Z" {
		t.Fatalf("after event 3: %+v, want the 18:10 report untouched (not per event)", doc.Reports)
	}

	// The Target Triggers again, but the write is suppressed while the
	// report is alive: the row freezes at the first episode's write.
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
	if got := marks(d); len(got) != 2 {
		t.Errorf("log-action marks = %v, want 2 (one per Trigger)", got)
	}
}

// TestE2EConcurrentTriggersLeaveClearedBucket: concurrent Triggers empty the
// tracker atomically, so a probe at exactly the volume must not Trigger.
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

	// Timestamps are out of order on purpose; each of the 24 events
	// overflows volume 1000 on its own, so all Trigger concurrently.
	const events = 24
	times := []string{eventTime1, "1734346934.123"}
	for i := range events {
		d.send(nginxLine(times[i%2], "203.0.113.7", "GET", "/big", 200, 2000))
	}
	d.waitProcessed(t, events)

	if got := marks(d); len(got) != events {
		t.Fatalf("log-action marks = %d, want %d (every storm event Triggered)", len(got), events)
	}

	// The probe sums to exactly the volume: it must not Trigger over a
	// cleared bucket, but would over any leftover accumulation.
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
