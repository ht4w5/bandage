package evaluation

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	bandage "github.com/HT4w5/bandage/internal/domain"
)

// matchAll accepts every event.
type matchAll struct{}

func (matchAll) Match(*bandage.Event) bool { return true }

// stubCache is a TrackerCache test double recording updates and clears.
type stubCache struct {
	records map[string]bandage.Record
	updates []stubUpdate
	clears  []stubClear
}

type stubUpdate struct {
	ns, key string
	ttl     time.Duration
}

type stubClear struct {
	ns, key string
}

func (c *stubCache) Update(_ context.Context, ns, key string, ttl time.Duration, fn func(*bandage.Record)) (bandage.Record, error) {
	if c.records == nil {
		c.records = make(map[string]bandage.Record)
	}
	full := ns + "\x00" + key
	r := c.records[full]
	fn(&r)
	c.records[full] = r
	c.updates = append(c.updates, stubUpdate{ns: ns, key: key, ttl: ttl})
	return r, nil
}

// Clear empties the record for (ns, key) and records the call.
func (c *stubCache) Clear(_ context.Context, ns, key string) error {
	c.clears = append(c.clears, stubClear{ns: ns, key: key})
	delete(c.records, ns+"\x00"+key)
	return nil
}

// stubSink is a ReportSink double capturing reports; the next failures
// writes fail (the failed-write retry seam).
type stubSink struct {
	upserts  []bandage.Report
	attempts int
	failures int
}

func (s *stubSink) Trigger(_ context.Context, rec bandage.Report) error {
	s.attempts++
	if s.failures > 0 {
		s.failures--
		return errors.New("report write failed")
	}
	s.upserts = append(s.upserts, rec)
	return nil
}

// captureLogger is a Logger double recording every record's fields.
type captureLogger struct{ records []map[string]any }

func (l *captureLogger) Log(_ bandage.Level, _ string, fields map[string]any) {
	l.records = append(l.records, fields)
}

// constVolume is a VolumeMethod double: one tolerated volume regardless of
// size.
type constVolume float64

func (v constVolume) Volume(float64) float64 { return float64(v) }
func (v constVolume) String() string         { return "constant" }

// stepVolume is a VolumeMethod double: low below threshold bytes, high
// from it. The real volume methods have their own tests in track.
type stepVolume struct {
	threshold, low, high float64
}

func (v stepVolume) Volume(size float64) float64 {
	if size >= v.threshold {
		return v.high
	}
	return v.low
}
func (v stepVolume) String() string { return "step" }

// harness assembles a service around one replay rule and exposes the
// stubs' recorded state.
type harness struct {
	svc  *Service
	sink *stubSink
	cch  *stubCache
}

func newHarness(t *testing.T, cfg *bandage.TrackerConfig) *harness {
	t.Helper()
	// The loader defaults the target prefix at build; mirror that here.
	if cfg.TargetPrefix == (bandage.TargetPrefix{}) {
		cfg.TargetPrefix = bandage.DefaultTargetPrefix
	}
	sink := &stubSink{}
	cache := &stubCache{}
	chains := []bandage.Chain{{
		Name: "replay",
		Rules: []bandage.Rule{{
			ID:      "iso-replay",
			Filter:  matchAll{},
			Tracker: cfg,
			Actions: []bandage.Action{{Report: &bandage.ReportAction{Reason: "iso-replay", TTL: time.Hour}}},
		}},
	}}
	return &harness{
		svc:  NewService(chains, cache, sink, func() time.Time { return time.Unix(1000, 0) }, nil),
		sink: sink,
		cch:  cache,
	}
}

func (h *harness) evaluate(t *testing.T, ev *bandage.Event) {
	t.Helper()
	if err := h.svc.Evaluate(context.Background(), ev); err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
}

// evaluateErr evaluates one event expecting the failed report write to
// propagate (a failed write aborts the action list).
func (h *harness) evaluateErr(t *testing.T, ev *bandage.Event) {
	t.Helper()
	if err := h.svc.Evaluate(context.Background(), ev); err == nil {
		t.Fatalf("Evaluate error = nil, want the failed report write to propagate")
	}
}

// newRuleHarness assembles the service around one rule with the given tracker
// and actions (the Trigger-semantics seam).
func newRuleHarness(t *testing.T, cfg *bandage.TrackerConfig, actions ...bandage.Action) *harness {
	t.Helper()
	if cfg != nil && cfg.TargetPrefix == (bandage.TargetPrefix{}) {
		cfg.TargetPrefix = bandage.DefaultTargetPrefix
	}
	sink := &stubSink{}
	cache := &stubCache{}
	chains := []bandage.Chain{{
		Name: "abuse",
		Rules: []bandage.Rule{{
			ID:      "rate-overflow",
			Filter:  matchAll{},
			Tracker: cfg,
			Actions: actions,
		}},
	}}
	return &harness{
		svc:  NewService(chains, cache, sink, func() time.Time { return time.Unix(1000, 0) }, nil),
		sink: sink,
		cch:  cache,
	}
}

func event(at int64, path string, sent, size int64) *bandage.Event {
	return &bandage.Event{
		Time:       time.Unix(at, 0),
		RemoteAddr: netip.MustParseAddr("203.0.113.7"),
		Path:       path,
		Status:     200,
		SentBytes:  sent,
		SizeBytes:  size,
	}
}

// Unknown size estimates are skipped entirely: no increment, no decay, no
// cache touch - no Match is possible during enrichment warm-up.
func TestReplaySkipsUnknownSize(t *testing.T) {
	h := newHarness(t, &bandage.TrackerConfig{
		Kind: bandage.TrackReplay, Leak: 0, Volume: 0.5,
	})
	h.evaluate(t, event(100, "/a", 1000, bandage.FilesizeUnknown))

	if len(h.cch.updates) != 0 {
		t.Errorf("cache updates = %+v, want none (unknown size skips the cache entirely)", h.cch.updates)
	}
	if len(h.sink.upserts) != 0 {
		t.Errorf("upserts = %+v, want none (no Match during warm-up)", h.sink.upserts)
	}
}

// The increment is the transferred fraction of the estimated size, capped
// at 1 per event.
func TestReplayFractionIncrement(t *testing.T) {
	tests := []struct {
		name  string
		steps []struct{ sent, size int64 }
		want  float64
	}{
		{"half a file adds half", []struct{ sent, size int64 }{{50, 100}}, 0.5},
		{"a full file adds one", []struct{ sent, size int64 }{{100, 100}}, 1},
		{"overshoot is capped at one", []struct{ sent, size int64 }{{250, 100}}, 1},
		{"two halves accumulate", []struct{ sent, size int64 }{{50, 100}, {50, 100}}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, &bandage.TrackerConfig{
				Kind: bandage.TrackReplay, Leak: 0, Volume: 100,
			})
			for i, s := range tt.steps {
				h.evaluate(t, event(int64(100+i), "/a", s.sent, s.size))
			}
			// A vacuous pass is possible here: an empty map makes the
			// loop below assert nothing at all.
			if len(h.cch.records) == 0 {
				t.Fatal("no replay records in the cache, want one")
			}
			for _, r := range h.cch.records {
				if r.Value != tt.want {
					t.Errorf("value = %v, want %v", r.Value, tt.want)
				}
			}
		})
	}
}

// Replay state is keyed by (Target, path): the target prefix string and the
// path joined with "\x00", namespaced by the rule ID.
func TestReplayKeysByTargetAndPath(t *testing.T) {
	h := newHarness(t, &bandage.TrackerConfig{
		Kind: bandage.TrackReplay, Leak: 0, Volume: 100,
	})

	h.evaluate(t, event(100, "/a", 100, 100))
	h.evaluate(t, event(101, "/b", 100, 100))
	ev := event(102, "/a", 100, 100)
	ev.RemoteAddr = netip.MustParseAddr("203.0.113.8")
	h.evaluate(t, ev)

	want := []string{"203.0.113.7/32\x00/a", "203.0.113.7/32\x00/b", "203.0.113.8/32\x00/a"}
	if len(h.cch.updates) != 3 {
		t.Fatalf("updates = %d, want 3", len(h.cch.updates))
	}
	for i, u := range h.cch.updates {
		if u.ns != "iso-replay" || u.key != want[i] {
			t.Errorf("update %d = (%q, %q), want (%q, %q)", i, u.ns, u.key, "iso-replay", want[i])
		}
	}
}

// Fractions decay like any leaky bucket (leak*dt) and overflow strictly
// above volume; the reading carries kind, value, leak and volume.
func TestReplayDecayAndOverflow(t *testing.T) {
	cfg := &bandage.TrackerConfig{Kind: bandage.TrackReplay, Leak: 0.5, Volume: 2}
	h := newHarness(t, cfg)

	// Full-file downloads (fraction 1 each): 1 at t=100; 2-1=1 at t=102;
	// 2 at t=102; 3-1=2 at t=104; 3 at t=104 overflows (3 > 2).
	at := []int64{100, 102, 102, 104, 104}
	for i, ts := range at {
		h.evaluate(t, event(ts, "/a", 100, 100))
		wantReport := i == len(at)-1
		if got := len(h.sink.upserts) != 0; got != wantReport {
			t.Fatalf("after event %d: report = %v, want %v (value vs volume 2)", i, got, wantReport)
		}
	}

	rec := h.sink.upserts[0]
	want := bandage.TrackerReading{Track: "replay", Value: 3, Leak: 0.5, Volume: 2}
	if rec.Tracker != want {
		t.Errorf("tracker reading = %+v, want %+v", rec.Tracker, want)
	}
	if rec.Sample.Size != 100 || rec.Sample.Sent != 100 || rec.Sample.Path != "/a" {
		t.Errorf("sample = %+v, want the triggering transfer with size 100", rec.Sample)
	}
}

// The volume at trigger time is the volume method's output for that event's
// estimated file size.
func TestReplayReadingCarriesVolumeMethodOutput(t *testing.T) {
	cfg := &bandage.TrackerConfig{
		Kind:         bandage.TrackReplay,
		Leak:         0,
		VolumeMethod: stepVolume{threshold: 1000, low: 2, high: 5},
	}
	h := newHarness(t, cfg)

	// A big file tolerates 5 equivalents; the sixth full download overflows.
	for i := 0; i < 6; i++ {
		h.evaluate(t, event(int64(100+i), "/big.iso", 2000, 2000))
	}
	if len(h.sink.upserts) != 1 {
		t.Fatalf("upserts = %+v, want 1", h.sink.upserts)
	}
	want := bandage.TrackerReading{Track: "replay", Value: 6, Volume: 5}
	if got := h.sink.upserts[0].Tracker; got != want {
		t.Errorf("tracker reading = %+v, want %+v", got, want)
	}
}

// The cache-entry TTL is volume/leak of the current volume-method output,
// re-derived per event; leak 0 falls back to the default TTL.
func TestReplayTTLDerivedPerEvent(t *testing.T) {
	cfg := &bandage.TrackerConfig{
		Kind:         bandage.TrackReplay,
		Leak:         0.5,
		VolumeMethod: stepVolume{threshold: 1000, low: 2, high: 5},
	}
	h := newHarness(t, cfg)

	h.evaluate(t, event(100, "/a", 100, 100))   // small: volume 2 -> TTL 2/0.5 = 4s
	h.evaluate(t, event(101, "/a", 2000, 2000)) // estimate moved big: volume 5 -> TTL 10s

	if len(h.cch.updates) != 2 {
		t.Fatalf("updates = %+v, want 2", h.cch.updates)
	}
	if got := h.cch.updates[0].ttl; got != 4*time.Second {
		t.Errorf("first TTL = %v, want 4s (volume 2 / leak 0.5)", got)
	}
	if got := h.cch.updates[1].ttl; got != 10*time.Second {
		t.Errorf("second TTL = %v, want 10s (volume 5 / leak 0.5)", got)
	}

	// leak 0: the default TTL.
	cfg0 := &bandage.TrackerConfig{
		Kind:         bandage.TrackReplay,
		VolumeMethod: constVolume(3),
	}
	h0 := newHarness(t, cfg0)
	h0.evaluate(t, event(100, "/a", 100, 100))
	if got := h0.cch.updates[0].ttl; got != bandage.DefaultTTL {
		t.Errorf("leak 0 TTL = %v, want %v", got, bandage.DefaultTTL)
	}
}

// A Trigger empties the matched rule's tracker record for the match's key:
// one Trigger per accumulation episode, not per event.
func TestTriggerEmptiesTrackerRecord(t *testing.T) {
	h := newRuleHarness(t, &bandage.TrackerConfig{Kind: bandage.TrackRate, Leak: 0, Volume: 2},
		bandage.Action{Report: &bandage.ReportAction{Reason: "overflow", TTL: time.Hour}})

	// 1 + 1 + 1 = 3 > 2 overflows on the third event: one Trigger.
	for i := 0; i < 3; i++ {
		h.evaluate(t, event(int64(100+i), "/a", 100, 0))
	}
	if h.sink.attempts != 1 {
		t.Fatalf("report writes = %d, want 1 (one Trigger per episode)", h.sink.attempts)
	}
	if got := h.sink.upserts[0].Tracker.Value; got != 3 {
		t.Errorf("trigger reading = %v, want 3 (the Trigger-time reading, pre-reset)", got)
	}
	if got := h.cch.clears; len(got) != 1 || got[0].ns != "rate-overflow" || got[0].key != "203.0.113.7/32" {
		t.Errorf("tracker clears = %+v, want the match's Target key emptied once", got)
	}

	// Re-armed: two more events accumulate 2 and the third Triggers again
	// (a full volume must recur).
	for i := 0; i < 2; i++ {
		h.evaluate(t, event(int64(200+i), "/a", 100, 0))
	}
	if h.sink.attempts != 1 {
		t.Fatalf("report writes = %d, want still 1 (a full volume must recur)", h.sink.attempts)
	}
	h.evaluate(t, event(300, "/a", 100, 0))
	if h.sink.attempts != 2 {
		t.Fatalf("report writes = %d, want 2 (second episode Triggered)", h.sink.attempts)
	}
}

// A replay Trigger empties the (Target, path) record the match keyed on:
// per-path accumulation re-arms while other paths keep their state.
func TestTriggerEmptiesReplayTrackerPerPath(t *testing.T) {
	h := newHarness(t, &bandage.TrackerConfig{Kind: bandage.TrackReplay, Leak: 0, Volume: 2})

	// /a and /b accumulate a full download each per event. /a reaches
	// 3 > 2 and Triggers; /b sits at 2.
	for i, path := range []string{"/a", "/b", "/a", "/b", "/a"} {
		h.evaluate(t, event(int64(100+i), path, 100, 100))
	}
	if h.sink.attempts != 1 {
		t.Fatalf("report writes = %d, want 1 (/a overflows)", h.sink.attempts)
	}
	want := "203.0.113.7/32\x00/a"
	if got := h.cch.clears; len(got) != 1 || got[0].ns != "iso-replay" || got[0].key != want {
		t.Fatalf("tracker clears = %+v, want only (%q, %q) emptied", got, "iso-replay", want)
	}

	// /b kept its accumulation: its next download overflows (3 > 2).
	h.evaluate(t, event(105, "/b", 100, 100))
	if h.sink.attempts != 2 {
		t.Fatalf("report writes = %d, want 2 (/b kept its state)", h.sink.attempts)
	}
	// while /a re-armed and needs a full volume again.
	h.evaluate(t, event(106, "/a", 100, 100))
	if h.sink.attempts != 2 {
		t.Fatalf("report writes = %d, want still 2 (/a re-arms from empty)", h.sink.attempts)
	}
}

// A failed report write leaves the tracker record intact and the next
// matching event retries the report.
func TestFailedReportWriteLeavesTrackerRecordIntact(t *testing.T) {
	h := newRuleHarness(t, &bandage.TrackerConfig{Kind: bandage.TrackRate, Leak: 0, Volume: 2},
		bandage.Action{Report: &bandage.ReportAction{Reason: "overflow", TTL: time.Hour}})
	h.sink.failures = 1

	h.evaluate(t, event(100, "/a", 100, 0))
	h.evaluate(t, event(101, "/a", 100, 0))
	h.evaluateErr(t, event(102, "/a", 100, 0))
	if h.sink.attempts != 1 || len(h.sink.upserts) != 0 {
		t.Fatalf("attempts = %d, upserts = %d, want one failed write", h.sink.attempts, len(h.sink.upserts))
	}
	if got := h.cch.clears; len(got) != 0 {
		t.Fatalf("tracker clears = %+v, want none (a failed write is not a Trigger outcome)", got)
	}

	// The kept episode overflows again (4 > 2) and the retry lands.
	h.evaluate(t, event(200, "/a", 100, 0))
	if h.sink.attempts != 2 || len(h.sink.upserts) != 1 {
		t.Fatalf("attempts = %d, upserts = %d, want the retry to land", h.sink.attempts, len(h.sink.upserts))
	}
	// The landed Trigger emptied the record: a lone event no longer overflows.
	h.evaluate(t, event(300, "/a", 100, 0))
	if h.sink.attempts != 2 {
		t.Fatalf("attempts = %d, want still 2 (the landed Trigger emptied the record)", h.sink.attempts)
	}
}

// A match whose actions contain no report action never empties the tracker.
func TestMatchWithoutReportActionKeepsTracker(t *testing.T) {
	h := newRuleHarness(t, &bandage.TrackerConfig{Kind: bandage.TrackRate, Leak: 0, Volume: 100},
		bandage.Action{Log: &bandage.LogAction{Level: bandage.LevelDebug, Message: "SEEN:"}})
	for i := 0; i < 5; i++ {
		h.evaluate(t, event(int64(100+i), "/a", 100, 0))
	}
	if got := h.cch.clears; len(got) != 0 {
		t.Errorf("tracker clears = %+v, want none (no report action ran)", got)
	}
	for full, r := range h.cch.records {
		if r.Value != 5 {
			t.Errorf("record %q = %+v, want value 5 (log-only rules accumulate as before)", full, r)
		}
	}
	if h.sink.attempts != 0 {
		t.Errorf("report writes = %d, want 0", h.sink.attempts)
	}
}

// Tracker-less rules have nothing to empty: every match Triggers on filter
// alone and no record is ever cleared.
func TestTrackerlessRuleClearsNothing(t *testing.T) {
	h := newRuleHarness(t, nil,
		bandage.Action{Report: &bandage.ReportAction{Reason: "tripwire", TTL: time.Hour}})
	for i := 0; i < 3; i++ {
		h.evaluate(t, event(int64(100+i), "/a", 100, 0))
	}
	if h.sink.attempts != 3 {
		t.Errorf("report writes = %d, want 3 (tracker-less rules match on filter alone)", h.sink.attempts)
	}
	if got := h.cch.clears; len(got) != 0 {
		t.Errorf("tracker clears = %+v, want none (nothing to clear)", got)
	}
}

// Actions see the Trigger-time tracker reading (pre-reset), never the
// emptied bucket.
func TestActionsSeeTriggerTimeReading(t *testing.T) {
	log := &captureLogger{}
	sink, cache := &stubSink{}, &stubCache{}
	cfg := &bandage.TrackerConfig{Kind: bandage.TrackRate, Leak: 0, Volume: 2, TargetPrefix: bandage.DefaultTargetPrefix}
	chains := []bandage.Chain{{Name: "abuse", Rules: []bandage.Rule{{
		ID: "rate-overflow", Filter: matchAll{}, Tracker: cfg,
		Actions: []bandage.Action{
			{Report: &bandage.ReportAction{Reason: "overflow", TTL: time.Hour}},
			{Log: &bandage.LogAction{Level: bandage.LevelInfo, Message: "OVERFLOW:"}},
		},
	}}}}
	svc := NewService(chains, cache, sink, func() time.Time { return time.Unix(1000, 0) }, log)

	for i := 0; i < 3; i++ {
		if err := svc.Evaluate(context.Background(), event(int64(100+i), "/a", 100, 0)); err != nil {
			t.Fatalf("Evaluate error: %v", err)
		}
	}
	if len(log.records) != 1 {
		t.Fatalf("log records = %d, want 1 (the match's log action)", len(log.records))
	}
	want := bandage.TrackerReading{Track: "rate", Value: 3, Volume: 2}
	if got := log.records[0]["tracker"]; got != want {
		t.Errorf("logged tracker reading = %+v, want %+v (the Trigger-time reading, pre-reset)", got, want)
	}
}
