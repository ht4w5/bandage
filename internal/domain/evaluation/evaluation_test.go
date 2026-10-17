package evaluation

import (
	"context"
	"net/netip"
	"testing"
	"time"

	bandage "github.com/HT4w5/bandage/internal/domain"
	"github.com/HT4w5/bandage/internal/domain/report"
	"github.com/HT4w5/bandage/internal/domain/track"
)

// Replay tracker semantics at the evaluation seam (PLAN §1, DECISIONS
// §8): unknown sizes are skipped entirely, increments are transferred
// fractions capped at 1, state is keyed per (Target, path), decay and
// overflow follow the generic leaky-bucket math, and the cache-entry TTL
// is derived per event from the volume-method output. Stubs stand in at
// the existing ports (DECISIONS §2); no sleeps, event timestamps only.

// matchAll accepts every event.
type matchAll struct{}

func (matchAll) Match(*bandage.Event) bool { return true }

// stubCache is a track.TrackerCache test double recording every update.
type stubCache struct {
	records map[string]track.Record
	updates []stubUpdate
}

type stubUpdate struct {
	ns, key string
	ttl     time.Duration
}

func (c *stubCache) Update(_ context.Context, ns, key string, ttl time.Duration, fn func(*track.Record)) (track.Record, error) {
	if c.records == nil {
		c.records = make(map[string]track.Record)
	}
	full := ns + "\x00" + key
	r := c.records[full]
	fn(&r)
	c.records[full] = r
	c.updates = append(c.updates, stubUpdate{ns: ns, key: key, ttl: ttl})
	return r, nil
}

// stubRepo is a report.Repository test double capturing upserts.
type stubRepo struct {
	upserts []bandage.Report
}

func (r *stubRepo) Upsert(_ context.Context, rec bandage.Report) error {
	r.upserts = append(r.upserts, rec)
	return nil
}

func (r *stubRepo) List(context.Context, report.Query) ([]bandage.Report, error) {
	return nil, nil
}

func (r *stubRepo) Delete(context.Context, report.Query) (int, error) { return 0, nil }

func (r *stubRepo) DeleteExpired(context.Context, time.Time) (int, error) { return 0, nil }

// harness assembles a service around one replay rule and exposes the
// stubs' recorded state.
type harness struct {
	svc  *Service
	repo *stubRepo
	cch  *stubCache
}

func newHarness(t *testing.T, cfg *bandage.TrackerConfig) *harness {
	t.Helper()
	// The loader defaults the target prefix at build; mirror that here.
	if cfg.TargetPrefix == (bandage.TargetPrefix{}) {
		cfg.TargetPrefix = bandage.DefaultTargetPrefix
	}
	repo := &stubRepo{}
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
		svc:  NewService(chains, cache, report.NewService(repo), func() time.Time { return time.Unix(1000, 0) }, nil),
		repo: repo,
		cch:  cache,
	}
}

func (h *harness) evaluate(t *testing.T, ev *bandage.Event) {
	t.Helper()
	if err := h.svc.Evaluate(context.Background(), ev); err != nil {
		t.Fatalf("Evaluate error: %v", err)
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

// Events whose size estimate is unknown are skipped entirely: no
// increment, no decay, no cache touch — no Match is possible during
// enrichment warm-up, even with a volume a single transfer would burst
// through.
func TestReplaySkipsUnknownSize(t *testing.T) {
	h := newHarness(t, &bandage.TrackerConfig{
		Kind: bandage.TrackReplay, Leak: 0, Volume: 0.5,
	})
	h.evaluate(t, event(100, "/a", 1000, bandage.FilesizeUnknown))

	if len(h.cch.updates) != 0 {
		t.Errorf("cache updates = %+v, want none (unknown size skips the cache entirely)", h.cch.updates)
	}
	if len(h.repo.upserts) != 0 {
		t.Errorf("upserts = %+v, want none (no Match during warm-up)", h.repo.upserts)
	}
}

// The increment is the transferred fraction of the estimated size,
// capped at 1 per event (DECISIONS §8).
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
			for _, r := range h.cch.records {
				if r.Value != tt.want {
					t.Errorf("value = %v, want %v", r.Value, tt.want)
				}
			}
		})
	}
}

// Replay state is keyed by (Target, path): the aggregated target prefix
// string and the path joined with "\x00" (DECISIONS §9), namespaced by
// the rule ID.
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

// The generic leaky-bucket math applies to fractions too: value decays
// by leak×Δt between events and Overflows strictly above volume. The
// reading at trigger time carries kind, value, leak and volume.
func TestReplayDecayAndOverflow(t *testing.T) {
	cfg := &bandage.TrackerConfig{Kind: bandage.TrackReplay, Leak: 0.5, Volume: 2}
	h := newHarness(t, cfg)

	// Full-file downloads (fraction 1 each): 1 at t=100; 2−1=1 at t=102;
	// 2 at t=102; 3−1=2 at t=104; 3 at t=104 overflows (3 > 2).
	at := []int64{100, 102, 102, 104, 104}
	for i, ts := range at {
		h.evaluate(t, event(ts, "/a", 100, 100))
		wantReport := i == len(at)-1
		if got := len(h.repo.upserts) != 0; got != wantReport {
			t.Fatalf("after event %d: report = %v, want %v (value vs volume 2)", i, got, wantReport)
		}
	}

	rec := h.repo.upserts[0]
	want := bandage.TrackerReading{Track: "replay", Value: 3, Leak: 0.5, Volume: 2}
	if rec.Tracker != want {
		t.Errorf("tracker reading = %+v, want %+v", rec.Tracker, want)
	}
	if rec.Sample.Size != 100 || rec.Sample.Sent != 100 || rec.Sample.Path != "/a" {
		t.Errorf("sample = %+v, want the triggering transfer with size 100", rec.Sample)
	}
}

// The volume at trigger time is the volume method's output for that
// event's estimated file size (DECISIONS §8).
func TestReplayReadingCarriesVolumeMethodOutput(t *testing.T) {
	cfg := &bandage.TrackerConfig{
		Kind:         bandage.TrackReplay,
		Leak:         0,
		VolumeMethod: track.StepVolume{Threshold: 1000, VolumeLow: 2, VolumeHigh: 5},
	}
	h := newHarness(t, cfg)

	// A big file tolerates 5 equivalents; the sixth full download (value
	// 6) overflows and reports volume 5.
	for i := 0; i < 6; i++ {
		h.evaluate(t, event(int64(100+i), "/big.iso", 2000, 2000))
	}
	if len(h.repo.upserts) != 1 {
		t.Fatalf("upserts = %+v, want 1", h.repo.upserts)
	}
	want := bandage.TrackerReading{Track: "replay", Value: 6, Volume: 5}
	if got := h.repo.upserts[0].Tracker; got != want {
		t.Errorf("tracker reading = %+v, want %+v", got, want)
	}
}

// The cache-entry TTL is derived per event as volume/leak from the
// current volume-method output (DECISIONS §8), so it moves when the
// method's output moves; leak 0 falls back to the default TTL.
func TestReplayTTLDerivedPerEvent(t *testing.T) {
	cfg := &bandage.TrackerConfig{
		Kind:         bandage.TrackReplay,
		Leak:         0.5,
		VolumeMethod: track.StepVolume{Threshold: 1000, VolumeLow: 2, VolumeHigh: 5},
	}
	h := newHarness(t, cfg)

	h.evaluate(t, event(100, "/a", 100, 100))   // small: volume 2 → TTL 2/0.5 = 4s
	h.evaluate(t, event(101, "/a", 2000, 2000)) // estimate moved big: volume 5 → TTL 10s

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
		VolumeMethod: track.ConstantVolume(3),
	}
	h0 := newHarness(t, cfg0)
	h0.evaluate(t, event(100, "/a", 100, 100))
	if got := h0.cch.updates[0].ttl; got != track.DefaultTTL {
		t.Errorf("leak 0 TTL = %v, want %v", got, track.DefaultTTL)
	}
}
