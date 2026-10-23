package evaluation

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/HT4w5/webmedkit/bandage/internal/domain"
)

// BenchmarkEvaluate measures full chain evaluation over pre-parsed events
// with stub ports (the domain lint keeps the real store and sink out).

// benchCache is a map-backed TrackerCache double (no locking).
type benchCache struct{ records map[string]domain.Record }

func newBenchCache() *benchCache {
	return &benchCache{records: make(map[string]domain.Record)}
}

func (c *benchCache) Update(_ context.Context, ns, key string, _ time.Duration, fn func(*domain.Record)) (domain.Record, error) {
	full := ns + domain.KeySep + key
	r := c.records[full]
	fn(&r)
	c.records[full] = r
	return r, nil
}

// Clear empties the record for (ns, key) - the Trigger reset.
func (c *benchCache) Clear(_ context.Context, ns, key string) error {
	delete(c.records, ns+domain.KeySep+key)
	return nil
}

// benchSink is a counting ReportSink double.
type benchSink struct{ triggers int }

func (s *benchSink) Trigger(context.Context, domain.Report) error {
	s.triggers++
	return nil
}

// benchMatcher stands in for the filter tree this module cannot import:
// one prefix comparison per rule.
type benchMatcher struct{ prefix string }

func (m benchMatcher) Match(ev *domain.Event) bool { return strings.HasPrefix(ev.Path, m.prefix) }

// benchEvents builds n events cycling 256 target keys.
func benchEvents(n int) []domain.Event {
	events := make([]domain.Event, n)
	for i := range events {
		events[i] = domain.Event{
			RemoteAddr: netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", i%256)),
			Method:     "GET",
			Path:       fmt.Sprintf("/files/obj-%04d.bin", i%256),
			Agent:      "curl/8.5.0",
			Status:     200,
			SentBytes:  6000,
		}
	}
	return events
}

// benchEvent returns pool event i with its timestamp at the i-th second of
// the fixture epoch; time must march forward per op or the leaky bucket freezes.
func benchEvent(events []domain.Event, i int) domain.Event {
	ev := events[i%len(events)]
	ev.Time = benchEpoch.Add(time.Duration(i) * time.Second)
	return ev
}

// benchChains mirrors configs/rules.yml tracker rules with report actions, one
// per chain: trigger-every (volume 0.5, every event Triggers) and match-never.
func benchChains(triggerEvery bool) []domain.Chain {
	leak, volume := 10.0, 200.0
	if triggerEvery {
		leak, volume = 0, 0.5
	}
	rate := func(id string) domain.Rule {
		return domain.Rule{
			ID:     id,
			Filter: benchMatcher{prefix: "/"},
			Tracker: &domain.TrackerConfig{
				Kind:         domain.TrackRate,
				Leak:         leak,
				Volume:       volume,
				TTL:          domain.TTL(leak, volume),
				TargetPrefix: domain.DefaultTargetPrefix,
			},
			Actions: []domain.Action{{Report: &domain.ReportAction{Reason: id + "-overflow", TTL: time.Hour}}},
		}
	}
	return []domain.Chain{
		{Name: "download-abuse", Rules: []domain.Rule{rate("sustained-egress")}},
		{Name: "flood", Rules: []domain.Rule{rate("rapid-requests")}},
		{Name: "scanning", Rules: []domain.Rule{rate("probe-paths")}},
	}
}

// benchEpoch is the fixture event-time origin (benchNow the fixed wall clock);
// it duplicates internal/bench.Epoch, which the domain lint keeps out - keep it identical.
var benchEpoch = time.Unix(1734345934, 0).UTC()

func benchNow() time.Time { return benchEpoch }

// TestBenchChainsMatchTheirNames verifies the fixture's scenario split:
// trigger-every Triggers per event and match-never triggers none.
func TestBenchChainsMatchTheirNames(t *testing.T) {
	tests := []struct {
		name         string
		triggerEvery bool
		perEvent     int // Trigger calls per event: one per single-rule chain
	}{
		{"trigger-every", true, 3},
		{"match-never", false, 0},
	}
	events := benchEvents(1024)
	const passes = 10
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink := &benchSink{}
			svc := NewService(benchChains(tt.triggerEvery), newBenchCache(), sink, benchNow, nil)
			for i := 0; i < passes*len(events); i++ {
				ev := benchEvent(events, i)
				if err := svc.Evaluate(context.Background(), &ev); err != nil {
					t.Fatalf("Evaluate error: %v", err)
				}
			}
			want := tt.perEvent * passes * len(events)
			if sink.triggers != want {
				t.Fatalf("triggers = %d, want %d (%d per event over %d events)", sink.triggers, want, tt.perEvent, passes*len(events))
			}
		})
	}
}

func BenchmarkEvaluate(b *testing.B) {
	for _, tc := range []struct {
		name         string
		triggerEvery bool
	}{{"trigger-every", true}, {"match-never", false}} {
		b.Run(tc.name, func(b *testing.B) {
			svc := NewService(benchChains(tc.triggerEvery), newBenchCache(), &benchSink{}, benchNow, nil)
			events := benchEvents(1024)
			ctx := context.Background()
			var lines int
			for b.Loop() {
				ev := benchEvent(events, lines)
				if err := svc.Evaluate(ctx, &ev); err != nil {
					b.Fatalf("Evaluate: %v", err)
				}
				lines++
			}
			// One op is one event, i.e. one log line.
			var rate float64
			if elapsed := b.Elapsed(); elapsed > 0 {
				rate = float64(lines) / elapsed.Seconds()
			}
			b.ReportMetric(rate, "lines/s")
		})
	}
}
