package evaluation

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	bandage "github.com/HT4w5/bandage/internal/domain"
)

// BenchmarkEvaluate measures full chain evaluation over pre-parsed
// events (H4, H6) with stub ports: the domain lint keeps the real
// memory store and sqlite sink out of this package, so the integration
// variants live in internal/app/evaluate_bench_test.go. The stubs stand
// in at the consumer-side ports (DECISIONS §2): a map-backed
// TrackerCache (store map access without locking and LRU) and a
// counting ReportSink. The fires/never-fires split isolates the action
// and report path: the fire rules overflow on every event, the quiet
// rules never do.

// benchCache is a map-backed TrackerCache double: per-key accumulate
// without recording (the recording double lives in evaluation_test.go).
type benchCache struct{ records map[string]bandage.Record }

func newBenchCache() *benchCache {
	return &benchCache{records: make(map[string]bandage.Record)}
}

func (c *benchCache) Update(_ context.Context, ns, key string, _ time.Duration, fn func(*bandage.Record)) (bandage.Record, error) {
	full := ns + bandage.KeySep + key
	r := c.records[full]
	fn(&r)
	c.records[full] = r
	return r, nil
}

// benchSink is a counting ReportSink double.
type benchSink struct{ triggers int }

func (s *benchSink) Trigger(context.Context, bandage.Report) error {
	s.triggers++
	return nil
}

// benchMatcher stands in for the filter tree this module cannot import:
// one prefix comparison per rule.
type benchMatcher struct{ prefix string }

func (m benchMatcher) Match(ev *bandage.Event) bool { return strings.HasPrefix(ev.Path, m.prefix) }

// benchEvents builds the pre-parsed event pool: n events cycling 256
// target keys, the domain-lint-safe stand-in for the internal/bench
// corpus. Timestamps come from benchEvent, which places event i at the
// i-th second of the fixture epoch.
func benchEvents(n int) []bandage.Event {
	events := make([]bandage.Event, n)
	for i := range events {
		events[i] = bandage.Event{
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

// benchEvent returns pool event i with its timestamp at the i-th second
// of the fixture epoch. Evaluation time must march forward per op:
// cycling timestamps would freeze the leaky bucket's LastUpdate and
// let the quiet rules' value creep past their volume. The same step
// drives the benchmark loop and its fixture test.
func benchEvent(events []bandage.Event, i int) bandage.Event {
	ev := events[i%len(events)]
	ev.Time = benchEpoch.Add(time.Duration(i) * time.Second)
	return ev
}

// benchChains mirrors configs/rules.yml's tracker rules with report
// actions, one rule per chain: a report rule is terminal, so a
// single-rule chain keeps the fires/never-fires paths doing identical
// filter and tracker work and differing only in the report action.
// The fire variant uses rate trackers with volume 0.5 — one request per
// event always overflows, so every event runs the report action. The
// quiet variant (leak 10, volume 200) decays at 10/s against the +1
// increment and, at benchEvent's one-second event spacing, never
// overflows. TestBenchChainsFireAsNamed pins both behaviors.
func benchChains(fire bool) []bandage.Chain {
	leak, volume := 10.0, 200.0
	if fire {
		leak, volume = 0, 0.5
	}
	rate := func(id string) bandage.Rule {
		return bandage.Rule{
			ID:     id,
			Filter: benchMatcher{prefix: "/"},
			Tracker: &bandage.TrackerConfig{
				Kind:         bandage.TrackRate,
				Leak:         leak,
				Volume:       volume,
				TTL:          bandage.TTL(leak, volume),
				TargetPrefix: bandage.DefaultTargetPrefix,
			},
			Actions: []bandage.Action{{Report: &bandage.ReportAction{Reason: id + "-overflow", TTL: time.Hour}}},
		}
	}
	return []bandage.Chain{
		{Name: "download-abuse", Rules: []bandage.Rule{rate("sustained-egress")}},
		{Name: "flood", Rules: []bandage.Rule{rate("rapid-requests")}},
		{Name: "scanning", Rules: []bandage.Rule{rate("probe-paths")}},
	}
}

// benchEpoch is the fixture event-time origin; benchNow is the fixed
// wall clock report timestamps run on.
var benchEpoch = time.Unix(1734345934, 0).UTC()

func benchNow() time.Time { return benchEpoch }

// TestBenchChainsFireAsNamed verifies the benchmark fixture's scenario
// split (the H4 measurements rest on it): the fire chains trigger on
// every event and the quiet chains trigger none, over repeated passes
// of the event pool.
func TestBenchChainsFireAsNamed(t *testing.T) {
	tests := []struct {
		name     string
		fire     bool
		perEvent int // report triggers per event: one per single-rule chain
	}{
		{"fires", true, 3},
		{"never-fires", false, 0},
	}
	events := benchEvents(1024)
	const passes = 10
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink := &benchSink{}
			svc := NewService(benchChains(tt.fire), newBenchCache(), sink, benchNow, nil)
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
		name string
		fire bool
	}{{"fires", true}, {"never-fires", false}} {
		b.Run(tc.name, func(b *testing.B) {
			svc := NewService(benchChains(tc.fire), newBenchCache(), &benchSink{}, benchNow, nil)
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
			// One op is one event, i.e. one log line (the shared
			// bench helper is unreachable under the domain lint).
			b.ReportMetric(float64(lines)/b.Elapsed().Seconds(), "lines/s")
		})
	}
}
