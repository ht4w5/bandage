package splint

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// Primary seam: the update cycle driven against a fake report endpoint
// (httptest) and observed at the firewall-driver boundary (the Stub):
// given a report document, which ban rules are installed and when.
// The report document's canonical example is the base fixture; every
// validation gets a failing and a passing case.

// docServer is the fake report endpoint: it serves the scripted
// responses in order (the last one sticks), so every cycle's answer is
// fixed before the loop starts.
type docServer struct {
	*httptest.Server
	mu  sync.Mutex
	res []docResponse
	i   int
}

type docResponse struct {
	status int
	body   string
}

func newDocServer(t *testing.T) *docServer {
	t.Helper()
	return newDocServerTLS(t, nil)
}

// newDocServerTLS starts the fake report endpoint as HTTPS with tlsCfg
// (mutual TLS when it requires client certificates); a nil config keeps
// the plain-HTTP endpoint.
func newDocServerTLS(t *testing.T, tlsCfg *tls.Config) *docServer {
	t.Helper()
	s := &docServer{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		r := docResponse{status: http.StatusInternalServerError}
		if len(s.res) > 0 {
			j := min(s.i, len(s.res)-1)
			s.i++
			r = s.res[j]
		}
		w.WriteHeader(r.status)
		io.WriteString(w, r.body) // error ignored: tests assert the outcome
	}))
	if tlsCfg != nil {
		srv.TLS = tlsCfg
		srv.StartTLS()
	} else {
		srv.Start()
	}
	s.Server = srv
	t.Cleanup(s.Close)
	return s
}

// serve scripts the next response; the last scripted response sticks
// for every later request.
func (s *docServer) serve(status int, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.res = append(s.res, docResponse{status, body})
}

// logCapture is the concurrency-safe sink the seam's logs land in.
type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *logCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *logCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// canonicalDoc extracts the report document's canonical example from
// docs/reports.md (its first fenced ```json block), so the published
// contract and its consumer cannot drift.
func canonicalDoc(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../docs/reports.md")
	if err != nil {
		t.Fatalf("read docs/reports.md: %v", err)
	}
	fenceOpen, fenceEnd := []byte("```json\n"), []byte("\n```")
	i := bytes.Index(data, fenceOpen)
	if i < 0 {
		t.Fatalf("docs/reports.md: no fenced ```json block (the first one is the canonical example)")
	}
	rest := data[i+len(fenceOpen):]
	j := bytes.Index(rest, fenceEnd)
	if j <= 0 {
		t.Fatalf("docs/reports.md: no non-empty fenced ```json block")
	}
	return string(rest[:j])
}

// fixture builds a document body from the canonical example: it decodes
// the example into a generic form, lets mutate change it and re-encodes.
// Every fixture therefore descends from the published example.
func fixture(t *testing.T, mutate func(t *testing.T, doc map[string]any)) string {
	t.Helper()
	doc := decodeFixture(t, canonicalDoc(t))
	if mutate != nil {
		mutate(t, doc)
	}
	return encodeFixture(t, doc)
}

func decodeFixture(t *testing.T, body string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(body))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return doc
}

func encodeFixture(t *testing.T, doc map[string]any) string {
	t.Helper()
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encode fixture: %v", err)
	}
	return string(data)
}

// record returns the i-th report record of a decoded fixture document.
func record(t *testing.T, doc map[string]any, i int) map[string]any {
	t.Helper()
	reports, ok := doc["reports"].([]any)
	if !ok || i >= len(reports) {
		t.Fatalf("fixture document has no report record %d", i)
	}
	rec, ok := reports[i].(map[string]any)
	if !ok {
		t.Fatalf("fixture report record %d is not an object", i)
	}
	return rec
}

// penalty returns the penalty object of a decoded fixture record.
func penalty(t *testing.T, rec map[string]any) map[string]any {
	t.Helper()
	p, ok := rec["penalty"].(map[string]any)
	if !ok {
		t.Fatalf("fixture report record has no penalty object")
	}
	return p
}

// cloneRecord deep-copies a decoded fixture record via a JSON round trip.
func cloneRecord(t *testing.T, rec map[string]any) map[string]any {
	t.Helper()
	return decodeFixture(t, encodeFixture(t, rec))
}

// banRule is a compiled ban rule expectation: the stance, its rate
// (nil for stances that carry none) over the given Targets.
func banRule(stance Stance, rate *int64, targets ...string) BanRule {
	r := BanRule{Stance: stance, Rate: rate}
	for _, target := range targets {
		r.Targets = append(r.Targets, netip.MustParsePrefix(target))
	}
	return r
}

// ratePtr points at a penalty rate fixture.
func ratePtr(n int64) *int64 { return &n }

// dropRule is the silent-drop ban rule.
func dropRule(targets ...string) BanRule {
	return banRule(StanceDrop, nil, targets...)
}

// mustPrefixes parses prefix literals for test policies.
func mustPrefixes(t *testing.T, prefixes ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, s := range prefixes {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// newTestUpdater wires the seam under the default compilation policy:
// a real fetcher against the fake report endpoint, the recording stub
// driver and a capturing logger.
func newTestUpdater(t *testing.T, srv *docServer) (*Updater, *Stub, *logCapture) {
	t.Helper()
	return newTestUpdaterCfg(t, srv, defaultPolicy())
}

// newTestUpdaterCfg wires the seam under a specific compilation
// policy, for the cases that configure exclusions or the prefilter.
func newTestUpdaterCfg(t *testing.T, srv *docServer, p Policy) (*Updater, *Stub, *logCapture) {
	t.Helper()
	fetcher, err := NewFetcher(srv.URL)
	if err != nil {
		t.Fatalf("NewFetcher: %v", err)
	}
	stub := &Stub{}
	logs := &logCapture{}
	return New(fetcher, stub, p, DefaultInterval, zerolog.New(logs)), stub, logs
}

// The default compilation policy: the safety exclusions with the
// RFC1918 and ULA tier on (the shipped --exclude-private default) and
// an empty service prefilter (all traffic is service traffic).
func defaultPolicy() Policy {
	return NewPolicy(nil, true, Prefilter{})
}

// assertInstalls checks which ban rules the stub driver was asked to
// install: want is the ruleset of exactly one install call; a refused
// cycle passes nil and asserts nothing was installed. want may be an
// empty (non-nil) slice for a cycle that installs an empty ruleset.
func assertInstalls(t *testing.T, stub *Stub, want []BanRule) {
	t.Helper()
	calls := stub.InstallCalls()
	if want == nil {
		if len(calls) != 0 {
			t.Errorf("installed %d rulesets, want none", len(calls))
		}
		return
	}
	if len(calls) != 1 {
		t.Fatalf("installed %d rulesets, want 1", len(calls))
	}
	if !equalRules(calls[0], want) {
		t.Errorf("installed ban rules = %v, want %v", calls[0], want)
	}
}

func equalRules(got, want []BanRule) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if !slices.Equal(got[i].Targets, want[i].Targets) ||
			!slices.Equal(got[i].Prefilter.DstPorts, want[i].Prefilter.DstPorts) ||
			!slices.Equal(got[i].Prefilter.DstAddrs, want[i].Prefilter.DstAddrs) ||
			got[i].Stance != want[i].Stance ||
			!equalRate(got[i].Rate, want[i].Rate) {
			return false
		}
	}
	return true
}

// equalRate compares two penalty rates: both absent or both present
// with the same value.
func equalRate(got, want *int64) bool {
	if got == nil || want == nil {
		return got == want
	}
	return *got == *want
}

// TestUpdateCycleCompilesTheCanonicalExample: the base fixture — the
// report document's canonical example — maps its one report's penalty
// (limit-bandwidth, rate 1000000) onto the bandwidth ban rule.
func TestUpdateCycleCompilesTheCanonicalExample(t *testing.T) {
	srv := newDocServer(t)
	srv.serve(http.StatusOK, canonicalDoc(t))
	u, stub, _ := newTestUpdater(t, srv)

	skips, err := u.Update(context.Background())
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if len(skips) != 0 {
		t.Errorf("skipped %d report records, want 0", len(skips))
	}
	assertInstalls(t, stub, []BanRule{banRule(StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")})
}

// TestUpdateCycleValidations drives one update cycle per fixture
// document, derived from the canonical example: every validation gets a
// failing and a passing case. A non-empty wantErr refuses the cycle
// (nothing installs); otherwise one ruleset installs and wantSkipped
// records are counted out.
func TestUpdateCycleValidations(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(t *testing.T, doc map[string]any)
		body        string // overrides the fixture document when non-empty
		wantErr     string
		wantRules   []BanRule
		wantSkipped int
	}{
		{
			name:    "an unknown document version refuses the cycle",
			mutate:  func(t *testing.T, doc map[string]any) { doc["version"] = json.Number("1") },
			wantErr: "version",
		},
		{
			name:      "document version 0 compiles its records",
			wantRules: []BanRule{banRule(StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")},
		},
		{
			name: "unknown document fields are ignored",
			mutate: func(t *testing.T, doc map[string]any) {
				doc["future_envelope_field"] = true
				rec := record(t, doc, 0)
				rec["future_record_field"] = 42
				penalty(t, rec)["future_penalty_field"] = "x"
			},
			wantRules: []BanRule{banRule(StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")},
		},
		{
			name:    "a malformed document body refuses the cycle",
			body:    "{not json",
			wantErr: "parse",
		},
		{
			name: "a record without a penalty is skipped",
			mutate: func(t *testing.T, doc map[string]any) {
				delete(record(t, doc, 0), "penalty")
			},
			wantRules:   []BanRule{},
			wantSkipped: 1,
		},
		{
			name: "a record with a valid penalty compiles",
			mutate: func(t *testing.T, doc map[string]any) {
				p := penalty(t, record(t, doc, 0))
				p["action"] = string(PenaltyReject)
				delete(p, "rate")
			},
			wantRules: []BanRule{banRule(StanceReject, nil, "203.0.113.7/32")},
		},
		{
			name: "a record with an unknown penalty action is skipped",
			mutate: func(t *testing.T, doc map[string]any) {
				penalty(t, record(t, doc, 0))["action"] = "throttle"
			},
			wantRules:   []BanRule{},
			wantSkipped: 1,
		},
		{
			name: "a record with a known penalty action compiles",
			mutate: func(t *testing.T, doc map[string]any) {
				penalty(t, record(t, doc, 0))["action"] = string(PenaltyLimitPktRate)
			},
			wantRules: []BanRule{banRule(StanceLimitPktRate, ratePtr(1000000), "203.0.113.7/32")},
		},
		{
			name: "a limit penalty without its rate is skipped",
			mutate: func(t *testing.T, doc map[string]any) {
				delete(penalty(t, record(t, doc, 0)), "rate")
			},
			wantRules:   []BanRule{},
			wantSkipped: 1,
		},
		{
			name: "a penalty rate below one is skipped",
			mutate: func(t *testing.T, doc map[string]any) {
				penalty(t, record(t, doc, 0))["rate"] = json.Number("0")
			},
			wantRules:   []BanRule{},
			wantSkipped: 1,
		},
		{
			name: "a limit penalty with its rate compiles",
			mutate: func(t *testing.T, doc map[string]any) {
				penalty(t, record(t, doc, 0))["rate"] = json.Number("500000")
			},
			wantRules: []BanRule{banRule(StanceLimitBandwidth, ratePtr(500000), "203.0.113.7/32")},
		},
		{
			name: "a rate on a non-limit penalty is skipped",
			mutate: func(t *testing.T, doc map[string]any) {
				penalty(t, record(t, doc, 0))["action"] = string(PenaltyDrop)
			},
			wantRules:   []BanRule{},
			wantSkipped: 1,
		},
		{
			name: "a non-limit penalty without its rate compiles",
			mutate: func(t *testing.T, doc map[string]any) {
				p := penalty(t, record(t, doc, 0))
				p["action"] = string(PenaltyDrop)
				delete(p, "rate")
			},
			wantRules: []BanRule{banRule(StanceDrop, nil, "203.0.113.7/32")},
		},
		{
			name: "a record with an unparseable Target is skipped",
			mutate: func(t *testing.T, doc map[string]any) {
				record(t, doc, 0)["target"] = "not-a-prefix"
			},
			wantRules:   []BanRule{},
			wantSkipped: 1,
		},
		{
			name: "a record with a parseable Target compiles",
			mutate: func(t *testing.T, doc map[string]any) {
				record(t, doc, 0)["target"] = "203.0.113.7/24"
			},
			wantRules: []BanRule{banRule(StanceLimitBandwidth, ratePtr(1000000), "203.0.113.0/24")},
		},
		{
			name: "invalid records are skipped while the rest compile",
			mutate: func(t *testing.T, doc map[string]any) {
				rec := record(t, doc, 0)
				badTarget := cloneRecord(t, rec)
				badTarget["target"] = "not-a-prefix"
				noPenalty := cloneRecord(t, rec)
				delete(noPenalty, "penalty")
				doc["reports"] = []any{rec, badTarget, noPenalty}
			},
			wantRules:   []BanRule{banRule(StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")},
			wantSkipped: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newDocServer(t)
			body := fixture(t, tt.mutate)
			if tt.body != "" {
				body = tt.body
			}
			srv.serve(http.StatusOK, body)
			u, stub, _ := newTestUpdater(t, srv)

			skips, err := u.Update(context.Background())
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("Update succeeded, want error containing %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Update error %q does not contain %q", err, tt.wantErr)
				}
				assertInstalls(t, stub, nil)
				return
			}
			if err != nil {
				t.Fatalf("Update: %v", err)
			}
			if len(skips) != tt.wantSkipped {
				t.Errorf("skipped %d report records, want %d", len(skips), tt.wantSkipped)
			}
			assertInstalls(t, stub, tt.wantRules)
		})
	}
}

// TestUpdateCyclePenaltyMapping: every penalty action maps onto the
// stance the contract defines — the mapping is total over the closed
// vocabulary — with a failing and a passing case per action.
// limit-req-rate is deliberately not applied (ADR 0011): its passing
// case is the skip itself, logged and counted, with nothing installed.
func TestUpdateCyclePenaltyMapping(t *testing.T) {
	tests := []struct {
		name        string
		action      PenaltyAction
		rate        any // nil deletes the penalty's rate
		wantRules   []BanRule
		wantSkipped int
		wantSkipHas string
		wantLogs    []string
	}{
		{
			name:      "drop is applied as a silent drop",
			action:    PenaltyDrop,
			wantRules: []BanRule{dropRule("203.0.113.7/32")},
		},
		{
			name:        "a rate on drop is not applied and is skipped",
			action:      PenaltyDrop,
			rate:        json.Number("100"),
			wantRules:   []BanRule{},
			wantSkipped: 1,
		},
		{
			name:      "reject is applied as a reject",
			action:    PenaltyReject,
			wantRules: []BanRule{banRule(StanceReject, nil, "203.0.113.7/32")},
		},
		{
			name:        "a rate on reject is not applied and is skipped",
			action:      PenaltyReject,
			rate:        json.Number("100"),
			wantRules:   []BanRule{},
			wantSkipped: 1,
		},
		{
			name:      "limit-pkt-rate throttles packets to its rate",
			action:    PenaltyLimitPktRate,
			rate:      json.Number("250"),
			wantRules: []BanRule{banRule(StanceLimitPktRate, ratePtr(250), "203.0.113.7/32")},
		},
		{
			name:        "limit-pkt-rate without its rate is skipped",
			action:      PenaltyLimitPktRate,
			wantRules:   []BanRule{},
			wantSkipped: 1,
		},
		{
			name:      "limit-bandwidth throttles response bytes to its rate",
			action:    PenaltyLimitBandwidth,
			rate:      json.Number("500000"),
			wantRules: []BanRule{banRule(StanceLimitBandwidth, ratePtr(500000), "203.0.113.7/32")},
		},
		{
			name:        "limit-bandwidth without its rate is skipped",
			action:      PenaltyLimitBandwidth,
			wantRules:   []BanRule{},
			wantSkipped: 1,
		},
		{
			name:        "limit-req-rate is skipped, logged and counted",
			action:      PenaltyLimitReqRate,
			rate:        json.Number("300"),
			wantRules:   []BanRule{},
			wantSkipped: 1,
			wantSkipHas: "not applied",
			wantLogs:    []string{"skipped report record", `"skipped":1`},
		},
		{
			name:        "limit-req-rate without its rate is skipped too",
			action:      PenaltyLimitReqRate,
			wantRules:   []BanRule{},
			wantSkipped: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newDocServer(t)
			srv.serve(http.StatusOK, fixture(t, func(t *testing.T, doc map[string]any) {
				p := penalty(t, record(t, doc, 0))
				p["action"] = string(tt.action)
				if tt.rate == nil {
					delete(p, "rate")
				} else {
					p["rate"] = tt.rate
				}
			}))
			u, stub, logs := newTestUpdater(t, srv)

			skips, err := u.Update(context.Background())
			if err != nil {
				t.Fatalf("Update: %v", err)
			}
			if len(skips) != tt.wantSkipped {
				t.Fatalf("skipped %d report records, want %d", len(skips), tt.wantSkipped)
			}
			if tt.wantSkipHas != "" && !strings.Contains(skips[0].Reason, tt.wantSkipHas) {
				t.Errorf("skip reason %q does not contain %q", skips[0].Reason, tt.wantSkipHas)
			}
			for _, want := range tt.wantLogs {
				if !strings.Contains(logs.String(), want) {
					t.Errorf("logs do not contain %q: %s", want, logs.String())
				}
			}
			assertInstalls(t, stub, tt.wantRules)
		})
	}
}

// TestUpdateCycleLogsAndCountsSkippedRecords: every skipped record is
// logged with its identity and reason, and the cycle's summary counts
// the skips.
func TestUpdateCycleLogsAndCountsSkippedRecords(t *testing.T) {
	srv := newDocServer(t)
	srv.serve(http.StatusOK, fixture(t, func(t *testing.T, doc map[string]any) {
		rec := record(t, doc, 0)
		badTarget := cloneRecord(t, rec)
		badTarget["target"] = "not-a-prefix"
		noPenalty := cloneRecord(t, rec)
		delete(noPenalty, "penalty")
		doc["reports"] = []any{rec, badTarget, noPenalty}
	}))
	u, stub, logs := newTestUpdater(t, srv)

	skips, err := u.Update(context.Background())
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	assertInstalls(t, stub, []BanRule{banRule(StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")})

	if len(skips) != 2 {
		t.Fatalf("skipped %d report records, want 2", len(skips))
	}
	if skips[0].Target != "not-a-prefix" || skips[0].Reason == "" {
		t.Errorf("skips[0] = %+v, want the unparseable Target with a reason", skips[0])
	}
	if skips[1].Target != "203.0.113.7/32" || skips[1].Reason == "" {
		t.Errorf("skips[1] = %+v, want the missing-penalty record with a reason", skips[1])
	}
	logText := logs.String()
	if n := strings.Count(logText, "skipped report record"); n != 2 {
		t.Errorf("logged %d skip records, want 2: %s", n, logText)
	}
	if !strings.Contains(logText, `"skipped":2`) {
		t.Errorf("cycle summary does not count the skips: %s", logText)
	}
}

// TestUpdateCycleSubtractsExclusions: excluded prefixes are
// subtracted from every ban set, overriding every report — a fully
// covered Target produces no ban rule, a partially covered one keeps
// only its residual prefixes.
func TestUpdateCycleSubtractsExclusions(t *testing.T) {
	tests := []struct {
		name        string
		exclude     []string
		target      string
		wantRules   []BanRule
		wantSkipped int
	}{
		{
			name:        "an exclusion covering the whole Target produces no ban rule",
			exclude:     []string{"203.0.113.7/32"},
			target:      "203.0.113.7/32",
			wantRules:   []BanRule{},
			wantSkipped: 1,
		},
		{
			name:      "an exclusion disjoint from the Target leaves it untouched",
			exclude:   []string{"198.51.100.0/24"},
			target:    "203.0.113.7/32",
			wantRules: []BanRule{banRule(StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")},
		},
		{
			name:      "an exclusion covering part of the Target leaves its residual prefixes",
			exclude:   []string{"203.0.113.0/25"},
			target:    "203.0.113.0/24",
			wantRules: []BanRule{banRule(StanceLimitBandwidth, ratePtr(1000000), "203.0.113.128/25")},
		},
		{
			name:      "several exclusions each subtract from the Target",
			exclude:   []string{"203.0.113.0/25", "203.0.113.192/26"},
			target:    "203.0.113.0/24",
			wantRules: []BanRule{banRule(StanceLimitBandwidth, ratePtr(1000000), "203.0.113.128/26")},
		},
		{
			name:      "an exclusion covering part of an IPv6 Target leaves its residual prefixes",
			exclude:   []string{"2001:db8::/33"},
			target:    "2001:db8::/32",
			wantRules: []BanRule{banRule(StanceLimitBandwidth, ratePtr(1000000), "2001:db8:8000::/33")},
		},
		{
			name:      "an exclusion inside the Target splits it into residual prefixes",
			exclude:   []string{"203.0.113.64/26"},
			target:    "203.0.113.0/24",
			wantRules: []BanRule{banRule(StanceLimitBandwidth, ratePtr(1000000), "203.0.113.0/26", "203.0.113.128/25")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newDocServer(t)
			srv.serve(http.StatusOK, fixture(t, func(t *testing.T, doc map[string]any) {
				record(t, doc, 0)["target"] = tt.target
			}))
			u, stub, _ := newTestUpdaterCfg(t, srv, Policy{Exclude: mustPrefixes(t, tt.exclude...)})

			skips, err := u.Update(context.Background())
			if err != nil {
				t.Fatalf("Update: %v", err)
			}
			if len(skips) != tt.wantSkipped {
				t.Errorf("skipped %d report records, want %d", len(skips), tt.wantSkipped)
			}
			assertInstalls(t, stub, tt.wantRules)
		})
	}
}

// TestUpdateCycleSafetyExclusions: the safety exclusions — loopback
// and link-local are always excluded and cannot be re-included, and
// RFC1918 and ULA are excluded by default behind the --exclude-private
// opt-out, for hosts whose clients live in private space.
func TestUpdateCycleSafetyExclusions(t *testing.T) {
	tests := []struct {
		name   string
		policy Policy
		target string
		wantOK bool // true: the Target compiles to a ban rule
	}{
		{"a loopback Target is excluded and cannot be re-included", NewPolicy(nil, false, Prefilter{}), "127.0.0.1/32", false},
		{"the IPv6 loopback Target is excluded and cannot be re-included", NewPolicy(nil, false, Prefilter{}), "::1/128", false},
		{"a link-local Target is excluded and cannot be re-included", NewPolicy(nil, false, Prefilter{}), "169.254.5.6/32", false},
		{"the IPv6 link-local Target is excluded and cannot be re-included", NewPolicy(nil, false, Prefilter{}), "fe80::1/128", false},
		{"a public Target compiles under the safety exclusions", NewPolicy(nil, true, Prefilter{}), "203.0.113.7/32", true},
		{"an RFC1918 Target is excluded by default", NewPolicy(nil, true, Prefilter{}), "10.1.2.3/32", false},
		{"a ULA Target is excluded by default", NewPolicy(nil, true, Prefilter{}), "fd00::1/128", false},
		{"a private Target compiles when the default exclusions are opted out", NewPolicy(nil, false, Prefilter{}), "10.1.2.3/32", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newDocServer(t)
			srv.serve(http.StatusOK, fixture(t, func(t *testing.T, doc map[string]any) {
				record(t, doc, 0)["target"] = tt.target
			}))
			u, stub, _ := newTestUpdaterCfg(t, srv, tt.policy)

			skips, err := u.Update(context.Background())
			if err != nil {
				t.Fatalf("Update: %v", err)
			}
			if tt.wantOK {
				if len(skips) != 0 {
					t.Errorf("skipped %d report records, want 0", len(skips))
				}
				assertInstalls(t, stub, []BanRule{banRule(StanceLimitBandwidth, ratePtr(1000000), tt.target)})
				return
			}
			if len(skips) != 1 {
				t.Errorf("skipped %d report records, want 1", len(skips))
			}
			assertInstalls(t, stub, []BanRule{})
		})
	}
}

// TestUpdateCycleConstructsTheServicePrefilter: every ban rule leads
// with the service prefilter — the destination-port and
// destination-address sets of the protected service. Either set may
// be empty, meaning all; both are operator configuration.
func TestUpdateCycleConstructsTheServicePrefilter(t *testing.T) {
	tests := []struct {
		name      string
		prefilter Prefilter
	}{
		{
			name:      "a ban rule carries the configured destination-port set",
			prefilter: Prefilter{DstPorts: []uint16{53, 80, 443}},
		},
		{
			name: "a ban rule carries an empty destination-port set when none is configured",
		},
		{
			name:      "a ban rule carries the configured destination-address set",
			prefilter: Prefilter{DstAddrs: mustPrefixes(t, "203.0.113.5/32", "2001:db8::5/128")},
		},
		{
			name: "a ban rule carries an empty destination-address set when none is configured",
		},
		{
			name:      "a ban rule carries both prefilter sets",
			prefilter: Prefilter{DstPorts: []uint16{443}, DstAddrs: mustPrefixes(t, "203.0.113.5/32")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newDocServer(t)
			srv.serve(http.StatusOK, canonicalDoc(t))
			u, stub, _ := newTestUpdaterCfg(t, srv, NewPolicy(nil, true, tt.prefilter))

			if _, err := u.Update(context.Background()); err != nil {
				t.Fatalf("Update: %v", err)
			}
			want := []BanRule{{
				Targets:   mustPrefixes(t, "203.0.113.7/32"),
				Prefilter: tt.prefilter,
				Stance:    StanceLimitBandwidth,
				Rate:      ratePtr(1000000),
			}}
			assertInstalls(t, stub, want)
		})
	}
}

// TestUpdateKeepsTheLastInstalledRules: a failed cycle installs nothing
// and leaves the last installed rules in place.
func TestUpdateKeepsTheLastInstalledRules(t *testing.T) {
	keepLast := func(t *testing.T, status int, body string) {
		t.Helper()
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		srv.serve(status, body)
		u, stub, _ := newTestUpdater(t, srv)
		if _, err := u.Update(context.Background()); err != nil {
			t.Fatalf("first Update: %v", err)
		}
		if _, err := u.Update(context.Background()); err == nil {
			t.Fatal("second Update succeeded, want an error")
		}
		assertInstalls(t, stub, []BanRule{banRule(StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")})
		if stub.ResetCalls() != 0 {
			t.Errorf("Reset ran %d times, want 0", stub.ResetCalls())
		}
	}

	t.Run("a failed fetch keeps the last installed rules", func(t *testing.T) {
		keepLast(t, http.StatusInternalServerError, "")
	})
	t.Run("an unknown document version on a later cycle keeps the last installed rules", func(t *testing.T) {
		keepLast(t, http.StatusOK, fixture(t, func(t *testing.T, doc map[string]any) {
			doc["version"] = json.Number("1")
		}))
	})
}

// TestUpdateFailsLoudlyWhenTheDriverRefusesTheInstall: an install
// failure is a loud cycle error — the surface a
// missing-netlink-privileges install takes — and fatal at the startup
// test install, all stub-driven and unprivileged.
func TestUpdateFailsLoudlyWhenTheDriverRefusesTheInstall(t *testing.T) {
	t.Run("a refused install fails the cycle", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		u, stub, _ := newTestUpdater(t, srv)
		stub.InstallErr = errors.New("netlink: permission denied")

		if _, err := u.Update(context.Background()); err == nil || !strings.Contains(err.Error(), "install") {
			t.Fatalf("Update error = %v, want an install failure", err)
		}
		assertInstalls(t, stub, nil)
	})

	t.Run("a refused install at startup exits with an error", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		u, stub, _ := newTestUpdater(t, srv)
		stub.InstallErr = errors.New("netlink: permission denied")

		err := u.Run(context.Background())
		if err == nil || !strings.Contains(err.Error(), "startup test install") {
			t.Fatalf("Run error = %v, want a startup test install failure", err)
		}
		if stub.ResetCalls() != 1 {
			t.Errorf("Reset ran %d times, want 1 (reset before exiting non-zero)", stub.ResetCalls())
		}
	})
}

// TestUpdaterRun drives the update loop's lifecycle at the same seam:
// a failed startup test install is fatal, later failures keep the last
// rules with a loud log and the loop goes on, and cancelling the
// context resets the driver before exit.
func TestUpdaterRun(t *testing.T) {
	t.Run("a failed startup test install exits with an error", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusInternalServerError, "")
		u, stub, _ := newTestUpdater(t, srv)

		err := u.Run(context.Background())
		if err == nil || !strings.Contains(err.Error(), "startup test install") {
			t.Fatalf("Run error = %v, want a startup test install failure", err)
		}
		assertInstalls(t, stub, nil)
		if stub.ResetCalls() != 1 {
			t.Errorf("Reset ran %d times, want 1 (reset before exiting non-zero)", stub.ResetCalls())
		}
	})

	t.Run("the loop keeps the last rules and continues after a failed cycle", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		srv.serve(http.StatusInternalServerError, "")
		srv.serve(http.StatusOK, fixture(t, func(t *testing.T, doc map[string]any) {
			record(t, doc, 0)["target"] = "198.51.100.9/32"
		}))
		srv.serve(http.StatusInternalServerError, "")
		u, stub, logs := newTestUpdater(t, srv)
		ticks := make(chan time.Time)
		u.ticks = ticks
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		runDone := make(chan error, 1)
		go func() { runDone <- u.Run(ctx) }()

		sendTick(t, ticks, runDone) // cycle: failed fetch
		sendTick(t, ticks, runDone) // cycle: new rules install
		sendTick(t, ticks, runDone) // completes the previous cycle; starts one that fails either way
		cancel()
		if err := <-runDone; err != nil {
			t.Fatalf("Run: %v", err)
		}

		calls := stub.InstallCalls()
		want := [][]BanRule{
			{banRule(StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")},
			{banRule(StanceLimitBandwidth, ratePtr(1000000), "198.51.100.9/32")},
		}
		if len(calls) != len(want) {
			t.Fatalf("installed %d rulesets, want %d", len(calls), len(want))
		}
		for i := range want {
			if !equalRules(calls[i], want[i]) {
				t.Errorf("install call %d = %v, want %v", i, calls[i], want[i])
			}
		}
		if stub.ResetCalls() != 1 {
			t.Errorf("Reset ran %d times, want 1", stub.ResetCalls())
		}
		if n := strings.Count(logs.String(), "update failed; keeping last installed rules"); n != 2 {
			t.Errorf("logged %d keep-last warnings, want 2: %s", n, logs.String())
		}
	})

	t.Run("cancelling the context resets before exit", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		// The ticked cycle gets the scripted failure however the
		// cancellation race falls, so nothing more installs.
		srv.serve(http.StatusInternalServerError, "")
		u, stub, _ := newTestUpdater(t, srv)
		ticks := make(chan time.Time)
		u.ticks = ticks
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		runDone := make(chan error, 1)
		go func() { runDone <- u.Run(ctx) }()

		// The tick proves the startup test install succeeded.
		sendTick(t, ticks, runDone)
		cancel()
		if err := <-runDone; err != nil {
			t.Fatalf("Run: %v", err)
		}
		if stub.ResetCalls() != 1 {
			t.Errorf("Reset ran %d times, want 1", stub.ResetCalls())
		}
	})
}

// sendTick delivers one tick to the update loop, failing the test if
// the loop exits instead. A send completes only once Run picks the tick
// up, so each send also proves the startup test install succeeded and
// every earlier cycle has finished.
func sendTick(t *testing.T, ticks chan<- time.Time, runDone <-chan error) {
	t.Helper()
	select {
	case ticks <- time.Time{}:
	case err := <-runDone:
		t.Fatalf("Run exited before the tick: %v", err)
	}
}

// TestDryRunPrintsTheCompiledBanRules: --dry-run prints the compiled
// ban rules and one mapping line per ban rule — stance, rate and chain,
// the penalty → nftables mapping — and installs nothing: no driver
// call, no netlink, no privileges.
func TestDryRunPrintsTheCompiledBanRules(t *testing.T) {
	t.Run("the canonical example prints its ban rule and one mapping line", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		u, stub, _ := newTestUpdater(t, srv)

		var out bytes.Buffer
		if err := u.DryRun(context.Background(), &out); err != nil {
			t.Fatalf("DryRun: %v", err)
		}
		want := `[
  {
    "targets": [
      "203.0.113.7/32"
    ],
    "prefilter": {
      "dst_ports": [],
      "dst_addrs": []
    },
    "stance": "limit-bandwidth",
    "rate": 1000000
  }
]
stance=limit-bandwidth rate=1000000 chain=egress
`
		if out.String() != want {
			t.Errorf("DryRun output = %q, want %q", out.String(), want)
		}
		assertInstalls(t, stub, nil)
	})

	t.Run("every ban rule prints one mapping line with its stance, rate and chain", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, fixture(t, func(t *testing.T, doc map[string]any) {
			rec := record(t, doc, 0)
			dropped := cloneRecord(t, rec)
			p := penalty(t, dropped)
			p["action"] = string(PenaltyDrop)
			delete(p, "rate")
			throttled := cloneRecord(t, rec)
			tp := penalty(t, throttled)
			tp["action"] = string(PenaltyLimitPktRate)
			tp["rate"] = json.Number("250")
			doc["reports"] = []any{rec, dropped, throttled}
		}))
		u, stub, _ := newTestUpdater(t, srv)

		var out bytes.Buffer
		if err := u.DryRun(context.Background(), &out); err != nil {
			t.Fatalf("DryRun: %v", err)
		}
		var mapping []string
		for _, line := range strings.Split(out.String(), "\n") {
			if strings.HasPrefix(line, "stance=") {
				mapping = append(mapping, line)
			}
		}
		want := []string{
			"stance=limit-bandwidth rate=1000000 chain=egress",
			"stance=drop rate=- chain=ingress",
			"stance=limit-pkt-rate rate=250 chain=ingress",
		}
		if !slices.Equal(mapping, want) {
			t.Errorf("mapping lines = %q, want %q", mapping, want)
		}
		assertInstalls(t, stub, nil)
	})
}

// TestDryRunShowsTheEffectiveSets: --dry-run shows each ban rule's
// effective sets after exclusion subtraction, leading with the service
// prefilter.
func TestDryRunShowsTheEffectiveSets(t *testing.T) {
	srv := newDocServer(t)
	srv.serve(http.StatusOK, fixture(t, func(t *testing.T, doc map[string]any) {
		record(t, doc, 0)["target"] = "203.0.113.0/24"
	}))
	u, stub, _ := newTestUpdaterCfg(t, srv, NewPolicy(
		mustPrefixes(t, "203.0.113.0/25"), true,
		Prefilter{DstPorts: []uint16{53, 443}, DstAddrs: mustPrefixes(t, "203.0.113.5/32")},
	))

	var out bytes.Buffer
	if err := u.DryRun(context.Background(), &out); err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	want := `[
  {
    "targets": [
      "203.0.113.128/25"
    ],
    "prefilter": {
      "dst_ports": [
        53,
        443
      ],
      "dst_addrs": [
        "203.0.113.5/32"
      ]
    },
    "stance": "limit-bandwidth",
    "rate": 1000000
  }
]
stance=limit-bandwidth rate=1000000 chain=egress
`
	if out.String() != want {
		t.Errorf("DryRun output = %q, want %q", out.String(), want)
	}
	assertInstalls(t, stub, nil)
}

// TestClampInterval: the update interval's one-minute floor, failing
// and passing case per validation.
func TestClampInterval(t *testing.T) {
	tests := []struct {
		name        string
		in          time.Duration
		want        time.Duration
		wantClamped bool
	}{
		{"an update interval below the floor is clamped", 30 * time.Second, time.Minute, true},
		{"an update interval at the floor is kept", time.Minute, time.Minute, false},
		{"an update interval above the floor is kept", DefaultInterval, DefaultInterval, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, clamped := ClampInterval(tt.in)
			if got != tt.want || clamped != tt.wantClamped {
				t.Errorf("ClampInterval(%v) = (%v, %v), want (%v, %v)", tt.in, got, clamped, tt.want, tt.wantClamped)
			}
		})
	}
}

// TestNewClampsTheIntervalLoudly: clamping warns the operator; a
// conforming interval is accepted silently.
func TestNewClampsTheIntervalLoudly(t *testing.T) {
	tests := []struct {
		name      string
		interval  time.Duration
		wantWarn  bool
		wantValue time.Duration
	}{
		{"an update interval below the floor is clamped with a warning", 30 * time.Second, true, time.Minute},
		{"an update interval above the floor is kept silently", DefaultInterval, false, DefaultInterval},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newDocServer(t)
			fetcher, err := NewFetcher(srv.URL)
			if err != nil {
				t.Fatalf("NewFetcher: %v", err)
			}
			logs := &logCapture{}
			u := New(fetcher, &Stub{}, defaultPolicy(), tt.interval, zerolog.New(logs))
			if u.interval != tt.wantValue {
				t.Errorf("interval = %v, want %v", u.interval, tt.wantValue)
			}
			warned := strings.Contains(logs.String(), "clamped to the one-minute floor")
			if warned != tt.wantWarn {
				t.Errorf("clamping warning logged = %v, want %v: %s", warned, tt.wantWarn, logs.String())
			}
		})
	}
}
