package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/HT4w5/webmedkit/splint/internal/domain"
	"github.com/HT4w5/webmedkit/splint/internal/firewall"
	"github.com/HT4w5/webmedkit/splint/internal/firewall/firewalltest"
)

// Primary seam: the update cycle driven against a fake report endpoint
// (httptest), observed at the firewall-driver boundary (the firewalltest.Stub).

// docServer is the fake report endpoint serving scripted responses;
// the last scripted response sticks for every later request.
type docServer struct {
	*httptest.Server
	mu   sync.Mutex
	res  []docResponse
	i    int
	hits int
}

type docResponse struct {
	status int
	body   string
}

func newDocServer(t *testing.T) *docServer {
	t.Helper()
	return newDocServerTLS(t, nil)
}

// newDocServerTLS starts the endpoint as HTTPS with tlsCfg (mutual TLS
// when it requires client certificates); nil keeps the plain-HTTP one.
func newDocServerTLS(t *testing.T, tlsCfg *tls.Config) *docServer {
	t.Helper()
	s := &docServer{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.hits++
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

func (s *docServer) serve(status int, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.res = append(s.res, docResponse{status, body})
}

func (s *docServer) Hits() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits
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

// canonicalDoc extracts the canonical example from docs/reports.md
// (its first fenced json block) so the contract and consumer cannot drift.
func canonicalDoc(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../../docs/reports.md")
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

// fixture builds a document body from the canonical example via a
// generic decode/mutate/encode — every fixture descends from it.
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

func report(t *testing.T, doc map[string]any, i int) map[string]any {
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

func penalty(t *testing.T, rec map[string]any) map[string]any {
	t.Helper()
	p, ok := rec["penalty"].(map[string]any)
	if !ok {
		t.Fatalf("fixture report record has no penalty object")
	}
	return p
}

func cloneReport(t *testing.T, rec map[string]any) map[string]any {
	t.Helper()
	return decodeFixture(t, encodeFixture(t, rec))
}

type reportSpec struct {
	target string
	action domain.PenaltyAction
	rate   any // json.Number for a limit; nil deletes the rate
}

// setReports replaces the reports with one record per spec, each cloned
// from the canonical example's record and retargeted.
func setReports(t *testing.T, doc map[string]any, specs []reportSpec) {
	t.Helper()
	var reports []any
	for _, spec := range specs {
		rec := cloneReport(t, report(t, doc, 0))
		rec["target"] = spec.target
		p := penalty(t, rec)
		p["action"] = string(spec.action)
		if spec.rate == nil {
			delete(p, "rate")
		} else {
			p["rate"] = spec.rate
		}
		reports = append(reports, rec)
	}
	doc["reports"] = reports
}

func banRule(stance firewall.Stance, rate *int64, targets ...string) firewall.BanRule {
	r := firewall.BanRule{Stance: stance, Rate: rate}
	for _, target := range targets {
		r.Targets = append(r.Targets, netip.MustParsePrefix(target))
	}
	return r
}

func ratePtr(n int64) *int64 { return &n }

func dropRule(targets ...string) firewall.BanRule {
	return banRule(firewall.StanceDrop, nil, targets...)
}

func mustPrefixes(t *testing.T, prefixes ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, s := range prefixes {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func newTestUpdater(t *testing.T, srv *docServer) (*Updater, *firewalltest.Stub, *logCapture) {
	t.Helper()
	return newTestUpdaterCfg(t, srv, defaultPolicy())
}

func newTestUpdaterCfg(t *testing.T, srv *docServer, p domain.Policy) (*Updater, *firewalltest.Stub, *logCapture) {
	t.Helper()
	fetcher, err := NewFetcher(srv.URL)
	if err != nil {
		t.Fatalf("NewFetcher: %v", err)
	}
	stub := &firewalltest.Stub{}
	logs := &logCapture{}
	u, err := New(fetcher, []firewall.Point{{Label: "current", Driver: stub}}, p, DefaultInterval, zerolog.New(logs))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return u, stub, logs
}

// defaultPolicy is the shipped default: the safety exclusions with the
// RFC1918 and ULA tier on (the --exclude-private default).
func defaultPolicy() domain.Policy {
	return domain.NewPolicy(nil, true)
}

// assertApplies asserts the ruleset of exactly one apply call; nil
// means nothing reached the driver, an empty slice an empty ruleset.
func assertApplies(t *testing.T, stub *firewalltest.Stub, want []firewall.BanRule) {
	t.Helper()
	calls := stub.ApplyCalls()
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

func equalRules(got, want []firewall.BanRule) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if !slices.Equal(got[i].Targets, want[i].Targets) ||
			got[i].Stance != want[i].Stance ||
			!equalRate(got[i].Rate, want[i].Rate) {
			return false
		}
	}
	return true
}

func equalRate(got, want *int64) bool {
	if got == nil || want == nil {
		return got == want
	}
	return *got == *want
}

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
	assertApplies(t, stub, []firewall.BanRule{banRule(firewall.StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")})
}

// Each case drives one update cycle: a non-empty wantErr refuses it,
// otherwise wantRules installs and wantSkipped records are counted out.
func TestUpdateCycleValidations(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(t *testing.T, doc map[string]any)
		body        string // overrides the fixture document when non-empty
		wantErr     string
		wantRules   []firewall.BanRule
		wantSkipped int
	}{
		{
			name:    "an unknown document version refuses the cycle",
			mutate:  func(t *testing.T, doc map[string]any) { doc["version"] = json.Number("1") },
			wantErr: "version",
		},
		{
			name:    "an envelope without a version refuses the cycle",
			mutate:  func(t *testing.T, doc map[string]any) { delete(doc, "version") },
			wantErr: "version: required",
		},
		{
			name:    "an envelope without generated_at refuses the cycle",
			mutate:  func(t *testing.T, doc map[string]any) { delete(doc, "generated_at") },
			wantErr: "generated_at: required",
		},
		{
			name:    "an envelope without reports refuses the cycle",
			mutate:  func(t *testing.T, doc map[string]any) { delete(doc, "reports") },
			wantErr: "reports: required",
		},
		{
			name:      "document version 0 compiles its reports",
			wantRules: []firewall.BanRule{banRule(firewall.StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")},
		},
		{
			name: "an envelope with an empty reports list compiles to an empty ruleset",
			mutate: func(t *testing.T, doc map[string]any) {
				doc["reports"] = []any{}
			},
			wantRules: []firewall.BanRule{},
		},
		{
			name: "unknown document fields are ignored",
			mutate: func(t *testing.T, doc map[string]any) {
				doc["future_envelope_field"] = true
				rec := report(t, doc, 0)
				rec["future_record_field"] = 42
				penalty(t, rec)["future_penalty_field"] = "x"
			},
			wantRules: []firewall.BanRule{banRule(firewall.StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")},
		},
		{
			name:    "a malformed document body refuses the cycle",
			body:    "{not json",
			wantErr: "parse",
		},
		{
			name: "a report without a penalty is skipped",
			mutate: func(t *testing.T, doc map[string]any) {
				delete(report(t, doc, 0), "penalty")
			},
			wantRules:   []firewall.BanRule{},
			wantSkipped: 1,
		},
		{
			name: "a report with a valid penalty compiles",
			mutate: func(t *testing.T, doc map[string]any) {
				p := penalty(t, report(t, doc, 0))
				p["action"] = string(domain.PenaltyReject)
				delete(p, "rate")
			},
			wantRules: []firewall.BanRule{banRule(firewall.StanceReject, nil, "203.0.113.7/32")},
		},
		{
			name: "a report with an unknown penalty action is skipped",
			mutate: func(t *testing.T, doc map[string]any) {
				penalty(t, report(t, doc, 0))["action"] = "throttle"
			},
			wantRules:   []firewall.BanRule{},
			wantSkipped: 1,
		},
		{
			name: "a report with a known penalty action compiles",
			mutate: func(t *testing.T, doc map[string]any) {
				penalty(t, report(t, doc, 0))["action"] = string(domain.PenaltyLimitPktRate)
			},
			wantRules: []firewall.BanRule{banRule(firewall.StanceLimitPktRate, ratePtr(1000000), "203.0.113.7/32")},
		},
		{
			name: "a limit penalty without its rate is skipped",
			mutate: func(t *testing.T, doc map[string]any) {
				delete(penalty(t, report(t, doc, 0)), "rate")
			},
			wantRules:   []firewall.BanRule{},
			wantSkipped: 1,
		},
		{
			name: "a penalty rate below one is skipped",
			mutate: func(t *testing.T, doc map[string]any) {
				penalty(t, report(t, doc, 0))["rate"] = json.Number("0")
			},
			wantRules:   []firewall.BanRule{},
			wantSkipped: 1,
		},
		{
			name: "a limit penalty with its rate compiles",
			mutate: func(t *testing.T, doc map[string]any) {
				penalty(t, report(t, doc, 0))["rate"] = json.Number("500000")
			},
			wantRules: []firewall.BanRule{banRule(firewall.StanceLimitBandwidth, ratePtr(500000), "203.0.113.7/32")},
		},
		{
			name: "a rate on a non-limit penalty is skipped",
			mutate: func(t *testing.T, doc map[string]any) {
				penalty(t, report(t, doc, 0))["action"] = string(domain.PenaltyDrop)
			},
			wantRules:   []firewall.BanRule{},
			wantSkipped: 1,
		},
		{
			name: "a non-limit penalty without its rate compiles",
			mutate: func(t *testing.T, doc map[string]any) {
				p := penalty(t, report(t, doc, 0))
				p["action"] = string(domain.PenaltyDrop)
				delete(p, "rate")
			},
			wantRules: []firewall.BanRule{banRule(firewall.StanceDrop, nil, "203.0.113.7/32")},
		},
		{
			name: "a report with an unparseable Target is skipped",
			mutate: func(t *testing.T, doc map[string]any) {
				report(t, doc, 0)["target"] = "not-a-prefix"
			},
			wantRules:   []firewall.BanRule{},
			wantSkipped: 1,
		},
		{
			name: "a report with a parseable Target compiles",
			mutate: func(t *testing.T, doc map[string]any) {
				report(t, doc, 0)["target"] = "203.0.113.7/24"
			},
			wantRules: []firewall.BanRule{banRule(firewall.StanceLimitBandwidth, ratePtr(1000000), "203.0.113.0/24")},
		},
		{
			name: "invalid reports are skipped while the rest compile",
			mutate: func(t *testing.T, doc map[string]any) {
				rec := report(t, doc, 0)
				badTarget := cloneReport(t, rec)
				badTarget["target"] = "not-a-prefix"
				noPenalty := cloneReport(t, rec)
				delete(noPenalty, "penalty")
				doc["reports"] = []any{rec, badTarget, noPenalty}
			},
			wantRules:   []firewall.BanRule{banRule(firewall.StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")},
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
				assertApplies(t, stub, nil)
				return
			}
			if err != nil {
				t.Fatalf("Update: %v", err)
			}
			if len(skips) != tt.wantSkipped {
				t.Errorf("skipped %d report records, want %d", len(skips), tt.wantSkipped)
			}
			assertApplies(t, stub, tt.wantRules)
		})
	}
}

func TestUpdateCyclePenaltyMapping(t *testing.T) {
	tests := []struct {
		name        string
		action      domain.PenaltyAction
		rate        any // nil deletes the penalty's rate
		wantRules   []firewall.BanRule
		wantSkipped int
		wantSkipHas string
		wantLogs    []string
	}{
		{
			name:      "drop is applied as a silent drop",
			action:    domain.PenaltyDrop,
			wantRules: []firewall.BanRule{dropRule("203.0.113.7/32")},
		},
		{
			name:        "a rate on drop is not applied and is skipped",
			action:      domain.PenaltyDrop,
			rate:        json.Number("100"),
			wantRules:   []firewall.BanRule{},
			wantSkipped: 1,
		},
		{
			name:      "reject is applied as a reject",
			action:    domain.PenaltyReject,
			wantRules: []firewall.BanRule{banRule(firewall.StanceReject, nil, "203.0.113.7/32")},
		},
		{
			name:        "a rate on reject is not applied and is skipped",
			action:      domain.PenaltyReject,
			rate:        json.Number("100"),
			wantRules:   []firewall.BanRule{},
			wantSkipped: 1,
		},
		{
			name:      "limit-pkt-rate throttles packets to its rate",
			action:    domain.PenaltyLimitPktRate,
			rate:      json.Number("250"),
			wantRules: []firewall.BanRule{banRule(firewall.StanceLimitPktRate, ratePtr(250), "203.0.113.7/32")},
		},
		{
			name:        "limit-pkt-rate without its rate is skipped",
			action:      domain.PenaltyLimitPktRate,
			wantRules:   []firewall.BanRule{},
			wantSkipped: 1,
		},
		{
			name:      "limit-bandwidth throttles response bytes to its rate",
			action:    domain.PenaltyLimitBandwidth,
			rate:      json.Number("500000"),
			wantRules: []firewall.BanRule{banRule(firewall.StanceLimitBandwidth, ratePtr(500000), "203.0.113.7/32")},
		},
		{
			name:        "limit-bandwidth without its rate is skipped",
			action:      domain.PenaltyLimitBandwidth,
			wantRules:   []firewall.BanRule{},
			wantSkipped: 1,
		},
		{
			name:      "limit-req-rate throttles requests to its rate, as stated",
			action:    domain.PenaltyLimitReqRate,
			rate:      json.Number("300"),
			wantRules: []firewall.BanRule{banRule(firewall.StanceLimitReqRate, ratePtr(300), "203.0.113.7/32")},
		},
		{
			name:        "limit-req-rate without its rate is skipped too",
			action:      domain.PenaltyLimitReqRate,
			wantRules:   []firewall.BanRule{},
			wantSkipped: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newDocServer(t)
			srv.serve(http.StatusOK, fixture(t, func(t *testing.T, doc map[string]any) {
				p := penalty(t, report(t, doc, 0))
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
			assertApplies(t, stub, tt.wantRules)
		})
	}
}

func TestUpdateCycleLogsAndCountsSkippedReports(t *testing.T) {
	srv := newDocServer(t)
	srv.serve(http.StatusOK, fixture(t, func(t *testing.T, doc map[string]any) {
		rec := report(t, doc, 0)
		badTarget := cloneReport(t, rec)
		badTarget["target"] = "not-a-prefix"
		noPenalty := cloneReport(t, rec)
		delete(noPenalty, "penalty")
		doc["reports"] = []any{rec, badTarget, noPenalty}
	}))
	u, stub, logs := newTestUpdater(t, srv)

	skips, err := u.Update(context.Background())
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	assertApplies(t, stub, []firewall.BanRule{banRule(firewall.StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")})

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

// Declines reference their ban rule by index.
func TestUpdateCycleLogsAndCountsDeclinedFeatures(t *testing.T) {
	doc := fixture(t, func(t *testing.T, doc map[string]any) {
		setReports(t, doc, []reportSpec{
			{target: "203.0.113.7/32", action: domain.PenaltyLimitReqRate, rate: json.Number("300")},
			{target: "198.51.100.9/32", action: domain.PenaltyLimitReqRate, rate: json.Number("100")},
		})
	})

	t.Run("a declined feature is logged with its rule, feature and reason and counted", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, doc)
		u, stub, logs := newTestUpdater(t, srv)
		stub.ApplyDeclined = []firewall.Decline{
			{Rule: 0, Feature: "limit-req-rate", Reason: "application-layer intent; never faked at the packet layer"},
			{Rule: 1, Feature: "limit-req-rate", Reason: "application-layer intent; never faked at the packet layer"},
		}

		if _, err := u.Update(context.Background()); err != nil {
			t.Fatalf("Update: %v", err)
		}
		logText := logs.String()
		if n := strings.Count(logText, "declined ban rule feature"); n != 2 {
			t.Fatalf("logged %d declines, want 2 (one per declined rule): %s", n, logText)
		}
		for _, want := range []string{`"rule":0`, `"rule":1`, `"feature":"limit-req-rate"`, `"reason":"application-layer intent`, `"declined":2`} {
			if !strings.Contains(logText, want) {
				t.Errorf("the declines are not logged with %q: %s", want, logText)
			}
		}
	})

	t.Run("a cycle whose driver declines nothing logs no declines", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, doc)
		u, _, logs := newTestUpdater(t, srv)

		if _, err := u.Update(context.Background()); err != nil {
			t.Fatalf("Update: %v", err)
		}
		logText := logs.String()
		if strings.Contains(logText, "declined ban rule feature") {
			t.Errorf("logged a decline that did not happen: %s", logText)
		}
		if !strings.Contains(logText, `"declined":0`) {
			t.Errorf("the install summary does not count the non-declines: %s", logText)
		}
	})
}

// Every case asserts the whole installed ruleset, so the losing
// report's absence is asserted beside the winner's presence.
func TestUpdateCycleMergePolicy(t *testing.T) {
	tests := []struct {
		name      string
		reports   []reportSpec
		wantRules []firewall.BanRule
	}{
		{
			name: "reports of one family, length and penalty group into one ban rule",
			reports: []reportSpec{
				{target: "203.0.113.0/24", action: domain.PenaltyDrop},
				{target: "198.51.100.0/24", action: domain.PenaltyDrop},
				{target: "192.0.2.0/24", action: domain.PenaltyDrop},
			},
			wantRules: []firewall.BanRule{dropRule("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")},
		},
		{
			name: "reports of one length with different penalties do not group",
			reports: []reportSpec{
				{target: "203.0.113.0/24", action: domain.PenaltyDrop},
				{target: "192.0.2.0/24", action: domain.PenaltyReject},
			},
			wantRules: []firewall.BanRule{
				dropRule("203.0.113.0/24"),
				banRule(firewall.StanceReject, nil, "192.0.2.0/24"),
			},
		},
		{
			name: "reports of one penalty with different lengths do not group",
			reports: []reportSpec{
				{target: "203.0.113.7/32", action: domain.PenaltyDrop},
				{target: "203.0.113.0/24", action: domain.PenaltyDrop},
			},
			wantRules: []firewall.BanRule{
				dropRule("203.0.113.7/32"),
				dropRule("203.0.113.0/24"),
			},
		},
		{
			name: "targets of different families do not group",
			reports: []reportSpec{
				{target: "203.0.113.7/32", action: domain.PenaltyDrop},
				{target: "2001:db8::7/32", action: domain.PenaltyDrop},
			},
			wantRules: []firewall.BanRule{
				dropRule("203.0.113.7/32"),
				dropRule("2001:db8::/32"),
			},
		},
		{
			name: "ban rules order by prefix length descending, then strictness",
			reports: []reportSpec{
				{target: "203.0.0.0/16", action: domain.PenaltyLimitPktRate, rate: json.Number("100")},
				{target: "198.51.100.9/32", action: domain.PenaltyDrop},
				{target: "203.0.113.7/32", action: domain.PenaltyLimitPktRate, rate: json.Number("50")},
				{target: "192.0.2.0/24", action: domain.PenaltyReject},
			},
			wantRules: []firewall.BanRule{
				dropRule("198.51.100.9/32"),
				banRule(firewall.StanceLimitPktRate, ratePtr(50), "203.0.113.7/32"),
				banRule(firewall.StanceReject, nil, "192.0.2.0/24"),
				banRule(firewall.StanceLimitPktRate, ratePtr(100), "203.0.0.0/16"),
			},
		},
		{
			name: "a weaker /32 stance exceptions a stronger /16 ban",
			reports: []reportSpec{
				{target: "203.0.0.0/16", action: domain.PenaltyDrop},
				{target: "203.0.113.7/32", action: domain.PenaltyLimitPktRate, rate: json.Number("10")},
			},
			wantRules: []firewall.BanRule{
				banRule(firewall.StanceLimitPktRate, ratePtr(10), "203.0.113.7/32"),
				dropRule("203.0.0.0/16"),
			},
		},
		{
			name: "a stronger /32 stance tightens under a weaker /16 ban",
			reports: []reportSpec{
				{target: "203.0.0.0/16", action: domain.PenaltyLimitPktRate, rate: json.Number("100")},
				{target: "203.0.113.7/32", action: domain.PenaltyDrop},
			},
			wantRules: []firewall.BanRule{
				dropRule("203.0.113.7/32"),
				banRule(firewall.StanceLimitPktRate, ratePtr(100), "203.0.0.0/16"),
			},
		},
		{
			name: "a narrower report agreeing with the broader one keeps both bans",
			reports: []reportSpec{
				{target: "203.0.0.0/16", action: domain.PenaltyDrop},
				{target: "203.0.113.7/32", action: domain.PenaltyDrop},
			},
			wantRules: []firewall.BanRule{
				dropRule("203.0.113.7/32"),
				dropRule("203.0.0.0/16"),
			},
		},
		{
			name: "a drop tie beats a limit tie",
			reports: []reportSpec{
				{target: "203.0.113.7/32", action: domain.PenaltyLimitPktRate, rate: json.Number("250")},
				{target: "203.0.113.7/32", action: domain.PenaltyDrop},
			},
			wantRules: []firewall.BanRule{dropRule("203.0.113.7/32")},
		},
		{
			name: "a drop tie beats a reject tie",
			reports: []reportSpec{
				{target: "203.0.113.7/32", action: domain.PenaltyReject},
				{target: "203.0.113.7/32", action: domain.PenaltyDrop},
			},
			wantRules: []firewall.BanRule{dropRule("203.0.113.7/32")},
		},
		{
			name: "a reject tie beats a limit tie",
			reports: []reportSpec{
				{target: "203.0.113.7/32", action: domain.PenaltyLimitBandwidth, rate: json.Number("500")},
				{target: "203.0.113.7/32", action: domain.PenaltyReject},
			},
			wantRules: []firewall.BanRule{banRule(firewall.StanceReject, nil, "203.0.113.7/32")},
		},
		{
			name: "a smaller rate wins a limit tie of one action",
			reports: []reportSpec{
				{target: "203.0.113.7/32", action: domain.PenaltyLimitPktRate, rate: json.Number("250")},
				{target: "203.0.113.7/32", action: domain.PenaltyLimitPktRate, rate: json.Number("100")},
			},
			wantRules: []firewall.BanRule{banRule(firewall.StanceLimitPktRate, ratePtr(100), "203.0.113.7/32")},
		},
		{
			name: "duplicate reports of one penalty compile to one ban rule",
			reports: []reportSpec{
				{target: "203.0.113.7/32", action: domain.PenaltyDrop},
				{target: "203.0.113.7/32", action: domain.PenaltyDrop},
			},
			wantRules: []firewall.BanRule{dropRule("203.0.113.7/32")},
		},
		{
			name: "tied limits of different actions combine — one meter per dimension",
			reports: []reportSpec{
				{target: "203.0.113.7/32", action: domain.PenaltyLimitBandwidth, rate: json.Number("5000")},
				{target: "203.0.113.7/32", action: domain.PenaltyLimitPktRate, rate: json.Number("100")},
			},
			wantRules: []firewall.BanRule{
				banRule(firewall.StanceLimitPktRate, ratePtr(100), "203.0.113.7/32"),
				banRule(firewall.StanceLimitBandwidth, ratePtr(5000), "203.0.113.7/32"),
			},
		},
		{
			name: "tied limits of one action keep one meter at the smallest rate",
			reports: []reportSpec{
				{target: "203.0.113.7/32", action: domain.PenaltyLimitPktRate, rate: json.Number("200")},
				{target: "203.0.113.7/32", action: domain.PenaltyLimitPktRate, rate: json.Number("50")},
				{target: "203.0.113.7/32", action: domain.PenaltyLimitPktRate, rate: json.Number("100")},
			},
			wantRules: []firewall.BanRule{banRule(firewall.StanceLimitPktRate, ratePtr(50), "203.0.113.7/32")},
		},
		{
			name: "a drop tie wins over combined limit ties",
			reports: []reportSpec{
				{target: "203.0.113.7/32", action: domain.PenaltyLimitPktRate, rate: json.Number("100")},
				{target: "203.0.113.7/32", action: domain.PenaltyLimitBandwidth, rate: json.Number("5000")},
				{target: "203.0.113.7/32", action: domain.PenaltyDrop},
			},
			wantRules: []firewall.BanRule{dropRule("203.0.113.7/32")},
		},
		{
			name: "a weaker /32 request rate exceptions a stronger /16 ban",
			reports: []reportSpec{
				{target: "203.0.0.0/16", action: domain.PenaltyDrop},
				{target: "203.0.113.7/32", action: domain.PenaltyLimitReqRate, rate: json.Number("30")},
			},
			wantRules: []firewall.BanRule{
				banRule(firewall.StanceLimitReqRate, ratePtr(30), "203.0.113.7/32"),
				dropRule("203.0.0.0/16"),
			},
		},
		{
			name: "a stronger /32 drop tightens under a weaker /16 request rate",
			reports: []reportSpec{
				{target: "203.0.0.0/16", action: domain.PenaltyLimitReqRate, rate: json.Number("300")},
				{target: "203.0.113.7/32", action: domain.PenaltyDrop},
			},
			wantRules: []firewall.BanRule{
				dropRule("203.0.113.7/32"),
				banRule(firewall.StanceLimitReqRate, ratePtr(300), "203.0.0.0/16"),
			},
		},
		{
			name: "a drop tie beats a request-rate tie",
			reports: []reportSpec{
				{target: "203.0.113.7/32", action: domain.PenaltyLimitReqRate, rate: json.Number("300")},
				{target: "203.0.113.7/32", action: domain.PenaltyDrop},
			},
			wantRules: []firewall.BanRule{dropRule("203.0.113.7/32")},
		},
		{
			name: "a reject tie beats a request-rate tie",
			reports: []reportSpec{
				{target: "203.0.113.7/32", action: domain.PenaltyLimitReqRate, rate: json.Number("300")},
				{target: "203.0.113.7/32", action: domain.PenaltyReject},
			},
			wantRules: []firewall.BanRule{banRule(firewall.StanceReject, nil, "203.0.113.7/32")},
		},
		{
			name: "a smaller rate wins a request-rate tie of one action",
			reports: []reportSpec{
				{target: "203.0.113.7/32", action: domain.PenaltyLimitReqRate, rate: json.Number("300")},
				{target: "203.0.113.7/32", action: domain.PenaltyLimitReqRate, rate: json.Number("100")},
			},
			wantRules: []firewall.BanRule{banRule(firewall.StanceLimitReqRate, ratePtr(100), "203.0.113.7/32")},
		},
		{
			name: "request rates combine with the other limit dimensions — never lost to an invented ordering",
			reports: []reportSpec{
				{target: "203.0.113.7/32", action: domain.PenaltyLimitBandwidth, rate: json.Number("5000")},
				{target: "203.0.113.7/32", action: domain.PenaltyLimitReqRate, rate: json.Number("30")},
				{target: "203.0.113.7/32", action: domain.PenaltyLimitPktRate, rate: json.Number("100")},
			},
			wantRules: []firewall.BanRule{
				banRule(firewall.StanceLimitPktRate, ratePtr(100), "203.0.113.7/32"),
				banRule(firewall.StanceLimitBandwidth, ratePtr(5000), "203.0.113.7/32"),
				banRule(firewall.StanceLimitReqRate, ratePtr(30), "203.0.113.7/32"),
			},
		},
		{
			name: "a request rate does not lose to a bandwidth tie",
			reports: []reportSpec{
				{target: "203.0.113.7/32", action: domain.PenaltyLimitBandwidth, rate: json.Number("5000")},
				{target: "203.0.113.7/32", action: domain.PenaltyLimitReqRate, rate: json.Number("30")},
			},
			wantRules: []firewall.BanRule{
				banRule(firewall.StanceLimitBandwidth, ratePtr(5000), "203.0.113.7/32"),
				banRule(firewall.StanceLimitReqRate, ratePtr(30), "203.0.113.7/32"),
			},
		},
		{
			name: "a request rate does not lose to a packet-rate tie",
			reports: []reportSpec{
				{target: "203.0.113.7/32", action: domain.PenaltyLimitPktRate, rate: json.Number("100")},
				{target: "203.0.113.7/32", action: domain.PenaltyLimitReqRate, rate: json.Number("30")},
			},
			wantRules: []firewall.BanRule{
				banRule(firewall.StanceLimitPktRate, ratePtr(100), "203.0.113.7/32"),
				banRule(firewall.StanceLimitReqRate, ratePtr(30), "203.0.113.7/32"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newDocServer(t)
			srv.serve(http.StatusOK, fixture(t, func(t *testing.T, doc map[string]any) {
				setReports(t, doc, tt.reports)
			}))
			u, stub, _ := newTestUpdater(t, srv)

			if _, err := u.Update(context.Background()); err != nil {
				t.Fatalf("Update: %v", err)
			}
			assertApplies(t, stub, tt.wantRules)
		})
	}
}

func TestUpdateCycleMergePolicyIsOrderIndependent(t *testing.T) {
	reports := []reportSpec{
		{target: "203.0.0.0/16", action: domain.PenaltyDrop},
		{target: "203.0.113.7/32", action: domain.PenaltyLimitPktRate, rate: json.Number("10")},
		{target: "203.0.113.7/32", action: domain.PenaltyLimitBandwidth, rate: json.Number("5000")},
		{target: "203.0.113.7/32", action: domain.PenaltyLimitReqRate, rate: json.Number("30")},
		{target: "203.0.113.0/24", action: domain.PenaltyReject},
	}
	want := []firewall.BanRule{
		banRule(firewall.StanceLimitPktRate, ratePtr(10), "203.0.113.7/32"),
		banRule(firewall.StanceLimitBandwidth, ratePtr(5000), "203.0.113.7/32"),
		banRule(firewall.StanceLimitReqRate, ratePtr(30), "203.0.113.7/32"),
		banRule(firewall.StanceReject, nil, "203.0.113.0/24"),
		dropRule("203.0.0.0/16"),
	}
	for i, perm := range permutations(reports) {
		t.Run(fmt.Sprintf("permutation %d", i), func(t *testing.T) {
			srv := newDocServer(t)
			srv.serve(http.StatusOK, fixture(t, func(t *testing.T, doc map[string]any) {
				setReports(t, doc, perm)
			}))
			u, stub, _ := newTestUpdater(t, srv)

			if _, err := u.Update(context.Background()); err != nil {
				t.Fatalf("Update: %v", err)
			}
			assertApplies(t, stub, want)
		})
	}
}

func TestUpdateCycleMergePolicyWithExclusions(t *testing.T) {
	tests := []struct {
		name        string
		exclude     []string
		reports     []reportSpec
		wantRules   []firewall.BanRule
		wantSkipped int
	}{
		{
			name:    "an exclusion inside both Targets does not demote the narrower report's stance",
			exclude: []string{"203.0.113.7/32"},
			reports: []reportSpec{
				{target: "203.0.113.0/24", action: domain.PenaltyDrop},
				{target: "203.0.113.0/25", action: domain.PenaltyLimitPktRate, rate: json.Number("100")},
			},
			wantRules: []firewall.BanRule{
				banRule(firewall.StanceLimitPktRate, ratePtr(100), "203.0.113.6/32"),
				banRule(firewall.StanceLimitPktRate, ratePtr(100), "203.0.113.4/31"),
				banRule(firewall.StanceLimitPktRate, ratePtr(100), "203.0.113.0/30"),
				banRule(firewall.StanceLimitPktRate, ratePtr(100), "203.0.113.8/29"),
				banRule(firewall.StanceLimitPktRate, ratePtr(100), "203.0.113.16/28"),
				banRule(firewall.StanceLimitPktRate, ratePtr(100), "203.0.113.32/27"),
				banRule(firewall.StanceLimitPktRate, ratePtr(100), "203.0.113.64/26"),
				dropRule("203.0.113.128/25"),
			},
		},
		{
			name:    "an exclusion covering the narrower Target drops its report and keeps the broader ban's residual",
			exclude: []string{"203.0.113.0/25"},
			reports: []reportSpec{
				{target: "203.0.113.0/24", action: domain.PenaltyDrop},
				{target: "203.0.113.0/25", action: domain.PenaltyLimitPktRate, rate: json.Number("100")},
			},
			wantRules:   []firewall.BanRule{dropRule("203.0.113.128/25")},
			wantSkipped: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newDocServer(t)
			srv.serve(http.StatusOK, fixture(t, func(t *testing.T, doc map[string]any) {
				setReports(t, doc, tt.reports)
			}))
			u, stub, _ := newTestUpdaterCfg(t, srv, domain.Policy{Exclude: mustPrefixes(t, tt.exclude...)})

			skips, err := u.Update(context.Background())
			if err != nil {
				t.Fatalf("Update: %v", err)
			}
			if len(skips) != tt.wantSkipped {
				t.Errorf("skipped %d report records, want %d", len(skips), tt.wantSkipped)
			}
			assertApplies(t, stub, tt.wantRules)
		})
	}
}

func permutations(specs []reportSpec) [][]reportSpec {
	if len(specs) <= 1 {
		return [][]reportSpec{specs}
	}
	var out [][]reportSpec
	for i := range specs {
		rest := slices.Concat(specs[:i:i], specs[i+1:])
		for _, p := range permutations(rest) {
			out = append(out, append([]reportSpec{specs[i]}, p...))
		}
	}
	return out
}

func TestUpdateCycleSubtractsExclusions(t *testing.T) {
	tests := []struct {
		name        string
		exclude     []string
		target      string
		wantRules   []firewall.BanRule
		wantSkipped int
	}{
		{
			name:        "an exclusion covering the whole Target produces no ban rule",
			exclude:     []string{"203.0.113.7/32"},
			target:      "203.0.113.7/32",
			wantRules:   []firewall.BanRule{},
			wantSkipped: 1,
		},
		{
			name:      "an exclusion disjoint from the Target leaves it untouched",
			exclude:   []string{"198.51.100.0/24"},
			target:    "203.0.113.7/32",
			wantRules: []firewall.BanRule{banRule(firewall.StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")},
		},
		{
			name:      "an exclusion covering part of the Target leaves its residual prefixes",
			exclude:   []string{"203.0.113.0/25"},
			target:    "203.0.113.0/24",
			wantRules: []firewall.BanRule{banRule(firewall.StanceLimitBandwidth, ratePtr(1000000), "203.0.113.128/25")},
		},
		{
			name:      "several exclusions each subtract from the Target",
			exclude:   []string{"203.0.113.0/25", "203.0.113.192/26"},
			target:    "203.0.113.0/24",
			wantRules: []firewall.BanRule{banRule(firewall.StanceLimitBandwidth, ratePtr(1000000), "203.0.113.128/26")},
		},
		{
			name:      "an exclusion covering part of an IPv6 Target leaves its residual prefixes",
			exclude:   []string{"2001:db8::/33"},
			target:    "2001:db8::/32",
			wantRules: []firewall.BanRule{banRule(firewall.StanceLimitBandwidth, ratePtr(1000000), "2001:db8:8000::/33")},
		},
		{
			// The split compiles to one rule per prefix length — one
			// equal-length set per ban rule (same coverage).
			name:    "an exclusion inside the Target splits it into residual prefixes",
			exclude: []string{"203.0.113.64/26"},
			target:  "203.0.113.0/24",
			wantRules: []firewall.BanRule{
				banRule(firewall.StanceLimitBandwidth, ratePtr(1000000), "203.0.113.0/26"),
				banRule(firewall.StanceLimitBandwidth, ratePtr(1000000), "203.0.113.128/25"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newDocServer(t)
			srv.serve(http.StatusOK, fixture(t, func(t *testing.T, doc map[string]any) {
				report(t, doc, 0)["target"] = tt.target
			}))
			u, stub, _ := newTestUpdaterCfg(t, srv, domain.Policy{Exclude: mustPrefixes(t, tt.exclude...)})

			skips, err := u.Update(context.Background())
			if err != nil {
				t.Fatalf("Update: %v", err)
			}
			if len(skips) != tt.wantSkipped {
				t.Errorf("skipped %d report records, want %d", len(skips), tt.wantSkipped)
			}
			assertApplies(t, stub, tt.wantRules)
		})
	}
}

func TestUpdateCycleSafetyExclusions(t *testing.T) {
	tests := []struct {
		name   string
		policy domain.Policy
		target string
		wantOK bool // true: the Target compiles to a ban rule
	}{
		{"a loopback Target is excluded and cannot be re-included", domain.NewPolicy(nil, false), "127.0.0.1/32", false},
		{"the IPv6 loopback Target is excluded and cannot be re-included", domain.NewPolicy(nil, false), "::1/128", false},
		{"a link-local Target is excluded and cannot be re-included", domain.NewPolicy(nil, false), "169.254.5.6/32", false},
		{"the IPv6 link-local Target is excluded and cannot be re-included", domain.NewPolicy(nil, false), "fe80::1/128", false},
		{"a public Target compiles under the safety exclusions", domain.NewPolicy(nil, true), "203.0.113.7/32", true},
		{"an RFC1918 Target is excluded by default", domain.NewPolicy(nil, true), "10.1.2.3/32", false},
		{"a ULA Target is excluded by default", domain.NewPolicy(nil, true), "fd00::1/128", false},
		{"a private Target compiles when the default exclusions are opted out", domain.NewPolicy(nil, false), "10.1.2.3/32", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newDocServer(t)
			srv.serve(http.StatusOK, fixture(t, func(t *testing.T, doc map[string]any) {
				report(t, doc, 0)["target"] = tt.target
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
				assertApplies(t, stub, []firewall.BanRule{banRule(firewall.StanceLimitBandwidth, ratePtr(1000000), tt.target)})
				return
			}
			if len(skips) != 1 {
				t.Errorf("skipped %d report records, want 1", len(skips))
			}
			assertApplies(t, stub, []firewall.BanRule{})
		})
	}
}

func TestUpdateCycleLogsTheDriversSkip(t *testing.T) {
	t.Run("every cycle hands the ruleset to the driver", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		srv.serve(http.StatusOK, canonicalDoc(t))
		u, stub, logs := newTestUpdater(t, srv)
		stub.Skip = true

		for range 2 {
			if _, err := u.Update(context.Background()); err != nil {
				t.Fatalf("Update: %v", err)
			}
		}
		if n := len(stub.ApplyCalls()); n != 2 {
			t.Errorf("the driver was handed %d rulesets, want 2 (the engine never skips on its own)", n)
		}
		if n := strings.Count(logs.String(), "ban rules unchanged; skipping install"); n != 2 {
			t.Errorf("logged %d skips, want 2 (one per driver report): %s", n, logs.String())
		}
	})

	t.Run("a skipped cycle is logged with the hash", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		u, stub, logs := newTestUpdater(t, srv)
		stub.Skip = true

		if _, err := u.Update(context.Background()); err != nil {
			t.Fatalf("Update: %v", err)
		}
		if !strings.Contains(logs.String(), "ban rules unchanged; skipping install") {
			t.Errorf("the skipped install is not logged: %s", logs.String())
		}
		hashes := loggedHashes(logs.String())
		if len(hashes) != 1 {
			t.Errorf("logged hashes %v, want the skipped cycle's hash", hashes)
		}
	})
}

func TestUpdateCycleLogsTheRulesetHash(t *testing.T) {
	t.Run("every cycle logs the hash, identical across runs", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		u, _, logs := newTestUpdater(t, srv)
		for range 2 {
			if _, err := u.Update(context.Background()); err != nil {
				t.Fatalf("Update: %v", err)
			}
		}
		hashes := loggedHashes(logs.String())
		if len(hashes) < 2 {
			t.Fatalf("logged %d ruleset hashes, want at least one per cycle: %s", len(hashes), logs.String())
		}
		for _, h := range hashes {
			if h != hashes[0] {
				t.Errorf("cycle hashes disagree: %v", hashes)
			}
		}

		srv2 := newDocServer(t)
		srv2.serve(http.StatusOK, canonicalDoc(t))
		u2, _, logs2 := newTestUpdater(t, srv2)
		if _, err := u2.Update(context.Background()); err != nil {
			t.Fatalf("fresh run Update: %v", err)
		}
		if got := loggedHashes(logs2.String()); len(got) != 1 || got[0] != hashes[0] {
			t.Errorf("a fresh run logs hashes %v, want exactly [%s]", got, hashes[0])
		}
	})

	t.Run("a changed ruleset logs a different hash", func(t *testing.T) {
		hashOf := func(t *testing.T, body string) string {
			t.Helper()
			srv := newDocServer(t)
			srv.serve(http.StatusOK, body)
			u, _, logs := newTestUpdater(t, srv)
			if _, err := u.Update(context.Background()); err != nil {
				t.Fatalf("Update: %v", err)
			}
			hashes := loggedHashes(logs.String())
			if len(hashes) != 1 {
				t.Fatalf("logged %d ruleset hashes, want 1: %s", len(hashes), logs.String())
			}
			return hashes[0]
		}
		before := hashOf(t, canonicalDoc(t))
		after := hashOf(t, fixture(t, func(t *testing.T, doc map[string]any) {
			report(t, doc, 0)["target"] = "198.51.100.9/32"
		}))
		if after == before {
			t.Errorf("the changed ruleset logs the same hash %q as the old one", before)
		}
	})
}

func TestDryRunPrintsTheRulesetHash(t *testing.T) {
	printHash := func(t *testing.T, body string) string {
		t.Helper()
		srv := newDocServer(t)
		srv.serve(http.StatusOK, body)
		u, stub, _ := newTestUpdater(t, srv)
		var out bytes.Buffer
		if err := u.DryRun(context.Background(), &out); err != nil {
			t.Fatalf("DryRun: %v", err)
		}
		_, hash := splitDryRunHash(t, out.String())
		assertApplies(t, stub, nil)
		return hash
	}
	hash := printHash(t, canonicalDoc(t))
	if again := printHash(t, canonicalDoc(t)); again != hash {
		t.Errorf("the same document prints hashes %q and %q across runs", hash, again)
	}
	if changed := printHash(t, fixture(t, func(t *testing.T, doc map[string]any) {
		report(t, doc, 0)["target"] = "198.51.100.9/32"
	})); changed == hash {
		t.Errorf("the changed ruleset prints the old hash %q", hash)
	}
}

// Hash values are compared to each other only — never pinned — so the
// rolling-hash construction stays refactorable.
var hashPattern = regexp.MustCompile(`"hash":"([0-9a-f]+)"`)

func loggedHashes(text string) []string {
	var out []string
	for _, m := range hashPattern.FindAllStringSubmatch(text, -1) {
		out = append(out, m[1])
	}
	return out
}

// splitDryRunHash splits the dry-run output into its body and its
// ruleset-hash line ("hash=<hex>"); the hash is checked for shape only.
func splitDryRunHash(t *testing.T, out string) (body, hash string) {
	t.Helper()
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "hash=") {
			if hash != "" {
				t.Fatalf("dry-run output has two hash lines: %q", out)
			}
			hash = strings.TrimPrefix(line, "hash=")
			continue
		}
		lines = append(lines, line)
	}
	if hash == "" {
		t.Fatalf("dry-run output has no hash line: %q", out)
	}
	if strings.Trim(hash, "0123456789abcdef") != "" || hash == "" {
		t.Errorf("dry-run hash = %q, want lowercase hex", hash)
	}
	return strings.Join(lines, "\n"), hash
}

func TestUpdateCycleLogsTheBanRuleHits(t *testing.T) {
	srv := newDocServer(t)
	srv.serve(http.StatusOK, canonicalDoc(t))
	u, stub, logs := newTestUpdater(t, srv)
	stub.ApplyHits = []firewall.Hit{{Rule: 0, Packets: 5, Bytes: 100}}

	if _, err := u.Update(context.Background()); err != nil {
		t.Fatalf("first Update: %v", err)
	}
	logText := logs.String()
	if !strings.Contains(logText, "ban rule hit in the replaced ruleset") {
		t.Errorf("the install logs no ban rule hit: %s", logText)
	}
	if !strings.Contains(logText, `"rule":0`) || !strings.Contains(logText, `"packets":5`) || !strings.Contains(logText, `"bytes":100`) {
		t.Errorf("the ban rule hit does not carry its rule, packets and bytes: %s", logText)
	}

	stub.Skip = true
	if _, err := u.Update(context.Background()); err != nil {
		t.Fatalf("second Update: %v", err)
	}
	if !strings.Contains(logs.String(), "ban rules unchanged") {
		t.Errorf("the skipped install is not logged: %s", logs.String())
	}
	if n := strings.Count(logs.String(), "ban rule hit in the replaced ruleset"); n != 1 {
		t.Errorf("logged %d ban rule hits, want 1 (a skipped cycle logs no hits): %s", n, logs.String())
	}
}

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
		assertApplies(t, stub, []firewall.BanRule{banRule(firewall.StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")})
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

func TestUpdateFailsLoudlyWhenTheDriverRefusesTheInstall(t *testing.T) {
	t.Run("a refused install fails the cycle", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		u, stub, _ := newTestUpdater(t, srv)
		stub.ApplyErr = errors.New("netlink: permission denied")

		if _, err := u.Update(context.Background()); err == nil || !strings.Contains(err.Error(), "install") {
			t.Fatalf("Update error = %v, want an install failure", err)
		}
		assertApplies(t, stub, nil)
	})

	t.Run("a refused install at startup exits with an error", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		u, stub, _ := newTestUpdater(t, srv)
		stub.ApplyErr = errors.New("netlink: permission denied")

		err := u.Run(context.Background())
		if err == nil || !strings.Contains(err.Error(), "startup test install") {
			t.Fatalf("Run error = %v, want a startup test install failure", err)
		}
		if stub.ResetCalls() != 1 {
			t.Errorf("Reset ran %d times, want 1 (reset before exiting non-zero)", stub.ResetCalls())
		}
	})
}

func TestUpdaterRun(t *testing.T) {
	t.Run("a failed startup test install exits with an error", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusInternalServerError, "")
		u, stub, _ := newTestUpdater(t, srv)

		err := u.Run(context.Background())
		if err == nil || !strings.Contains(err.Error(), "startup test install") {
			t.Fatalf("Run error = %v, want a startup test install failure", err)
		}
		assertApplies(t, stub, nil)
		if stub.ResetCalls() != 1 {
			t.Errorf("Reset ran %d times, want 1 (reset before exiting non-zero)", stub.ResetCalls())
		}
	})

	t.Run("the loop keeps the last rules and continues after a failed cycle", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		srv.serve(http.StatusInternalServerError, "")
		srv.serve(http.StatusOK, fixture(t, func(t *testing.T, doc map[string]any) {
			report(t, doc, 0)["target"] = "198.51.100.9/32"
		}))
		srv.serve(http.StatusInternalServerError, "")
		u, stub, logs := newTestUpdater(t, srv)
		ticks := make(chan time.Time)
		u.ticks = ticks
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		runDone := make(chan error, 1)
		go func() { runDone <- u.Run(ctx) }()

		sendTick(t, ticks, runDone)
		sendTick(t, ticks, runDone)
		sendTick(t, ticks, runDone) // starts a cycle that fails either way
		cancel()
		if err := <-runDone; err != nil {
			t.Fatalf("Run: %v", err)
		}

		calls := stub.ApplyCalls()
		want := [][]firewall.BanRule{
			{banRule(firewall.StanceLimitBandwidth, ratePtr(1000000), "203.0.113.7/32")},
			{banRule(firewall.StanceLimitBandwidth, ratePtr(1000000), "198.51.100.9/32")},
		}
		if len(calls) != len(want) {
			t.Fatalf("installed %d rulesets, want %d", len(calls), len(want))
		}
		for i := range want {
			if !equalRules(calls[i], want[i]) {
				t.Errorf("apply call %d = %v, want %v", i, calls[i], want[i])
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
// the loop exits instead; a send completes only once Run picks the
// tick up, so each send also proves every earlier cycle has finished.
func sendTick(t *testing.T, ticks chan<- time.Time, runDone <-chan error) {
	t.Helper()
	select {
	case ticks <- time.Time{}:
	case err := <-runDone:
		t.Fatalf("Run exited before the tick: %v", err)
	}
}

func TestDryRunPrintsTheDriverPlan(t *testing.T) {
	t.Run("the canonical example prints its ban rule and one placement line", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, canonicalDoc(t))
		u, stub, _ := newTestUpdater(t, srv)
		stub.Placement = "test"

		var out bytes.Buffer
		if err := u.DryRun(context.Background(), &out); err != nil {
			t.Fatalf("DryRun: %v", err)
		}
		want := `[
  {
    "targets": [
      "203.0.113.7/32"
    ],
    "stance": "limit-bandwidth",
    "rate": 1000000
  }
]
stance=limit-bandwidth rate=1000000 placement=test
`
		body, _ := splitDryRunHash(t, out.String())
		if body != want {
			t.Errorf("DryRun output = %q, want %q", body, want)
		}
		assertApplies(t, stub, nil)
	})

	planDoc := func(t *testing.T) string {
		t.Helper()
		return fixture(t, func(t *testing.T, doc map[string]any) {
			setReports(t, doc, []reportSpec{
				{target: "203.0.113.7/32", action: domain.PenaltyLimitBandwidth, rate: json.Number("1000000")},
				{target: "198.51.100.9/32", action: domain.PenaltyDrop},
				{target: "192.0.2.5/32", action: domain.PenaltyLimitPktRate, rate: json.Number("250")},
				{target: "192.0.2.6/32", action: domain.PenaltyLimitReqRate, rate: json.Number("300")},
			})
		})
	}

	t.Run("every effective rule prints one line with its stance, rate and placement", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, planDoc(t))
		u, stub, _ := newTestUpdater(t, srv)
		stub.Placement = "test"

		var out bytes.Buffer
		if err := u.DryRun(context.Background(), &out); err != nil {
			t.Fatalf("DryRun: %v", err)
		}
		var plan []string
		for _, line := range strings.Split(out.String(), "\n") {
			if strings.HasPrefix(line, "stance=") {
				plan = append(plan, line)
			}
		}
		want := []string{
			"stance=drop rate=- placement=test",
			"stance=limit-pkt-rate rate=250 placement=test",
			"stance=limit-bandwidth rate=1000000 placement=test",
			"stance=limit-req-rate rate=300 placement=test",
		}
		if !slices.Equal(plan, want) {
			t.Errorf("plan lines = %q, want %q", plan, want)
		}
		assertApplies(t, stub, nil)
	})

	t.Run("declined features print with their rule, feature and reason", func(t *testing.T) {
		srv := newDocServer(t)
		srv.serve(http.StatusOK, planDoc(t))
		u, stub, _ := newTestUpdater(t, srv)
		stub.Placement = "test"
		stub.ApplyDeclined = []firewall.Decline{{
			Rule:    3,
			Feature: "limit-req-rate",
			Reason:  "application-layer intent; never faked at the packet layer",
		}}

		var out bytes.Buffer
		if err := u.DryRun(context.Background(), &out); err != nil {
			t.Fatalf("DryRun: %v", err)
		}
		var plan []string
		for _, line := range strings.Split(out.String(), "\n") {
			if strings.HasPrefix(line, "stance=") || strings.HasPrefix(line, "declined ") {
				plan = append(plan, line)
			}
		}
		want := []string{
			"stance=drop rate=- placement=test",
			"stance=limit-pkt-rate rate=250 placement=test",
			"stance=limit-bandwidth rate=1000000 placement=test",
			"declined rule=3 feature=limit-req-rate reason=application-layer intent; never faked at the packet layer",
		}
		if !slices.Equal(plan, want) {
			t.Errorf("plan lines = %q, want %q", plan, want)
		}
		assertApplies(t, stub, nil)
	})
}

func TestDryRunShowsTheEffectiveSets(t *testing.T) {
	srv := newDocServer(t)
	srv.serve(http.StatusOK, fixture(t, func(t *testing.T, doc map[string]any) {
		report(t, doc, 0)["target"] = "203.0.113.0/24"
	}))
	u, stub, _ := newTestUpdaterCfg(t, srv, domain.NewPolicy(
		mustPrefixes(t, "203.0.113.0/25"), true,
	))
	stub.Placement = "test"

	var out bytes.Buffer
	if err := u.DryRun(context.Background(), &out); err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	want := `[
  {
    "targets": [
      "203.0.113.128/25"
    ],
    "stance": "limit-bandwidth",
    "rate": 1000000
  }
]
stance=limit-bandwidth rate=1000000 placement=test
`
	body, _ := splitDryRunHash(t, out.String())
	if body != want {
		t.Errorf("DryRun output = %q, want %q", body, want)
	}
	assertApplies(t, stub, nil)
}

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
			u, err := New(fetcher, []firewall.Point{{Label: "current", Driver: &firewalltest.Stub{}}}, defaultPolicy(), tt.interval, zerolog.New(logs))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
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
