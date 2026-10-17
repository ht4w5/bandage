package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Primary seam (spec: Testing Decisions): the assembled daemon — real
// rule loader, parser, evaluation, report service and sqlite :memory:
// repository behind the HTTP API — driven by raw nginx-JSON syslog
// messages at a real ingest listener, asserted through GET /reports JSON,
// with the wall clock injected (never sleep).

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock(t time.Time) *testClock { return &testClock{t: t} }

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

const (
	wallBase = "2025-10-17T18:00:00Z" // injected wall clock at trigger

	// Event times as sent on the wire and as rendered in documents.
	eventTime1   = "1734345934.123"
	eventTime2   = "1734345935.123"
	eventTime1At = "2024-12-16T10:45:34Z"
	eventTime2At = "2024-12-16T10:45:35Z"
)

// nginxLine builds one raw nginx JSON access-log line.
func nginxLine(t, client, method, path string, status int, sent int64) string {
	return fmt.Sprintf(`{"time":%q,"client":%q,"method":%q,"url":%q,"status":%d,"sent":%d}`,
		t, client, method, path, status, sent)
}

// testDaemon bundles a running daemon with a raw-line sender.
type testDaemon struct {
	*Daemon
	send func(line string)
}

func startTestDaemon(t *testing.T, clock *testClock, network, dbPath, rulesYAML string) *testDaemon {
	t.Helper()
	listen := filepath.Join(t.TempDir(), "log.sock")
	switch network {
	case "unixgram":
		// listen is the temp sock path
	case "tcp", "udp":
		listen = freeAddr(t)
	default:
		t.Fatalf("unknown network %q", network)
	}

	cfg := Config{
		Ingest: Ingest{
			Driver: "syslog",
			Parser: "nginx",
			Syslog: Syslog{Network: network, Listen: listen},
		},
		DB:    DB{Driver: "sqlite", SQLite: SQLite{Path: dbPath}},
		Cache: Cache{MaxEntries: 65536},
		API:   API{Listen: "127.0.0.1:0"},
	}
	chains, err := ParseRules([]byte(rulesYAML))
	if err != nil {
		t.Fatalf("ParseRules error: %v", err)
	}
	d, err := New(cfg, chains, WithClock(clock.Now))
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	if err := d.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := d.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown error: %v", err)
		}
	})

	td := &testDaemon{Daemon: d}
	var conn net.Conn
	var err2 error
	switch network {
	case "unixgram":
		conn, err2 = net.Dial("unixgram", listen)
	case "tcp":
		conn, err2 = net.Dial("tcp", listen)
	case "udp":
		conn, err2 = net.Dial("udp", listen)
	}
	if err2 != nil {
		t.Fatalf("dial %s: %v", network, err2)
	}
	t.Cleanup(func() { conn.Close() })
	if network == "tcp" {
		td.send = func(line string) {
			if _, err := conn.Write([]byte(line + "\n")); err != nil {
				t.Errorf("send: %v", err)
			}
		}
	} else {
		td.send = func(line string) {
			if _, err := conn.Write([]byte(line)); err != nil {
				t.Errorf("send: %v", err)
			}
		}
	}
	return td
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func (d *testDaemon) waitProcessed(t *testing.T, n int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.WaitProcessed(ctx, n); err != nil {
		t.Fatalf("WaitProcessed(%d): %v", n, err)
	}
}

// reportEntry mirrors the version-0 report document entry.
type reportEntry struct {
	Rule      string `json:"rule"`
	Chain     string `json:"chain"`
	Reason    string `json:"reason"`
	Target    string `json:"target"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	ExpiresAt string `json:"expires_at"`
	Tracker   struct {
		Track  string  `json:"track"`
		Value  float64 `json:"value"`
		Leak   float64 `json:"leak"`
		Volume float64 `json:"volume"`
	} `json:"tracker"`
	Sample struct {
		Time   string `json:"time"`
		Path   string `json:"path"`
		Agent  string `json:"agent"`
		Status int    `json:"status"`
		Sent   int64  `json:"sent"`
		Size   int64  `json:"size"`
	} `json:"sample"`
}

type reportDoc struct {
	Version     int           `json:"version"`
	GeneratedAt string        `json:"generated_at"`
	Reports     []reportEntry `json:"reports"`
}

func (d *testDaemon) get(t *testing.T, path string, query url.Values) (int, reportDoc) {
	t.Helper()
	u := "http://" + d.APIAddr() + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	resp, err := http.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var doc reportDoc
	if len(body) > 0 {
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatalf("GET %s: bad JSON %q: %v", u, body, err)
		}
	}
	return resp.StatusCode, doc
}

func (d *testDaemon) getReports(t *testing.T, query url.Values) reportDoc {
	t.Helper()
	status, doc := d.get(t, "/reports", query)
	if status != http.StatusOK {
		t.Fatalf("GET /reports status = %d, want 200", status)
	}
	return doc
}

const bandwidthRules = `
version: 0
chains:
  - name: download-abuse
    rules:
      - id: sustained-egress
        tracker:
          track: bandwidth
          leak: 1000
          volume: 10000
        actions:
          - report:
              reason: egress-overflow
              ttl: 24h
`

// Overflow writes exactly one report carrying rule, chain, reason,
// target, wall-clock timestamps, the tracker reading and the sample.
func TestE2EOverflowWritesReport(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	d := startTestDaemon(t, clock, "unixgram", ":memory:", bandwidthRules)

	// 6000 + 6000 − 1000·1s = 11000 > 10000: overflows on the second event.
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/releases/24.04.iso", 200, 6000))
	d.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/releases/24.04.iso", 200, 6000))
	d.waitProcessed(t, 2)

	doc := d.getReports(t, nil)
	if doc.Version != 0 {
		t.Errorf("document version = %d, want 0", doc.Version)
	}
	if doc.GeneratedAt != wallBase {
		t.Errorf("generated_at = %q, want %q", doc.GeneratedAt, wallBase)
	}
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %d, want 1: %+v", len(doc.Reports), doc.Reports)
	}
	r := doc.Reports[0]
	if r.Rule != "sustained-egress" || r.Chain != "download-abuse" || r.Reason != "egress-overflow" {
		t.Errorf("provenance = %q/%q/%q", r.Rule, r.Chain, r.Reason)
	}
	if r.Target != "203.0.113.7/32" {
		t.Errorf("target = %q, want %q", r.Target, "203.0.113.7/32")
	}
	if r.CreatedAt != wallBase || r.UpdatedAt != wallBase {
		t.Errorf("created_at/updated_at = %q/%q, want %q", r.CreatedAt, r.UpdatedAt, wallBase)
	}
	if r.ExpiresAt != "2025-10-18T18:00:00Z" {
		t.Errorf("expires_at = %q, want %q", r.ExpiresAt, "2025-10-18T18:00:00Z")
	}
	if r.Tracker.Track != "bandwidth" || r.Tracker.Value != 11000 || r.Tracker.Leak != 1000 || r.Tracker.Volume != 10000 {
		t.Errorf("tracker = %+v, want {bandwidth 11000 1000 10000}", r.Tracker)
	}
	if r.Sample.Time != eventTime2At || r.Sample.Path != "/releases/24.04.iso" ||
		r.Sample.Agent != "" || r.Sample.Status != 200 || r.Sample.Sent != 6000 || r.Sample.Size != 0 {
		t.Errorf("sample = %+v", r.Sample)
	}
}

// The rate tracker overflows strictly above volume (flux bucket.yaml:
// leak=0, volume=2 → third request triggers).
func TestE2ERateOverflowStrictlyAboveVolume(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: api
    rules:
      - id: bursty-api
        tracker: {track: rate, leak: 0, volume: 2}
        actions: [{report: {reason: api-rate-overflow, ttl: 1h}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)

	d.send(nginxLine(eventTime1, "203.0.113.9", "GET", "/api", 200, 0))
	d.send(nginxLine(eventTime1, "203.0.113.9", "GET", "/api", 200, 0))
	d.waitProcessed(t, 2)
	if doc := d.getReports(t, nil); len(doc.Reports) != 0 {
		t.Fatalf("reports after 2 events = %+v, want none (value == volume does not overflow)", doc.Reports)
	}

	d.send(nginxLine(eventTime1, "203.0.113.9", "GET", "/api", 200, 0))
	d.waitProcessed(t, 3)
	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports after 3rd event = %+v, want 1", doc.Reports)
	}
	if doc.Reports[0].Tracker.Value != 3 {
		t.Errorf("tracker value = %v, want 3", doc.Reports[0].Tracker.Value)
	}
}

// Decay is computed from event time, not wall time: steady events drain
// and never overflow, a same-second burst does.
func TestE2EDecayUsesEventTime(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: api
    rules:
      - id: bursty-api
        tracker: {track: rate, leak: 1, volume: 4}
        actions: [{report: {reason: api-rate-overflow, ttl: 1h}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)

	// Steady one-per-second traffic drains fully; five events, no overflow.
	for i := 0; i < 5; i++ {
		d.send(nginxLine(fmt.Sprintf("%d", 1734345934+i), "203.0.113.9", "GET", "/api", 200, 0))
	}
	d.waitProcessed(t, 5)
	if doc := d.getReports(t, nil); len(doc.Reports) != 0 {
		t.Fatalf("steady traffic produced reports %+v, want none", doc.Reports)
	}

	// A six-request burst at one event time decays the leftover, then
	// accumulates 1..5; value 5 > 4 overflows.
	for i := 0; i < 6; i++ {
		d.send(nginxLine("1734346000", "203.0.113.9", "GET", "/api", 200, 0))
	}
	d.waitProcessed(t, 11)
	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("burst produced reports %+v, want 1", doc.Reports)
	}
	if doc.Reports[0].Tracker.Value != 5 {
		t.Errorf("tracker value = %v, want 5", doc.Reports[0].Tracker.Value)
	}
}

// Malformed lines and invalid required fields are dropped and counted.
func TestE2EMalformedLinesDroppedAndCounted(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	d := startTestDaemon(t, clock, "unixgram", ":memory:", bandwidthRules)

	d.send("this is not json")
	d.send(`{"time":"1734345934","client":"203.0.113.7","method":"GET","url":"/","status":99,"sent":0}`)
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/small", 200, 10))
	d.waitProcessed(t, 3)

	if doc := d.getReports(t, nil); len(doc.Reports) != 0 {
		t.Errorf("dropped lines produced reports %+v, want none", doc.Reports)
	}
	stats := d.Stats()
	if stats.Dropped != 2 {
		t.Errorf("stats dropped = %d, want 2", stats.Dropped)
	}
	if stats.Parsed != 1 {
		t.Errorf("stats parsed = %d, want 1", stats.Parsed)
	}
}

// A Trigger upserts exactly one report per (rule, target): created_at is
// fixed at creation, updated_at/expires_at refresh on every trigger.
func TestE2EReportUpsertIdentity(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: abuse
    rules:
      - id: byte-flood
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: byte-flood, ttl: 1h}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)

	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d.waitProcessed(t, 1)
	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 || doc.Reports[0].CreatedAt != wallBase {
		t.Fatalf("after first trigger: %+v", doc.Reports)
	}

	clock.Advance(10 * time.Minute)
	d.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/big", 200, 150))
	d.send(nginxLine(eventTime2, "203.0.113.8", "GET", "/big", 200, 150))
	d.waitProcessed(t, 3)

	doc = d.getReports(t, nil)
	if len(doc.Reports) != 2 {
		t.Fatalf("reports = %+v, want 2 (one per target)", doc.Reports)
	}
	// Sorted by created_at descending: the new target first.
	first, second := doc.Reports[0], doc.Reports[1]
	if first.Target != "203.0.113.8/32" || second.Target != "203.0.113.7/32" {
		t.Fatalf("sort order = %q then %q", first.Target, second.Target)
	}
	if second.CreatedAt != wallBase {
		t.Errorf("created_at = %q, want fixed %q", second.CreatedAt, wallBase)
	}
	if second.UpdatedAt != "2025-10-17T18:10:00Z" || second.ExpiresAt != "2025-10-17T19:10:00Z" {
		t.Errorf("updated_at/expires_at = %q/%q", second.UpdatedAt, second.ExpiresAt)
	}
	if first.UpdatedAt != "2025-10-17T18:10:00Z" {
		t.Errorf("new report updated_at = %q", first.UpdatedAt)
	}
}

// GET /reports filters by ?rule= and ?target= and never returns expired
// reports.
func TestE2EReportFiltersAndExpiry(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: abuse
    rules:
      - id: rule-one
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: one, ttl: 1h}}]
      - id: rule-two
        filter: any
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: two, ttl: 2h}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)

	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d.waitProcessed(t, 1)

	if doc := d.getReports(t, url.Values{"rule": {"rule-one"}}); len(doc.Reports) != 1 {
		t.Errorf("?rule=rule-one: %+v", doc.Reports)
	}
	if doc := d.getReports(t, url.Values{"rule": {"nope"}}); len(doc.Reports) != 0 {
		t.Errorf("?rule=nope: %+v", doc.Reports)
	}
	if doc := d.getReports(t, url.Values{"target": {"203.0.113.7/32"}}); len(doc.Reports) != 2 {
		t.Errorf("?target=203.0.113.7/32: %+v", doc.Reports)
	}
	if doc := d.getReports(t, url.Values{"target": {"203.0.113.8/32"}}); len(doc.Reports) != 0 {
		t.Errorf("?target=203.0.113.8/32: %+v", doc.Reports)
	}

	clock.Advance(90 * time.Minute)
	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 || doc.Reports[0].Rule != "rule-two" {
		t.Errorf("after 90m: %+v, want only rule-two (ttl 2h)", doc.Reports)
	}
	clock.Advance(90 * time.Minute)
	if doc := d.getReports(t, nil); len(doc.Reports) != 0 {
		t.Errorf("after 3h: %+v, want none (expired reports never returned)", doc.Reports)
	}
}

// GET /ping is liveness; nothing else is exposed.
func TestE2EAPIPingOnly(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	d := startTestDaemon(t, clock, "unixgram", ":memory:", bandwidthRules)

	resp, err := http.Get("http://" + d.APIAddr() + "/ping")
	if err != nil {
		t.Fatalf("GET /ping: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "pong" {
		t.Errorf("GET /ping = %d %q, want 200 %q", resp.StatusCode, body, "pong")
	}

	for _, path := range []string{"/", "/metrics", "/debug", "/reports/1"} {
		resp, err := http.Get("http://" + d.APIAddr() + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, resp.StatusCode)
		}
	}

	req, err := http.NewRequest(http.MethodDelete, "http://"+d.APIAddr()+"/reports?rule=x", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE /reports: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("DELETE /reports = %d, want 405 (dismiss is a later ticket)", resp.StatusCode)
	}
}

// Reports survive restarts (sqlite); tracker state is memory-only and
// restart-cold (per ADR 0002).
func TestE2ERestartPersistsReportsNotTrackers(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	dbPath := filepath.Join(t.TempDir(), "reports.db")

	d1 := startTestDaemon(t, clock, "unixgram", dbPath, bandwidthRules)
	d1.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 12000))
	d1.waitProcessed(t, 1)
	if doc := d1.getReports(t, nil); len(doc.Reports) != 1 {
		t.Fatalf("before restart: %+v", doc.Reports)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := d1.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	cancel()

	d2 := startTestDaemon(t, clock, "unixgram", dbPath, bandwidthRules)
	doc := d2.getReports(t, nil)
	if len(doc.Reports) != 1 || doc.Reports[0].Rule != "sustained-egress" {
		t.Fatalf("after restart: %+v, want the persisted report", doc.Reports)
	}

	// Tracker state restarts cold: one event of 100 bytes cannot overflow
	// the fresh bucket and must not touch the persisted report.
	d2.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/big", 200, 100))
	d2.waitProcessed(t, 1)
	after := d2.getReports(t, nil)
	if len(after.Reports) != 1 || after.Reports[0].UpdatedAt != wallBase {
		t.Errorf("after cold event: %+v, want untouched report", after.Reports)
	}
}

// All three syslog transports accept raw nginx JSON lines.
func TestE2ESyslogTransports(t *testing.T) {
	rules := `
version: 0
chains:
  - name: abuse
    rules:
      - id: one-shot
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: one-shot, ttl: 1h}}]
`
	for _, network := range []string{"unixgram", "tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			clock := newTestClock(mustTime(t, wallBase))
			d := startTestDaemon(t, clock, network, ":memory:", rules)
			d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
			d.waitProcessed(t, 1)
			if doc := d.getReports(t, nil); len(doc.Reports) != 1 {
				t.Errorf("reports = %+v, want 1", doc.Reports)
			}
		})
	}
}

// Real syslog framing (RFC3164-style) carries the nginx JSON as content.
func TestE2ESyslogFramedMessage(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: abuse
    rules:
      - id: one-shot
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: one-shot, ttl: 1h}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)
	d.send("<134>Dec 16 12:00:00 web1 nginx: " + nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d.waitProcessed(t, 1)
	if doc := d.getReports(t, nil); len(doc.Reports) != 1 {
		t.Errorf("reports = %+v, want 1", doc.Reports)
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

// Target aggregation (spec: target_prefix): sources in one aggregated
// prefix share the tracker's state and produce ONE Report Target
// rendered as the prefix; a single IPv6 source is never reported finer
// than /64.
func TestE2ETargetAggregationSharesStatePerPrefix(t *testing.T) {
	tests := []struct {
		name    string
		rules   string
		clients []string
		fourth  string
		want    string
		filter  url.Values
	}{
		{
			name: "ipv4 /24",
			rules: `
version: 0
chains:
  - name: abuse
    rules:
      - id: burst
        tracker: {track: rate, leak: 0, volume: 2, target_prefix: {ipv4: 24, ipv6: 64}}
        actions: [{report: {reason: burst, ttl: 1h}}]
`,
			clients: []string{"203.0.113.7", "203.0.113.8", "203.0.113.254"},
			fourth:  "203.0.113.9",
			want:    "203.0.113.0/24",
			filter:  url.Values{"target": {"203.0.113.0/24"}},
		},
		{
			name: "ipv6 /64 (default, never finer than /64)",
			rules: `
version: 0
chains:
  - name: abuse
    rules:
      - id: burst
        tracker: {track: rate, leak: 0, volume: 2}
        actions: [{report: {reason: burst, ttl: 1h}}]
`,
			clients: []string{"2001:db8::1", "2001:db8::2", "2001:db8:0:0:1:2:3:4"},
			fourth:  "2001:db8::ffff",
			want:    "2001:db8::/64",
			filter:  url.Values{"target": {"2001:db8::/64"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := newTestClock(mustTime(t, wallBase))
			d := startTestDaemon(t, clock, "unixgram", ":memory:", tt.rules)

			// One event per source address; none alone overflows volume 2.
			for _, client := range tt.clients {
				d.send(nginxLine(eventTime1, client, "GET", "/api", 200, 0))
			}
			d.waitProcessed(t, int64(len(tt.clients)))

			doc := d.getReports(t, nil)
			if len(doc.Reports) != 1 {
				t.Fatalf("reports = %+v, want 1 (shared state overflows once)", doc.Reports)
			}
			r := doc.Reports[0]
			if r.Target != tt.want {
				t.Errorf("target = %q, want %q", r.Target, tt.want)
			}
			if r.Tracker.Value != 3 {
				t.Errorf("tracker value = %v, want 3 (three sources accumulated)", r.Tracker.Value)
			}

			// Another source in the same prefix upserts the same Report
			// Target: still exactly one report.
			d.send(nginxLine(eventTime2, tt.fourth, "GET", "/api", 200, 0))
			d.waitProcessed(t, int64(len(tt.clients))+1)
			doc = d.getReports(t, nil)
			if len(doc.Reports) != 1 {
				t.Fatalf("reports after 4th source = %+v, want still 1", doc.Reports)
			}
			if doc.Reports[0].Target != tt.want {
				t.Errorf("target = %q, want %q", doc.Reports[0].Target, tt.want)
			}

			// ?target= matches the prefix string.
			if doc := d.getReports(t, tt.filter); len(doc.Reports) != 1 {
				t.Errorf("?target=%s: %+v, want 1", tt.filter.Get("target"), doc.Reports)
			}
		})
	}
}

// Sources in different aggregated prefixes never share tracker state and
// produce one Report Target each; ?target= matches the prefix string.
func TestE2ETargetAggregationSeparatesPrefixes(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: abuse
    rules:
      - id: burst
        tracker: {track: rate, leak: 0, volume: 2, target_prefix: {ipv4: 24, ipv6: 64}}
        actions: [{report: {reason: burst, ttl: 1h}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)

	// Two sources per prefix: two buckets at value 2 each. Nothing
	// overflows (value == volume does not overflow) — state does not
	// smear across prefixes.
	for _, client := range []string{"203.0.113.7", "203.0.113.8", "203.0.114.7", "203.0.114.8"} {
		d.send(nginxLine(eventTime1, client, "GET", "/api", 200, 0))
	}
	d.waitProcessed(t, 4)
	if doc := d.getReports(t, nil); len(doc.Reports) != 0 {
		t.Fatalf("reports after two per prefix = %+v, want none", doc.Reports)
	}

	// A third source in 203.0.113.0/24 overflows only that prefix.
	d.send(nginxLine(eventTime2, "203.0.113.9", "GET", "/api", 200, 0))
	d.waitProcessed(t, 5)
	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 || doc.Reports[0].Target != "203.0.113.0/24" {
		t.Fatalf("reports = %+v, want one for 203.0.113.0/24", doc.Reports)
	}

	// A third source in 203.0.114.0/24 gets its own report.
	d.send(nginxLine(eventTime2, "203.0.114.9", "GET", "/api", 200, 0))
	d.waitProcessed(t, 6)
	doc = d.getReports(t, nil)
	if len(doc.Reports) != 2 {
		t.Fatalf("reports = %+v, want one per prefix", doc.Reports)
	}
	seen := map[string]bool{doc.Reports[0].Target: true, doc.Reports[1].Target: true}
	if !seen["203.0.113.0/24"] || !seen["203.0.114.0/24"] {
		t.Errorf("report targets = %+v, want 203.0.113.0/24 and 203.0.114.0/24", doc.Reports)
	}

	// ?target= matches the aggregated prefix string, not raw addresses.
	if doc := d.getReports(t, url.Values{"target": {"203.0.113.0/24"}}); len(doc.Reports) != 1 {
		t.Errorf("?target=203.0.113.0/24: %+v, want 1", doc.Reports)
	}
	if doc := d.getReports(t, url.Values{"target": {"203.0.113.7/32"}}); len(doc.Reports) != 0 {
		t.Errorf("?target=203.0.113.7/32: %+v, want 0", doc.Reports)
	}
}
