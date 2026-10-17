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
		listen = freeAddr(t, network)
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
		// Parked spare connections from the shared test client would
		// block the daemon's graceful shutdown (a conn that never sent
		// a request is not idle to http.Server). Drop them first.
		http.DefaultClient.CloseIdleConnections()
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

// freeAddr reserves a free listen address for the network and returns
// it. The probe matches the network's address family and transport: a
// port free for TCP may well be busy for UDP.
func freeAddr(t *testing.T, network string) string {
	t.Helper()
	var addr string
	switch network {
	case "tcp":
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr = ln.Addr().String()
		ln.Close()
	case "udp":
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr = c.LocalAddr().String()
		c.Close()
	default:
		t.Fatalf("freeAddr: unknown network %q", network)
	}
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

// del issues DELETE /reports with the query and returns the response
// status and the {"deleted": n} count.
func (d *testDaemon) del(t *testing.T, query url.Values) (int, int) {
	t.Helper()
	u := "http://" + d.APIAddr() + "/reports"
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequest(http.MethodDelete, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE %s: %v", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, 0
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Deleted int `json:"deleted"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("DELETE %s: bad JSON %q: %v", u, body, err)
	}
	return resp.StatusCode, out.Deleted
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
	if r.Target != "203.0.113.7" {
		t.Errorf("target = %q, want %q", r.Target, "203.0.113.7")
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
	if first.Target != "203.0.113.8" || second.Target != "203.0.113.7" {
		t.Fatalf("sort order = %q then %q", first.Target, second.Target)
	}
	if second.CreatedAt != wallBase {
		t.Errorf("created_at = %q, want fixed %q", second.CreatedAt, wallBase)
	}
	if second.UpdatedAt != "2025-10-17T18:10:00Z" || second.ExpiresAt != "2025-10-17T19:10:00Z" {
		t.Errorf("updated_at/expires_at = %q/%q", second.UpdatedAt, second.ExpiresAt)
	}
	// The re-Trigger refreshes the tracker reading and the sample.
	if second.Tracker.Value != 300 {
		t.Errorf("tracker value = %v, want 300 (re-trigger refreshes the reading)", second.Tracker.Value)
	}
	if second.Sample.Time != eventTime2At {
		t.Errorf("sample time = %q, want %q (re-trigger refreshes the sample)", second.Sample.Time, eventTime2At)
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
	if doc := d.getReports(t, url.Values{"target": {"203.0.113.7"}}); len(doc.Reports) != 2 {
		t.Errorf("?target=203.0.113.7: %+v", doc.Reports)
	}
	if doc := d.getReports(t, url.Values{"target": {"203.0.113.8"}}); len(doc.Reports) != 0 {
		t.Errorf("?target=203.0.113.8: %+v", doc.Reports)
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

// DELETE /reports requires ?rule= and/or ?target= (400 without) and
// returns deleted-row counts per filter combination. Deletion is
// storage-level: expired rows count too.
func TestE2EDeleteByFilterCounts(t *testing.T) {
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
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: two, ttl: 1h}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)

	// Two clients in far-apart networks, so target aggregation can
	// never merge them into one target.
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d.send(nginxLine(eventTime1, "198.51.100.7", "GET", "/big", 200, 150))
	d.waitProcessed(t, 2)

	doc := d.getReports(t, nil)
	if len(doc.Reports) != 4 {
		t.Fatalf("reports = %+v, want 4 (two rules x two targets)", doc.Reports)
	}
	targets := map[string]bool{}
	for _, r := range doc.Reports {
		targets[r.Target] = true
	}
	if len(targets) != 2 {
		t.Fatalf("distinct targets = %v, want 2", targets)
	}
	var tA, tB string
	for target := range targets {
		if tA == "" {
			tA = target
		} else {
			tB = target
		}
	}

	// Missing both filters: 400, and nothing is deleted.
	if status, _ := d.del(t, nil); status != http.StatusBadRequest {
		t.Errorf("DELETE without filters = %d, want 400", status)
	}
	if doc := d.getReports(t, nil); len(doc.Reports) != 4 {
		t.Errorf("reports after 400 = %+v, want 4 still listed", doc.Reports)
	}

	// rule and target together narrow as AND.
	if _, n := d.del(t, url.Values{"rule": {"rule-one"}, "target": {tA}}); n != 1 {
		t.Errorf("DELETE rule-one&target=%s count = %d, want 1", tA, n)
	}
	// rule alone deletes every target of that rule.
	if _, n := d.del(t, url.Values{"rule": {"rule-one"}}); n != 1 {
		t.Errorf("DELETE rule-one count = %d, want 1", n)
	}
	// target alone deletes every rule for that target.
	if _, n := d.del(t, url.Values{"target": {tA}}); n != 1 {
		t.Errorf("DELETE target=%s count = %d, want 1", tA, n)
	}
	doc = d.getReports(t, nil)
	if len(doc.Reports) != 1 || doc.Reports[0].Rule != "rule-two" || doc.Reports[0].Target != tB {
		t.Fatalf("remaining = %+v, want only rule-two/%s", doc.Reports, tB)
	}
	if _, n := d.del(t, url.Values{"rule": {"rule-two"}, "target": {tB}}); n != 1 {
		t.Errorf("DELETE rule-two&target=%s count = %d, want 1", tB, n)
	}

	// Non-matching filters delete nothing.
	if _, n := d.del(t, url.Values{"rule": {"nope"}}); n != 0 {
		t.Errorf("DELETE rule=nope count = %d, want 0", n)
	}
	if doc := d.getReports(t, nil); len(doc.Reports) != 0 {
		t.Errorf("final reports = %+v, want none", doc.Reports)
	}
}

// Dismissal is not silence: DELETE /reports leaves tracker state
// untouched, so a report whose condition persists returns on the next
// trigger — with a fresh identity and a tracker reading that kept
// accumulating across the dismissal.
func TestE2EDismissIsNotSilence(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: abuse
    rules:
      - id: sticky
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: sticky, ttl: 1h}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)

	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d.waitProcessed(t, 1)
	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 || doc.Reports[0].Tracker.Value != 150 {
		t.Fatalf("after first trigger: %+v", doc.Reports)
	}

	if _, n := d.del(t, url.Values{"rule": {"sticky"}}); n != 1 {
		t.Fatalf("dismiss count = %d, want 1", n)
	}
	if doc := d.getReports(t, nil); len(doc.Reports) != 0 {
		t.Fatalf("after dismiss: %+v, want none", doc.Reports)
	}

	// The condition persists: the next trigger brings the report back.
	clock.Advance(10 * time.Minute)
	d.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/big", 200, 150))
	d.waitProcessed(t, 2)
	doc = d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("after re-trigger: %+v, want the report back", doc.Reports)
	}
	r := doc.Reports[0]
	if r.CreatedAt != "2025-10-17T18:10:00Z" {
		t.Errorf("created_at = %q, want a fresh %q (dismissed report is gone)", r.CreatedAt, "2025-10-17T18:10:00Z")
	}
	if r.Tracker.Value != 300 {
		t.Errorf("tracker value = %v, want 300 (dismissal touched no tracker state)", r.Tracker.Value)
	}
	if r.Sample.Time != eventTime2At {
		t.Errorf("sample time = %q, want %q", r.Sample.Time, eventTime2At)
	}
}

// The periodic sweeper deletes expired rows from storage at the
// injected wall clock: an expired row is gone without any DELETE, a
// live row survives the pass.
func TestE2ESweeperDeletesExpiredRows(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: abuse
    rules:
      - id: rule-one
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: one, ttl: 1h}}]
      - id: rule-three
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: three, ttl: 1h}}]
      - id: rule-two
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: two, ttl: 2h}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)

	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d.waitProcessed(t, 1)
	if doc := d.getReports(t, nil); len(doc.Reports) != 3 {
		t.Fatalf("reports = %+v, want 3", doc.Reports)
	}

	clock.Advance(90 * time.Minute)
	// Expired reports are never returned...
	if doc := d.getReports(t, nil); len(doc.Reports) != 1 || doc.Reports[0].Rule != "rule-two" {
		t.Fatalf("after 90m: %+v, want only rule-two", doc.Reports)
	}
	// ...but they are still in storage until swept: dismissal counts
	// them like any other row.
	if _, n := d.del(t, url.Values{"rule": {"rule-three"}}); n != 1 {
		t.Errorf("dismiss of an expired row = %d, want 1 (still stored pre-sweep)", n)
	}

	// One sweeper pass at the injected clock deletes expired rows only.
	if _, err := d.sweepOnce(context.Background()); err != nil {
		t.Fatalf("sweepOnce: %v", err)
	}
	if _, n := d.del(t, url.Values{"rule": {"rule-one"}}); n != 0 {
		t.Errorf("dismiss after sweep = %d, want 0 (row swept away)", n)
	}
	if _, n := d.del(t, url.Values{"rule": {"rule-two"}}); n != 1 {
		t.Errorf("dismiss of a live row = %d, want 1 (sweeper leaves it)", n)
	}
}

// expires_at is recomputed unconditionally on every trigger: a
// re-trigger whose ttl is shorter (config changed across restart)
// pulls expiry in, even over an earlier, later-expiring value, while
// created_at stays fixed at the report's first trigger.
func TestE2EExpiresAtRefreshedUnconditionally(t *testing.T) {
	expiryRules := func(ttl string) string {
		return fmt.Sprintf(`
version: 0
chains:
  - name: abuse
    rules:
      - id: sticky
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: sticky, ttl: %s}}]
`, ttl)
	}
	clock := newTestClock(mustTime(t, wallBase))
	dbPath := filepath.Join(t.TempDir(), "reports.db")

	d1 := startTestDaemon(t, clock, "unixgram", dbPath, expiryRules("24h"))
	d1.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d1.waitProcessed(t, 1)
	doc := d1.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("after first trigger: %+v", doc.Reports)
	}
	if doc.Reports[0].CreatedAt != wallBase || doc.Reports[0].ExpiresAt != "2025-10-18T18:00:00Z" {
		t.Fatalf("created_at/expires_at = %q/%q, want %q/2025-10-18T18:00:00Z",
			doc.Reports[0].CreatedAt, doc.Reports[0].ExpiresAt, wallBase)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := d1.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	cancel()

	// Restart with a shorter ttl for the same rule: the re-trigger must
	// overwrite the later-expiring value, not extend it.
	clock.Advance(30 * time.Minute)
	d2 := startTestDaemon(t, clock, "unixgram", dbPath, expiryRules("1m"))
	d2.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/big", 200, 150))
	d2.waitProcessed(t, 1)
	doc = d2.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("after re-trigger: %+v, want 1", doc.Reports)
	}
	r := doc.Reports[0]
	if r.CreatedAt != wallBase {
		t.Errorf("created_at = %q, want fixed %q", r.CreatedAt, wallBase)
	}
	if r.UpdatedAt != "2025-10-17T18:30:00Z" || r.ExpiresAt != "2025-10-17T18:31:00Z" {
		t.Errorf("updated_at/expires_at = %q/%q, want 2025-10-17T18:30:00Z/2025-10-17T18:31:00Z "+
			"(unconditional refresh over the later-expiring 2025-10-18T18:00:00Z)", r.UpdatedAt, r.ExpiresAt)
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
