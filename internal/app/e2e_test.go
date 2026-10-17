package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	bandage "github.com/HT4w5/bandage/internal/domain"
	"github.com/HT4w5/bandage/internal/identity"
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

// testDaemon bundles a running daemon with a raw-line sender and the
// captured log records (log actions are observable through the daemon's
// injectable logger).
type testDaemon struct {
	*Daemon
	send func(line string)
	logs *logCapture
}

// logCapture is a concurrency-safe zerolog writer that records every
// record's level, message and fields for assertions — the daemon seam's
// log capture (spec: Log capture), reworked from a stdlib slog handler
// to a zerolog writer capturing decoded fields.
type logCapture struct {
	mu   sync.Mutex
	buf  []byte
	recs []capturedLog
}

type capturedLog struct {
	Level   zerolog.Level
	Message string
	Attrs   map[string]any
}

// Write collects the JSON log records (one per line) and decodes each
// into a capturedLog.
func (c *logCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buf = append(c.buf, p...)
	for {
		i := bytes.IndexByte(c.buf, '\n')
		if i < 0 {
			break
		}
		line := c.buf[:i]
		c.buf = c.buf[i+1:]
		if len(line) == 0 {
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal(line, &raw); err != nil {
			return 0, fmt.Errorf("logCapture: decode record: %w", err)
		}
		rec := capturedLog{Attrs: make(map[string]any, len(raw))}
		for k, v := range raw {
			switch k {
			case zerolog.LevelFieldName:
				if s, ok := v.(string); ok {
					rec.Level, _ = zerolog.ParseLevel(s)
				}
			case zerolog.MessageFieldName:
				rec.Message, _ = v.(string)
			default:
				rec.Attrs[k] = v
			}
		}
		c.recs = append(c.recs, rec)
	}
	return len(p), nil
}

// attrInto decodes a captured field into v through its JSON encoding:
// typed values survive the record's JSON round trip.
func attrInto(t *testing.T, rec capturedLog, key string, v any) {
	t.Helper()
	raw, ok := rec.Attrs[key]
	if !ok {
		t.Fatalf("record %q has no %q field: %+v", rec.Message, key, rec.Attrs)
	}
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal %q field %q: %v", rec.Message, key, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("unmarshal %q field %q: %v", rec.Message, key, err)
	}
}

// withMessage returns the captured records with the given message.
func (c *logCapture) withMessage(msg string) []capturedLog {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []capturedLog
	for _, r := range c.recs {
		if r.Message == msg {
			out = append(out, r)
		}
	}
	return out
}

// messages returns the captured record messages in emission order.
func (c *logCapture) messages() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.recs))
	for _, r := range c.recs {
		out = append(out, r.Message)
	}
	return out
}

func startTestDaemon(t *testing.T, clock *testClock, network, dbPath, rulesYAML string) *testDaemon {
	t.Helper()
	return startTestDaemonCfg(t, clock, network, dbPath, rulesYAML, nil)
}

// startTestDaemonCfg is startTestDaemon with a config mutation hook for
// tests that need a non-default knob (e.g. a small cache entry cap) and
// trailing daemon options applied last (e.g. a differently leveled
// logger).
func startTestDaemonCfg(t *testing.T, clock *testClock, network, dbPath, rulesYAML string, mutate func(*Config), extra ...Option) *testDaemon {
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
		// The existing suite asserts exact accumulation values, so it
		// runs the deterministic single-worker pipeline; the worker-pool
		// tests set pipeline.workers explicitly (ADR 0007).
		Pipeline: Pipeline{Workers: 1},
		API:      API{Listen: "127.0.0.1:0"},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	chains, err := ParseRules([]byte(rulesYAML))
	if err != nil {
		t.Fatalf("ParseRules error: %v", err)
	}
	logs := &logCapture{}
	opts := append([]Option{WithClock(clock.Now), WithLogger(zerolog.New(logs))}, extra...)
	d, err := New(cfg, chains, opts...)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	if err := d.Start(context.Background()); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	t.Cleanup(func() {
		// Close pooled HTTP connections before shutting down: the shared
		// client can leave a connection that was accepted but never used
		// (a parked spare is not idle to http.Server), and
		// http.Server.Shutdown waits on those until the peer closes them
		// (golang/go#22682). Belt and braces: the one-shot apiClient
		// never pools, but nothing may leave a connection behind.
		if tr, ok := http.DefaultTransport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
		apiClient.CloseIdleConnections()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := d.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown error: %v", err)
		}
	})

	td := &testDaemon{Daemon: d, logs: logs}
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
	if err := d.Daemon.waitProcessed(ctx, n); err != nil {
		t.Fatalf("waitProcessed(%d): %v", n, err)
	}
}

// apiClient makes one-shot HTTP calls (keep-alive disabled). A pooled
// connection the client never reuses would sit un-started on the server
// where net/http's Shutdown leaves brand-new connections alone for ~5s,
// racing the cleanup deadline; the tests must leave no connections behind.
var apiClient = &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

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
	u := "http://" + d.apiAddr() + "/reports"
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequest(http.MethodDelete, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := apiClient.Do(req)
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
	u := "http://" + d.apiAddr() + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	resp, err := apiClient.Get(u)
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
	stats := d.stats()
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
// reports. Two chains report on one event: a chain's first terminal
// match ends it, so one event reports from one rule per chain.
func TestE2EReportFiltersAndExpiry(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: abuse-one
    rules:
      - id: rule-one
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: one, ttl: 1h}}]
  - name: abuse-two
    rules:
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

	resp, err := apiClient.Get("http://" + d.apiAddr() + "/ping")
	if err != nil {
		t.Fatalf("GET /ping: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "pong" {
		t.Errorf("GET /ping = %d %q, want 200 %q", resp.StatusCode, body, "pong")
	}

	for _, path := range []string{"/", "/metrics", "/debug", "/reports/1"} {
		resp, err := apiClient.Get("http://" + d.apiAddr() + path)
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

// Bounded tracker cache (ticket 07, ADR 0002): an evicted bucket
// accumulates fresh state from zero on the next event — never a crash,
// never a stale Match — and the rule matches again after re-accumulating
// past volume.
func TestE2EEvictedBucketAccumulatesFresh(t *testing.T) {
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
	// max_entries 2: file-size enrichment shares the store (namespace
	// "filesize", ticket 05), so one slot holds its per-path record and
	// one the live tracker bucket. The store evicts per shard (the cap
	// splits into a per-shard budget of one), so the test's fixed keys
	// must place both tracker targets in one shard and the filesize
	// record in the other: FNV-1a of "bursty-api\x00203.0.113.7/32" and
	// "bursty-api\x00203.0.113.9/32" (the store keys) agree mod 2 and
	// "filesize\x00/api" differs. Then an event for another target caps
	// the cache and evicts the previous bucket (logged and counted by
	// the store).
	d := startTestDaemonCfg(t, clock, "unixgram", ":memory:", rules, func(c *Config) {
		c.Cache.MaxEntries = 2
	})

	// 203.0.113.7 overflows on its third event: value 3 > 2.
	for i := 0; i < 3; i++ {
		d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/api", 200, 0))
	}
	d.waitProcessed(t, 3)
	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 || doc.Reports[0].Tracker.Value != 3 || doc.Reports[0].UpdatedAt != wallBase {
		t.Fatalf("first trigger: %+v", doc.Reports)
	}

	// One event for another target caps the cache: 203.0.113.7's bucket
	// is evicted and restarts from zero on its next event, so that event
	// must not Match — the report stays untouched.
	clock.Advance(10 * time.Minute)
	d.send(nginxLine(eventTime2, "203.0.113.9", "GET", "/api", 200, 0))
	d.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/api", 200, 0))
	d.waitProcessed(t, 5)
	// The eviction of the old bucket is logged with its tracker
	// namespace and Target (ticket 07): nothing resets silently.
	if evictions := d.logs.withMessage("tracker cache eviction"); !slices.ContainsFunc(evictions, func(r capturedLog) bool {
		return r.Attrs["namespace"] == "bursty-api" && r.Attrs["target"] == "203.0.113.7/32"
	}) {
		t.Errorf("eviction log for bursty-api/203.0.113.7/32 missing in %v", evictions)
	}
	doc = d.getReports(t, nil)
	if len(doc.Reports) != 1 || doc.Reports[0].UpdatedAt != wallBase || doc.Reports[0].Tracker.Value != 3 {
		t.Fatalf("after eviction + one fresh event: %+v, want untouched report (no stale Match)", doc.Reports)
	}

	// The rule matches again after the tracker re-accumulates past
	// volume from zero: value 3 > 2 refreshes the same (rule, target) row.
	clock.Advance(10 * time.Minute)
	d.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/api", 200, 0))
	d.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/api", 200, 0))
	d.waitProcessed(t, 7)
	doc = d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want 1", doc.Reports)
	}
	r := doc.Reports[0]
	if r.Tracker.Value != 3 {
		t.Errorf("tracker value = %v, want 3 (fresh accumulation after eviction)", r.Tracker.Value)
	}
	if r.CreatedAt != wallBase {
		t.Errorf("created_at = %q, want %q (identity unchanged)", r.CreatedAt, wallBase)
	}
	if r.UpdatedAt != "2025-10-17T18:20:00Z" {
		t.Errorf("updated_at = %q, want %q (the report triggered again)", r.UpdatedAt, "2025-10-17T18:20:00Z")
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
  - name: abuse-one
    rules:
      - id: rule-one
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: one, ttl: 1h}}]
  - name: abuse-two
    rules:
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
  - name: one
    rules:
      - id: rule-one
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: one, ttl: 1h}}]
  - name: three
    rules:
      - id: rule-three
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: three, ttl: 1h}}]
  - name: two
    rules:
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

// A rule's filter gates its tracker: non-matching events neither
// accumulate nor decay it and never match the rule.
func TestE2EFilterGatesTracker(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: gated
    rules:
      - id: gated-egress
        filter: 'path prefix "/releases" and method GET'
        tracker: {track: bandwidth, leak: 1, volume: 20}
        actions: [{report: {reason: gated-overflow, ttl: 24h}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)

	// Non-matching traffic alone must not overflow the tracker, even at
	// sizes that would (500 > 20).
	d.send(nginxLine("1734345900", "203.0.113.7", "GET", "/api/data", 200, 500))
	d.send(nginxLine("1734345901", "203.0.113.7", "POST", "/releases/24.04.iso", 200, 500))
	d.waitProcessed(t, 2)
	if doc := d.getReports(t, nil); len(doc.Reports) != 0 {
		t.Fatalf("reports after non-matching traffic = %+v, want none", doc.Reports)
	}

	// Matching events see only their own contributions. Two events at the
	// same second accumulate 10 + 10 = 20 (no overflow at volume 20); the
	// non-matching 500-byte event far in the future must neither
	// accumulate nor move LastUpdate; the third matching event at t+2
	// then decays 2s and overflows: 20 + 10 − 2 = 28 > 20. Had the
	// non-matching event touched the tracker it would have drained it to
	// zero and its later LastUpdate would suppress decay on the
	// out-of-order third event (increment only → 10), never overflowing.
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/releases/24.04.iso", 200, 10))
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/releases/24.04.iso", 200, 10))
	d.send(nginxLine("1734345984.123", "203.0.113.7", "GET", "/api/data", 200, 500))
	d.send(nginxLine("1734345936.123", "203.0.113.7", "GET", "/releases/24.04.iso", 200, 10))
	d.waitProcessed(t, 6)

	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want exactly one (the gated rule)", doc.Reports)
	}
	r := doc.Reports[0]
	if r.Rule != "gated-egress" || r.Reason != "gated-overflow" {
		t.Errorf("provenance = %q/%q", r.Rule, r.Reason)
	}
	if r.Tracker.Value != 28 {
		t.Errorf("tracker value = %v, want 28 (non-matching events must not accumulate or decay)", r.Tracker.Value)
	}
	if r.Sample.Path != "/releases/24.04.iso" {
		t.Errorf("sample path = %q, want the matching event", r.Sample.Path)
	}

	// Once the tracker overflows, non-matching events still never match:
	// this one would re-trigger the report and bump updated_at if the
	// filter did not gate.
	clock.Advance(time.Hour)
	d.send(nginxLine("1734345936.123", "203.0.113.7", "POST", "/releases/24.04.iso", 200, 500))
	d.waitProcessed(t, 7)
	doc = d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want exactly one", doc.Reports)
	}
	if doc.Reports[0].UpdatedAt != wallBase {
		t.Errorf("updated_at = %q, want %q (non-matching events must never match)", doc.Reports[0].UpdatedAt, wallBase)
	}
}

// goto runs the target chain and then ends the current chain (DECISIONS
// §1: flux's buildStmtGoto is buggy and behaves as jump — this test
// cannot pass with that port). The topic chain's rule overflows only on
// its second traversal of one event (rate leak=0 volume=1): the report
// after a single event proves goto ran the target chain, and the missing
// after-goto report proves goto ended the routing chain.
func TestE2EGotoRunsTargetAndEndsCurrentChain(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: routing
    rules:
      - id: route-to-topic
        actions: [{goto: topic}]
      - id: after-goto
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: after-goto, ttl: 1h}}]
  - name: topic
    rules:
      - id: topic-match
        tracker: {track: rate, leak: 0, volume: 1}
        actions: [{report: {reason: topic-match, ttl: 1h}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d.waitProcessed(t, 1)

	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want exactly the topic-match report (after-goto must not match)", doc.Reports)
	}
	r := doc.Reports[0]
	if r.Rule != "topic-match" || r.Reason != "topic-match" {
		t.Errorf("report = %q/%q, want topic-match/topic-match", r.Rule, r.Reason)
	}
	if r.Tracker.Value != 2 {
		// One increment from the goto-entered traversal and one from
		// the chain's own top-level traversal.
		t.Errorf("tracker value = %v, want 2 (goto runs the target chain)", r.Tracker.Value)
	}
}

// jump runs the target chain and then resumes the current chain: the
// rule after the jump still runs on the same event.
func TestE2EJumpRunsTargetAndResumesCurrentChain(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: routing
    rules:
      - id: route-to-topic
        actions: [{jump: topic}]
      - id: after-jump
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: after-jump, ttl: 1h}}]
  - name: topic
    rules:
      - id: topic-match
        tracker: {track: rate, leak: 0, volume: 1}
        actions: [{report: {reason: topic-match, ttl: 1h}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d.waitProcessed(t, 1)

	doc := d.getReports(t, nil)
	got := make(map[string]bool, len(doc.Reports))
	for _, r := range doc.Reports {
		got[r.Rule] = true
	}
	if len(doc.Reports) != 2 || !got["after-jump"] || !got["topic-match"] {
		t.Fatalf("reports = %+v, want after-jump (resumed) and topic-match (jumped)", doc.Reports)
	}
}

// Rules within a chain run in order and the first match of a terminal
// rule ends the chain: later rules are skipped even when they would
// match, while a non-terminal match (log/jump only) lets traversal
// continue to the next rule.
func TestE2EFirstMatchPerChainEndsTraversal(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: order
    rules:
      - id: first-match
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: first-match, ttl: 1h}}]
      - id: second-match
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: second-match, ttl: 1h}}]
  - name: continue
    rules:
      - id: non-terminal
        actions: [{log: "debug,CONT:"}]
      - id: after-non-terminal
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: after-non-terminal, ttl: 1h}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d.waitProcessed(t, 1)

	doc := d.getReports(t, nil)
	got := make(map[string]bool, len(doc.Reports))
	for _, r := range doc.Reports {
		got[r.Rule] = true
	}
	if len(doc.Reports) != 2 || !got["first-match"] || !got["after-non-terminal"] {
		t.Fatalf("reports = %+v, want first-match and after-non-terminal (second-match skipped)", doc.Reports)
	}
}

// stop ends traversal of its chain only: other chains are still
// evaluated for the same event.
func TestE2EStopEndsChainWithoutStoppingOtherChains(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: halt
    rules:
      - id: stop-here
        actions: [stop]
      - id: after-stop
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: after-stop, ttl: 1h}}]
  - name: topic
    rules:
      - id: topic-match
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: topic-match, ttl: 1h}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d.waitProcessed(t, 1)

	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 || doc.Reports[0].Rule != "topic-match" {
		t.Fatalf("reports = %+v, want only topic-match (stop ends its chain, not the others)", doc.Reports)
	}
}

// log actions log the rule, its Target, the Event and the rule's
// tracker reading at the Match (PLAN §1), in flux's "level,message"
// shape: the level and message name the record, the fields are
// attached.
func TestE2ELogActionLogsEventAndTrackerReading(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: debugging
    rules:
      - id: seen
        actions: [{log: "debug,SEEN:"}]
      - id: overflow
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions:
          - log: "info,OVERFLOW:"
          - report: {reason: overflow, ttl: 1h}
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d.waitProcessed(t, 1)

	wantTime := time.Unix(1734345934, 123000000) // eventTime1 as parsed
	checkLog := func(msg string, level zerolog.Level, wantRule, wantTarget string, wantTracker bandage.TrackerReading) {
		t.Helper()
		recs := d.logs.withMessage(msg)
		if len(recs) != 1 {
			t.Fatalf("%q records = %+v, want exactly 1", msg, recs)
		}
		rec := recs[0]
		if rec.Level != level {
			t.Errorf("%q level = %v, want %v", msg, rec.Level, level)
		}
		if rec.Attrs["rule"] != wantRule {
			t.Errorf("%q rule = %v, want %q", msg, rec.Attrs["rule"], wantRule)
		}
		if rec.Attrs["target"] != wantTarget {
			t.Errorf("%q target = %v, want %q", msg, rec.Attrs["target"], wantTarget)
		}
		var ev bandage.Event
		attrInto(t, rec, "event", &ev)
		if ev.RemoteAddr.String() != "203.0.113.7" || ev.Method != "GET" || ev.Path != "/big" ||
			ev.Status != 200 || ev.SentBytes != 150 || !ev.Time.Equal(wantTime) {
			t.Errorf("%q logged event = %+v, want the parsed /big event", msg, ev)
		}
		var tracker bandage.TrackerReading
		attrInto(t, rec, "tracker", &tracker)
		if tracker != wantTracker {
			t.Errorf("%q tracker reading = %+v, want %+v", msg, tracker, wantTracker)
		}
	}

	// Log content is contractual here (spec story 18: a log action
	// "logs the event and the tracker reading" — Testing Decisions:
	// never assert log text except where logging is the contract).
	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want the overflow rule's report", doc.Reports)
	}
	// The trigger-time reading is report evidence (story 34): the log
	// record's reading must equal it — kind, leak and volume shaped by
	// the rule's config — and never a hand-computed bucket value.
	reportReading := doc.Reports[0].Tracker
	if reportReading.Track != "bandwidth" || reportReading.Leak != 0 || reportReading.Volume != 100 {
		t.Errorf("report reading shape = %+v, want {bandwidth 0 100} from the rule's config", reportReading)
	}

	// A tracker-less rule matches on filter alone and logs an empty
	// reading; the tracker rule logs the trigger-time reading. The
	// Target is the report's Target — the event's source aggregated to
	// the tracker's prefix; the tracker-less rule uses the default
	// per-address aggregation (203.0.113.7 → 203.0.113.7/32).
	checkLog("SEEN:", zerolog.DebugLevel, "seen", "203.0.113.7/32", bandage.TrackerReading{})
	checkLog("OVERFLOW:", zerolog.InfoLevel, "overflow", "203.0.113.7/32", reportReading)
}

// Level filtering is observable (spec: level filtering): a daemon
// logger built from a configured level keeps records at or above it and
// drops the rest — the domain's four words map onto the real levels.
func TestE2ELevelFilteringDropsRecordsBelowConfiguredLevel(t *testing.T) {
	rules := `
version: 0
chains:
  - name: levels
    rules:
      - id: debug-log
        actions: [{log: "debug,DEBUG-MARK:"}]
      - id: info-log
        actions: [{log: "info,INFO-MARK:"}]
      - id: warn-log
        actions: [{log: "warn,WARN-MARK:"}]
`
	tests := []struct {
		level bandage.Level
		want  []string
		gone  []string
	}{
		{level: bandage.LevelInfo, want: []string{"INFO-MARK:", "WARN-MARK:"}, gone: []string{"DEBUG-MARK:"}},
		{level: bandage.LevelWarn, want: []string{"WARN-MARK:"}, gone: []string{"DEBUG-MARK:", "INFO-MARK:"}},
	}
	for _, tt := range tests {
		t.Run(tt.level.String(), func(t *testing.T) {
			clock := newTestClock(mustTime(t, wallBase))
			buf := &syncBuffer{}
			d := startTestDaemonCfg(t, clock, "unixgram", ":memory:", rules, nil, WithLogger(NewLogger(buf, tt.level)))
			d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
			d.waitProcessed(t, 1)

			out := buf.String()
			for _, msg := range tt.gone {
				if strings.Contains(out, msg) {
					t.Errorf("%q record present below the configured %s level:\n%s", msg, tt.level, out)
				}
			}
			for _, msg := range tt.want {
				if !strings.Contains(out, msg) {
					t.Errorf("%q record absent at the configured %s level:\n%s", msg, tt.level, out)
				}
			}
		})
	}
}

// syncBuffer is a concurrency-safe log sink for tests that assert on
// the rendered output: the daemon logs from several goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// Chains are traversed in file order and rules within a chain in order;
// goto runs its target chain at the point of dispatch and then ends the
// current chain (its later rules skipped), while later chains are still
// evaluated for the event.
func TestE2EChainFileOrderAndFirstMatchSemantics(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: alpha
    rules:
      - id: a1
        actions: [{log: "debug,MARK:A1"}]
      - id: a2
        actions: [{log: "debug,MARK:A2"}, {goto: gamma}]
      - id: a3
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: a3, ttl: 1h}}]
  - name: beta
    rules:
      - id: b1
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{log: "debug,MARK:B1"}, {report: {reason: b1, ttl: 1h}}]
  - name: gamma
    rules:
      - id: g1
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{log: "debug,MARK:G1"}, {report: {reason: g1, ttl: 1h}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d.waitProcessed(t, 1)

	// Traversal facts from report evidence: gamma's rule reports twice
	// (150 + 150 bytes), so gamma ran both at a2's dispatch and at its
	// own file-order traversal; a3 is absent, so goto ended alpha; b1
	// reports, so later chains were still evaluated.
	doc := d.getReports(t, nil)
	byRule := make(map[string]reportEntry, len(doc.Reports))
	for _, r := range doc.Reports {
		byRule[r.Rule] = r
	}
	if len(doc.Reports) != 2 {
		t.Fatalf("reports = %+v, want exactly b1 and g1", doc.Reports)
	}
	if _, ok := byRule["a3"]; ok {
		t.Errorf("reports = %+v, want no a3 (goto ends its chain)", doc.Reports)
	}
	if _, ok := byRule["b1"]; !ok {
		t.Errorf("reports = %+v, want b1 (later chains still evaluated)", doc.Reports)
	}
	g1, ok := byRule["g1"]
	if !ok {
		t.Fatalf("reports = %+v, want g1 (goto runs the target chain)", doc.Reports)
	}
	if g1.Tracker.Value != 300 {
		t.Errorf("g1 tracker value = %v, want 300 (dispatch plus file-order traversal)", g1.Tracker.Value)
	}

	// The remaining fact — the emission order within the one event — is
	// only observable as log content, and log content IS the contract
	// for the log action (spec story 18: "logs the event and the tracker
	// reading"; Testing Decisions: never assert log text except where
	// logging is the contract). The markers are the action's message
	// argument.
	var got []string
	for _, msg := range d.logs.messages() {
		if strings.HasPrefix(msg, "MARK:") {
			got = append(got, msg)
		}
	}
	want := []string{"MARK:A1", "MARK:A2", "MARK:G1", "MARK:B1", "MARK:G1"}
	if !slices.Equal(got, want) {
		t.Errorf("log order = %v, want %v (file order, rule order, dispatch, termination)", got, want)
	}
}

// A terminal rule runs its FULL action list before ending its chain
// (spec: Actions and control flow): goto runs the target chain mid-list,
// the report after it still runs, and only then does the chain end.
func TestE2EFullActionListRunsBeforeTerminality(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: dispatch
    rules:
      - id: route
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions:
          - goto: topic
          - report: {reason: routed, ttl: 1h}
      - id: after
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: after, ttl: 1h}}]
  - name: topic
    rules:
      - id: topic-match
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: topic-match, ttl: 1h}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d.waitProcessed(t, 1)

	doc := d.getReports(t, nil)
	byRule := make(map[string]reportEntry, len(doc.Reports))
	for _, r := range doc.Reports {
		byRule[r.Rule] = r
	}
	if len(doc.Reports) != 2 {
		t.Fatalf("reports = %+v, want exactly routed and topic-match", doc.Reports)
	}
	if r, ok := byRule["route"]; !ok || r.Reason != "routed" {
		t.Errorf("reports = %+v, want route/routed (the report after goto still runs)", doc.Reports)
	}
	if _, ok := byRule["after"]; ok {
		t.Errorf("reports = %+v, want no after (goto ends its chain)", doc.Reports)
	}
	topic, ok := byRule["topic-match"]
	if !ok {
		t.Fatalf("reports = %+v, want topic-match (goto runs the target chain)", doc.Reports)
	}
	// The topic chain ran twice for the one event — once at the goto
	// dispatch and once at its own file-order traversal — so its
	// tracker accumulated 2×150 bytes.
	if topic.Tracker.Value != 300 {
		t.Errorf("topic-match tracker value = %v, want 300 (dispatch plus file-order traversal)", topic.Tracker.Value)
	}
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

// File-size enrichment is per path with a warm-up gate (period 5,
// minSamples 5 — DECISIONS §3): the replay tracker is blind until a
// path's estimate warms, then accumulates transferred fractions of the
// estimated size per (Target, path) and reports the computed volume with
// the enriched sample size.
func TestE2EReplayWarmUpBlindThenReports(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: download-abuse
    rules:
      - id: iso-replay
        tracker: {track: replay, leak: 0, volume: 2}
        actions: [{report: {reason: iso-replay, ttl: 1h}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)

	// Warm-up (the first 4 of 5 samples): the size estimate is unknown,
	// so every event is skipped entirely. Volume 2 would overflow on the
	// second transfer had anything accumulated.
	for i := 0; i < 4; i++ {
		d.send(nginxLine(fmt.Sprintf("%d", 1734345934+i), "203.0.113.7", "GET", "/releases/24.04.iso", 200, 1000))
	}
	d.waitProcessed(t, 4)
	if doc := d.getReports(t, nil); len(doc.Reports) != 0 {
		t.Fatalf("reports during warm-up = %+v, want none (replay is blind until the estimate warms)", doc.Reports)
	}

	// Samples 5..7 are enriched (size 1000): each full transfer adds
	// fraction 1, and value 3 > volume 2 overflows on the third.
	for i := 4; i < 7; i++ {
		d.send(nginxLine(fmt.Sprintf("%d", 1734345934+i), "203.0.113.7", "GET", "/releases/24.04.iso", 200, 1000))
	}
	d.waitProcessed(t, 7)
	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports after warm-up = %+v, want 1", doc.Reports)
	}
	r := doc.Reports[0]
	if r.Tracker.Track != "replay" || r.Tracker.Value != 3 || r.Tracker.Leak != 0 || r.Tracker.Volume != 2 {
		t.Errorf("tracker = %+v, want {replay 3 0 2} (value, leak and volume at trigger)", r.Tracker)
	}
	if r.Sample.Size != 1000 || r.Sample.Sent != 1000 {
		t.Errorf("sample = %+v, want the triggering transfer with enriched size 1000", r.Sample)
	}
}

// The volume method scales tolerance with file size at trigger time and
// replay state stays separated per (Target, path): a small file (1
// tolerated equivalent) overflows while a big file of the same target
// (3 tolerated equivalents) with the same accumulated fractions does
// not.
func TestE2EReplayVolumeMethodScalesTolerance(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: download-abuse
    rules:
      - id: iso-replay
        tracker:
          track: replay
          leak: 0
          volume: {method: step, threshold: 1000, volume_low: 1, volume_high: 3}
        actions: [{report: {reason: iso-replay, ttl: 1h}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)

	// Interleave small (100 B) and big (10 000 B) transfers of two paths
	// from one client: each path warms and accumulates on its own.
	for i := 0; i < 6; i++ {
		d.send(nginxLine(fmt.Sprintf("%d", 1734345934+2*i), "203.0.113.7", "GET", "/small.iso", 200, 100))
		d.send(nginxLine(fmt.Sprintf("%d", 1734345935+2*i), "203.0.113.7", "GET", "/big.iso", 200, 10000))
	}
	d.waitProcessed(t, 12)

	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want exactly the small file's (the big file stays under its tolerance)", doc.Reports)
	}
	r := doc.Reports[0]
	// The small file's samples 5 and 6 add fraction 1 each: value 2
	// overflows its volume 1 — the step method's volume_low at size 100.
	if r.Tracker.Track != "replay" || r.Tracker.Value != 2 || r.Tracker.Volume != 1 {
		t.Errorf("tracker = %+v, want {replay 2 0 1} (volume_low at size 100)", r.Tracker)
	}
	if r.Sample.Path != "/small.iso" || r.Sample.Size != 100 {
		t.Errorf("sample = %+v, want /small.iso with enriched size 100", r.Sample)
	}
}

// The daemon's startup log record carries the build identity fields —
// name, version, commit and build date (spec story 14, ticket 02) — so
// the log stream itself identifies the running build. The test binary is
// not linker-injected, so the values are the identity module's defaults.
func TestStartupLogCarriesBuildIdentity(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	d := startTestDaemon(t, clock, "unixgram", ":memory:", bandwidthRules)

	recs := d.logs.withMessage("starting")
	if len(recs) != 1 {
		t.Fatalf("starting records = %d, want 1", len(recs))
	}
	attrs := recs[0].Attrs
	if attrs["name"] != identity.Name {
		t.Errorf("name = %v, want %q", attrs["name"], identity.Name)
	}
	if attrs["version"] != identity.Version() {
		t.Errorf("version = %v, want %q", attrs["version"], identity.Version())
	}
	if attrs["commit"] != identity.Commit() {
		t.Errorf("commit = %v, want %q", attrs["commit"], identity.Commit())
	}
	if attrs["build_date"] != identity.BuildDate() {
		t.Errorf("build_date = %v, want %q", attrs["build_date"], identity.BuildDate())
	}
}
