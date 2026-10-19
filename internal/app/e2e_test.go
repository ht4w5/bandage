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
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"

	bandage "github.com/HT4w5/bandage/internal/domain"
	"github.com/HT4w5/bandage/internal/identity"
)

// Primary seam: the assembled daemon driven by raw nginx-JSON syslog messages
// at a real ingest listener, asserted through GET /reports JSON.

// testClock is the injected wall clock every seam runs on (never sleep);
// reads are atomic because the clock also sits in measured benchmark paths.
type testClock struct {
	t atomic.Pointer[time.Time]
}

func newTestClock(t time.Time) *testClock {
	c := &testClock{}
	c.t.Store(&t)
	return c
}

func (c *testClock) Now() time.Time { return *c.t.Load() }

func (c *testClock) Advance(d time.Duration) {
	for {
		old := c.t.Load()
		next := old.Add(d)
		if c.t.CompareAndSwap(old, &next) {
			return
		}
	}
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

// testDaemon bundles a running daemon with a raw-line sender and captured
// log records.
type testDaemon struct {
	*Daemon
	send func(line string)
	logs *logCapture
}

// logCapture is a concurrency-safe zerolog writer that records every
// record's level, message and fields for assertions.
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

// attrInto decodes a captured field into v through its JSON encoding.
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

// startTestDaemonCfg is startTestDaemon with a config mutation hook and
// trailing daemon options.
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
		// The suite asserts exact accumulation values, so it runs the
		// deterministic single-worker pipeline.
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
		// Close pooled HTTP connections first: http.Server.Shutdown waits
		// on accepted-but-unused connections (golang/go#22682).
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

// freeAddr reserves a free listen address for the network; the probe matches
// the network's transport (a TCP-free port may be busy for UDP).
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

// apiClient makes one-shot HTTP calls (keep-alive disabled) so no pooled
// connection can outlive a test and race the cleanup deadline.
var apiClient = &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

// penaltyEntry mirrors the report entry's nested penalty object: the
// action always, its rate exactly for a limit action.
type penaltyEntry struct {
	Action string `json:"action"`
	Rate   *int64 `json:"rate"`
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
	Penalty *penaltyEntry `json:"penalty"`
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

// statsDoc is the /stats document decoded loosely into a generic map:
// the shape is human-facing and unversioned, so never assert field-for-field.
type statsDoc map[string]any

// getStats issues GET /stats and returns the raw body plus the decoded
// document.
func (d *testDaemon) getStats(t *testing.T) ([]byte, statsDoc) {
	t.Helper()
	resp, err := apiClient.Get("http://" + d.apiAddr() + "/stats")
	if err != nil {
		t.Fatalf("GET /stats: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /stats status = %d, want 200 (body %q)", resp.StatusCode, body)
	}
	var doc statsDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("GET /stats: bad JSON %q: %v", body, err)
	}
	return body, doc
}

// statsNum reads one numeric field out of a /stats block.
func statsNum(t *testing.T, doc statsDoc, block, field string) float64 {
	t.Helper()
	b, ok := doc[block].(map[string]any)
	if !ok {
		t.Fatalf("/stats has no %q block: %v", block, doc)
	}
	v, ok := b[field].(float64)
	if !ok {
		t.Fatalf("/stats %q has no numeric %q: %v", block, field, b)
	}
	return v
}

// statsStr reads one string field out of a /stats block.
func statsStr(t *testing.T, doc statsDoc, block, field string) string {
	t.Helper()
	b, ok := doc[block].(map[string]any)
	if !ok {
		t.Fatalf("/stats has no %q block: %v", block, doc)
	}
	v, ok := b[field].(string)
	if !ok {
		t.Fatalf("/stats %q has no string %q: %v", block, field, b)
	}
	return v
}

// statsBool reads one boolean field out of a /stats block.
func statsBool(t *testing.T, doc statsDoc, block, field string) bool {
	t.Helper()
	b, ok := doc[block].(map[string]any)
	if !ok {
		t.Fatalf("/stats has no %q block: %v", block, doc)
	}
	v, ok := b[field].(bool)
	if !ok {
		t.Fatalf("/stats %q has no boolean %q: %v", block, field, b)
	}
	return v
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
              penalty: limit-bandwidth
              rate: 1MB
`

// TestE2EOverflowWritesReport: overflow writes exactly one report carrying
// rule, chain, reason, target, timestamps, tracker reading and sample.
func TestE2EOverflowWritesReport(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	d := startTestDaemon(t, clock, "unixgram", ":memory:", bandwidthRules)

	// 6000 + 6000 - 1000*1s = 11000 > 10000: overflows on the second event.
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

// TestE2ERateOverflowStrictlyAboveVolume: the tracker overflows strictly
// above volume (leak=0, volume=2 -> third request triggers).
func TestE2ERateOverflowStrictlyAboveVolume(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: api
    rules:
      - id: bursty-api
        tracker: {track: rate, leak: 0, volume: 2}
        actions: [{report: {reason: api-rate-overflow, ttl: 1h, penalty: limit-req-rate, rate: 200}}]
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

// TestE2EDecayUsesEventTime: decay is computed from event time, not wall
// time: steady events drain, a same-second burst overflows.
func TestE2EDecayUsesEventTime(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: api
    rules:
      - id: bursty-api
        tracker: {track: rate, leak: 1, volume: 4}
        actions: [{report: {reason: api-rate-overflow, ttl: 1h, penalty: limit-req-rate, rate: 200}}]
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

	// A six-request burst at one event time accumulates 1..5; value 5 > 4
	// overflows.
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

// TestE2EMalformedLinesDroppedAndCounted: malformed lines and invalid
// required fields are dropped and counted.
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
	stats := d.counters()
	if stats.Dropped != 2 {
		t.Errorf("stats dropped = %d, want 2", stats.Dropped)
	}
	if stats.Parsed != 1 {
		t.Errorf("stats parsed = %d, want 1", stats.Parsed)
	}
}

// TestE2EReportUpsertIdentity: one report per (rule, target) with row
// identity; a live report's write is suppressed and frozen at its first write.
func TestE2EReportUpsertIdentity(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: abuse
    rules:
      - id: byte-flood
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: byte-flood, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)

	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d.waitProcessed(t, 1)
	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 || doc.Reports[0].CreatedAt != wallBase {
		t.Fatalf("after first trigger: %+v", doc.Reports)
	}

	clock.Advance(10 * time.Minute)
	d.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/big", 200, 150)) // re-Triggers: write suppressed
	d.send(nginxLine(eventTime2, "203.0.113.8", "GET", "/big", 200, 150)) // a new (rule, target) writes
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
	// The re-Trigger wrote nothing: the live report freezes at the first
	// write (Sample and update time unchanged).
	if second.CreatedAt != wallBase || second.UpdatedAt != wallBase || second.ExpiresAt != "2025-10-17T19:00:00Z" {
		t.Errorf("created_at/updated_at/expires_at = %q/%q/%q, want all frozen at the first write",
			second.CreatedAt, second.UpdatedAt, second.ExpiresAt)
	}
	if second.Tracker.Value != 150 {
		t.Errorf("tracker value = %v, want 150 (the first Trigger's reading, frozen)", second.Tracker.Value)
	}
	if second.Sample.Time != eventTime1At {
		t.Errorf("sample time = %q, want %q (frozen)", second.Sample.Time, eventTime1At)
	}
	if first.UpdatedAt != "2025-10-17T18:10:00Z" {
		t.Errorf("new report updated_at = %q", first.UpdatedAt)
	}

	// Past expiry (19:00) the next Trigger upserts the still-stored row:
	// created_at stays fixed while updated_at and expires_at recompute.
	clock.Advance(90 * time.Minute) // 19:40
	d.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/big", 200, 150))
	d.waitProcessed(t, 4)

	doc = d.getReports(t, nil)
	if len(doc.Reports) != 1 { // 203.0.113.8's report expired at 19:10 and is never returned
		t.Fatalf("reports = %+v, want the upserted 203.0.113.7 row", doc.Reports)
	}
	r := doc.Reports[0]
	if r.Target != "203.0.113.7/32" {
		t.Fatalf("target = %q, want 203.0.113.7/32", r.Target)
	}
	if r.CreatedAt != wallBase {
		t.Errorf("created_at = %q, want fixed %q (upsert identity over the stored row)", r.CreatedAt, wallBase)
	}
	if r.UpdatedAt != "2025-10-17T19:40:00Z" || r.ExpiresAt != "2025-10-17T20:40:00Z" {
		t.Errorf("updated_at/expires_at = %q/%q, want the 19:40 write's", r.UpdatedAt, r.ExpiresAt)
	}
	if r.Tracker.Value != 150 {
		t.Errorf("tracker value = %v, want 150 (a fresh episode)", r.Tracker.Value)
	}
	if r.Sample.Time != eventTime2At {
		t.Errorf("sample time = %q, want %q", r.Sample.Time, eventTime2At)
	}
}

// TestE2EReportFiltersAndExpiry: GET /reports filters by ?rule= and ?target=
// and never returns expired reports.
func TestE2EReportFiltersAndExpiry(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: abuse-one
    rules:
      - id: rule-one
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: one, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
  - name: abuse-two
    rules:
      - id: rule-two
        filter: any
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: two, ttl: 2h, penalty: limit-bandwidth, rate: 1MB}}]
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

// TestE2EStatsBuildAndCumulativeCounters: /stats answers with the build
// identity and cumulative counters, as human-facing indented JSON.
func TestE2EStatsBuildAndCumulativeCounters(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	d := startTestDaemonCfg(t, clock, "unixgram", ":memory:", bandwidthRules, func(c *Config) {
		c.Pipeline.Workers = 3
	})

	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 4000))
	d.send("this is not json")
	d.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/big", 200, 3000))
	d.waitProcessed(t, 3)
	clock.Advance(90 * time.Second)

	body, doc := d.getStats(t)
	if !bytes.HasPrefix(body, []byte("{\n  \"")) {
		t.Errorf("/stats body = %q, want indented JSON", body)
	}
	if _, ok := doc["version"]; ok {
		t.Errorf("/stats carries a format version %v, want none (human-facing, unversioned)", doc["version"])
	}
	if got := doc["generated_at"]; got != "2025-10-17T18:01:30Z" {
		t.Errorf("generated_at = %v, want %q", got, "2025-10-17T18:01:30Z")
	}
	if got := doc["uptime"]; got != "1m30s" {
		t.Errorf("uptime = %v, want %q", got, "1m30s")
	}

	// The build block mirrors the identity module (the test binary is
	// not linker-injected, so the values are the identity defaults).
	for _, f := range []struct{ field, want string }{
		{"name", identity.Name},
		{"version", identity.Version()},
		{"commit", identity.Commit()},
		{"build_date", identity.BuildDate()},
		{"go_version", identity.GoVersion()},
		{"platform", identity.Platform()},
	} {
		if got := statsStr(t, doc, "build", f.field); got != f.want {
			t.Errorf("build.%s = %q, want %q", f.field, got, f.want)
		}
	}
	if got := statsBool(t, doc, "build", "dirty"); got != identity.Dirty() {
		t.Errorf("build.dirty = %v, want %v", got, identity.Dirty())
	}

	// The pipeline block: the resolved worker count and exact line
	// accounting under the worker pool.
	for _, f := range []struct {
		field string
		want  float64
	}{
		{"workers", 3},
		{"received", 3},
		{"parsed", 2},
		{"dropped", 1},
	} {
		if got := statsNum(t, doc, "pipeline", f.field); got != f.want {
			t.Errorf("pipeline.%s = %v, want %v", f.field, got, f.want)
		}
	}

	// The tracker cache block: each parsed event updated the shared store
	// twice (file-size record + tracker bucket), and both records stay live.
	for _, f := range []struct {
		field string
		want  float64
	}{
		{"gets", 4},
		{"sets", 4},
		{"misses", 2},
		{"evictions", 0},
		{"size", 2},
		{"entry_cap", 65536},
	} {
		if got := statsNum(t, doc, "tracker_cache", f.field); got != f.want {
			t.Errorf("tracker_cache.%s = %v, want %v", f.field, got, f.want)
		}
	}
}

// TestE2EStatisticsLogAgreesWithStats: the periodic statistics log line's
// counters agree with /stats (both render the same snapshot).
func TestE2EStatisticsLogAgreesWithStats(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	d := startTestDaemon(t, clock, "unixgram", ":memory:", bandwidthRules)

	// Three parses on one path and one dropped line give every counter a
	// distinct value (cache_gets == cache_sets is structural: every
	// Update counts one of each). Distinct absolutes pin each counter to
	// its key; agreement with /stats alone would let equal-valued
	// counters swap places unnoticed.
	//
	// The third event alone exceeds volume (3000+3000+12000 > 10000),
	// so its Trigger clears the tracker entry and leaves cache_size at 1.
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 3000))
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 3000))
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 12000))
	d.send("this is not json")
	d.waitProcessed(t, 4)
	d.logStatistics()

	_, doc := d.getStats(t)
	recs := d.logs.withMessage("statistics")
	if len(recs) != 1 {
		t.Fatalf("statistics records = %d, want 1", len(recs))
	}
	// attrInto fails on a missing field, so asserting every value also
	// asserts that the line keeps its long-standing fields.
	for _, f := range []struct {
		key, block, field string
		abs               int64
	}{
		{"received", "pipeline", "received", 4},
		{"parsed", "pipeline", "parsed", 3},
		{"dropped", "pipeline", "dropped", 1},
		{"cache_gets", "tracker_cache", "gets", 6},
		{"cache_sets", "tracker_cache", "sets", 6},
		{"cache_misses", "tracker_cache", "misses", 2},
		{"cache_evictions", "tracker_cache", "evictions", 0},
		{"cache_size", "tracker_cache", "size", 1},
	} {
		var v int64
		attrInto(t, recs[0], f.key, &v)
		if v != f.abs {
			t.Errorf("statistics log %s = %d, want %d", f.key, v, f.abs)
		}
		if want := statsNum(t, doc, f.block, f.field); float64(v) != want {
			t.Errorf("statistics log %s = %d, /stats %s.%s = %v, want the same counter", f.key, v, f.block, f.field, want)
		}
	}
}

// TestE2EStatsCountsEvictions: evictions surface in /stats' tracker cache
// block, counting the same events the eviction log records.
func TestE2EStatsCountsEvictions(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: api
    rules:
      - id: bursty-api
        tracker: {track: rate, leak: 0, volume: 2}
        actions: [{report: {reason: api-rate-overflow, ttl: 1h, penalty: limit-req-rate, rate: 200}}]
`
	// max_entries 1: the file-size record and the tracker bucket share
	// one slot, so inserting the bucket evicts the record.
	d := startTestDaemonCfg(t, clock, "unixgram", ":memory:", rules, func(c *Config) {
		c.Cache.MaxEntries = 1
	})

	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/api", 200, 0))
	d.waitProcessed(t, 1)

	_, doc := d.getStats(t)
	for _, f := range []struct {
		field string
		want  float64
	}{
		{"evictions", 1},
		{"size", 1},
		{"entry_cap", 1},
	} {
		if got := statsNum(t, doc, "tracker_cache", f.field); got != f.want {
			t.Errorf("tracker_cache.%s = %v, want %v", f.field, got, f.want)
		}
	}
	if evictions := d.logs.withMessage("tracker cache eviction"); len(evictions) != 1 {
		t.Errorf("eviction logs = %v, want 1 (logged and counted together)", evictions)
	}
}

// TestE2EAPIPingAndUnknownPaths: GET /ping is liveness; nothing else is
// exposed beyond the report API and the /stats snapshot.
func TestE2EAPIPingAndUnknownPaths(t *testing.T) {
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

// TestE2ERestartPersistsReportsNotTrackers: reports survive restarts (sqlite);
// tracker state is memory-only and restart-cold.
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

// TestE2ESyslogTransports: all three syslog transports accept raw nginx
// JSON lines.
func TestE2ESyslogTransports(t *testing.T) {
	rules := `
version: 0
chains:
  - name: abuse
    rules:
      - id: one-shot
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: one-shot, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
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

// TestE2EEvictedBucketAccumulatesFresh: an evicted bucket accumulates fresh
// state from zero on the next event and matches again past volume.
func TestE2EEvictedBucketAccumulatesFresh(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: api
    rules:
      - id: bursty-api
        tracker: {track: rate, leak: 0, volume: 2}
        actions: [{report: {reason: api-rate-overflow, ttl: 1h, penalty: limit-req-rate, rate: 200}}, {log: "debug,MARK:BURSTY"}]
`
	// max_entries 2 with a per-shard budget of one: the fixed keys place
	// both tracker targets in one shard and the filesize record in the other.
	d := startTestDaemonCfg(t, clock, "unixgram", ":memory:", rules, func(c *Config) {
		c.Cache.MaxEntries = 2
	})

	// 203.0.113.7 overflows on its third event (value 3 > 2); the fourth
	// event re-arms the emptied bucket at value 1, the entry an insert can evict.
	for i := 0; i < 3; i++ {
		d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/api", 200, 0))
	}
	d.waitProcessed(t, 3)
	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 || doc.Reports[0].Tracker.Value != 3 || doc.Reports[0].UpdatedAt != wallBase {
		t.Fatalf("first trigger: %+v", doc.Reports)
	}
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/api", 200, 0))
	d.waitProcessed(t, 4)

	// The new target caps the cache and evicts 203.0.113.7's bucket, so
	// that bucket's next event must not Match (no stale Match).
	clock.Advance(10 * time.Minute)
	d.send(nginxLine(eventTime2, "203.0.113.9", "GET", "/api", 200, 0))
	d.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/api", 200, 0))
	d.waitProcessed(t, 6)
	// The eviction is logged with its tracker namespace and Target.
	if evictions := d.logs.withMessage("tracker cache eviction"); !slices.ContainsFunc(evictions, func(r capturedLog) bool {
		return r.Attrs["namespace"] == "bursty-api" && r.Attrs["target"] == "203.0.113.7/32"
	}) {
		t.Errorf("eviction log for bursty-api/203.0.113.7/32 missing in %v", evictions)
	}
	// The log action shows the fresh event did not Match (the report write
	// is suppressed while the report is alive, so marks are the observable).
	if got := marks(d); len(got) != 1 {
		t.Errorf("log-action marks = %v, want 1 (only the first episode matched)", got)
	}
	doc = d.getReports(t, nil)
	if len(doc.Reports) != 1 || doc.Reports[0].UpdatedAt != wallBase || doc.Reports[0].Tracker.Value != 3 {
		t.Fatalf("after eviction + one fresh event: %+v, want untouched report (no stale Match)", doc.Reports)
	}

	// After re-accumulating past volume the rule matches again; the DELETE
	// re-arms the write (a live report would suppress it).
	if _, n := d.del(t, url.Values{"rule": {"bursty-api"}}); n != 1 {
		t.Fatalf("delete count = %d, want 1", n)
	}
	clock.Advance(10 * time.Minute)
	d.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/api", 200, 0))
	d.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/api", 200, 0))
	d.waitProcessed(t, 8)
	doc = d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want 1", doc.Reports)
	}
	r := doc.Reports[0]
	if r.Tracker.Value != 3 {
		t.Errorf("tracker value = %v, want 3 (fresh accumulation after eviction)", r.Tracker.Value)
	}
	if r.CreatedAt != "2025-10-17T18:20:00Z" || r.UpdatedAt != "2025-10-17T18:20:00Z" {
		t.Errorf("created_at/updated_at = %q/%q, want the fresh 18:20 write (the deleted row is gone)",
			r.CreatedAt, r.UpdatedAt)
	}
	if got := marks(d); len(got) != 2 {
		t.Errorf("log-action marks = %v, want 2 (one match per re-accumulated episode)", got)
	}
}

// TestE2ESyslogFramedMessage: real syslog framing (RFC3164-style) carries
// the nginx JSON as content.
func TestE2ESyslogFramedMessage(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: abuse
    rules:
      - id: one-shot
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: one-shot, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)
	d.send("<134>Dec 16 12:00:00 web1 nginx: " + nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d.waitProcessed(t, 1)
	if doc := d.getReports(t, nil); len(doc.Reports) != 1 {
		t.Errorf("reports = %+v, want 1", doc.Reports)
	}
}

// TestE2EDeleteByFilterCounts: DELETE /reports requires ?rule= and/or
// ?target= (400 without) and returns deleted-row counts per filter.
func TestE2EDeleteByFilterCounts(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: abuse-one
    rules:
      - id: rule-one
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: one, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
  - name: abuse-two
    rules:
      - id: rule-two
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: two, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)

	// Two clients in far-apart networks: aggregation never merges them.
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

// TestE2EDeleteDoesNotTouchTrackerState: deleting reports never touches
// tracker state; the reading keeps accumulating across the deletion.
func TestE2EDeleteDoesNotTouchTrackerState(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: abuse
    rules:
      - id: sticky
        tracker: {track: bandwidth, leak: 0, volume: 200}
        actions: [{report: {reason: sticky, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)

	// 150 + 150 = 300 > 200 overflows on the second event; the third
	// event re-accumulates a partial episode (150) while the report is alive.
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d.waitProcessed(t, 3)
	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 || doc.Reports[0].Tracker.Value != 300 {
		t.Fatalf("after first trigger: %+v", doc.Reports)
	}

	if _, n := d.del(t, url.Values{"rule": {"sticky"}}); n != 1 {
		t.Fatalf("delete count = %d, want 1", n)
	}
	if doc := d.getReports(t, nil); len(doc.Reports) != 0 {
		t.Fatalf("after delete: %+v, want none", doc.Reports)
	}

	// The partial episode survives the delete: the report comes back
	// carrying the accumulated reading.
	clock.Advance(10 * time.Minute)
	d.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/big", 200, 150))
	d.waitProcessed(t, 4)
	doc = d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("after re-trigger: %+v, want the report back", doc.Reports)
	}
	r := doc.Reports[0]
	if r.CreatedAt != "2025-10-17T18:10:00Z" {
		t.Errorf("created_at = %q, want a fresh %q (deleted report is gone)", r.CreatedAt, "2025-10-17T18:10:00Z")
	}
	if r.Tracker.Value != 300 {
		t.Errorf("tracker value = %v, want 300 (deletion touched no tracker state: 150 kept + 150 new)", r.Tracker.Value)
	}
	if r.Sample.Time != eventTime2At {
		t.Errorf("sample time = %q, want %q", r.Sample.Time, eventTime2At)
	}
}

// TestE2ESweeperDeletesExpiredRows: the periodic sweeper deletes expired rows
// at the injected wall clock; live rows survive the pass.
func TestE2ESweeperDeletesExpiredRows(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: one
    rules:
      - id: rule-one
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: one, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
  - name: three
    rules:
      - id: rule-three
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: three, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
  - name: two
    rules:
      - id: rule-two
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: two, ttl: 2h, penalty: limit-bandwidth, rate: 1MB}}]
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
	// ...but they are still stored until swept.
	if _, n := d.del(t, url.Values{"rule": {"rule-three"}}); n != 1 {
		t.Errorf("delete of an expired row = %d, want 1 (still stored pre-sweep)", n)
	}

	// One sweeper pass at the injected clock deletes expired rows only.
	if _, err := d.sweepOnce(context.Background()); err != nil {
		t.Fatalf("sweepOnce: %v", err)
	}
	if _, n := d.del(t, url.Values{"rule": {"rule-one"}}); n != 0 {
		t.Errorf("delete after sweep = %d, want 0 (row swept away)", n)
	}
	if _, n := d.del(t, url.Values{"rule": {"rule-two"}}); n != 1 {
		t.Errorf("delete of a live row = %d, want 1 (sweeper leaves it)", n)
	}
}

// TestE2EExpiresAtRecomputedOnWrite: expires_at recomputes from each landed
// write's ttl while created_at stays fixed at the row's first insert.
func TestE2EExpiresAtRecomputedOnWrite(t *testing.T) {
	expiryRules := func(ttl string) string {
		return fmt.Sprintf(`
version: 0
chains:
  - name: abuse
    rules:
      - id: sticky
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: sticky, ttl: %s, penalty: limit-bandwidth, rate: 1MB}}]
`, ttl)
	}
	clock := newTestClock(mustTime(t, wallBase))
	dbPath := filepath.Join(t.TempDir(), "reports.db")

	d1 := startTestDaemon(t, clock, "unixgram", dbPath, expiryRules("1m"))
	d1.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d1.waitProcessed(t, 1)
	doc := d1.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("after first trigger: %+v", doc.Reports)
	}
	if doc.Reports[0].CreatedAt != wallBase || doc.Reports[0].ExpiresAt != "2025-10-17T18:01:00Z" {
		t.Fatalf("created_at/expires_at = %q/%q, want %q/2025-10-17T18:01:00Z",
			doc.Reports[0].CreatedAt, doc.Reports[0].ExpiresAt, wallBase)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := d1.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	cancel()

	// The re-trigger writes over the expired row: expiry recomputes
	// while created_at stays fixed.
	clock.Advance(30 * time.Minute)
	d2 := startTestDaemon(t, clock, "unixgram", dbPath, expiryRules("24h"))
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
	if r.UpdatedAt != "2025-10-17T18:30:00Z" || r.ExpiresAt != "2025-10-18T18:30:00Z" {
		t.Errorf("updated_at/expires_at = %q/%q, want 2025-10-17T18:30:00Z/2025-10-18T18:30:00Z "+
			"(recomputed over the stale 2025-10-17T18:01:00Z)", r.UpdatedAt, r.ExpiresAt)
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

// TestE2EFilterGatesTracker: a rule's filter gates its tracker; non-matching
// events neither accumulate nor decay it.
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
        actions: [{report: {reason: gated-overflow, ttl: 24h, penalty: limit-bandwidth, rate: 1MB}}, {log: "debug,MARK:GATE"}]
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

	// Matching events see only their own contributions: 20 + 10 - 2 = 28
	// > 20; a touched tracker would have drained and never overflowed.
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

	// Non-matching events still never match after overflow: the log
	// action is the observable (the report write is suppressed).
	clock.Advance(time.Hour)
	d.send(nginxLine("1734345936.123", "203.0.113.7", "POST", "/releases/24.04.iso", 200, 500))
	d.waitProcessed(t, 7)
	doc = d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want exactly one", doc.Reports)
	}
	if got := marks(d); len(got) != 1 {
		t.Errorf("log-action marks = %v, want 1 (non-matching events must never match)", got)
	}
	if doc.Reports[0].UpdatedAt != wallBase {
		t.Errorf("updated_at = %q, want %q (non-matching events must never match)", doc.Reports[0].UpdatedAt, wallBase)
	}
}

// TestE2EGotoRunsTargetAndEndsCurrentChain: goto runs the target chain and
// then ends the current chain (its later rules skipped).
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
        actions: [{report: {reason: after-goto, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
  - name: topic
    rules:
      - id: topic-match
        tracker: {track: rate, leak: 0, volume: 1}
        actions: [{report: {reason: topic-match, ttl: 1h, penalty: limit-req-rate, rate: 200}}]
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

// TestE2EJumpRunsTargetAndResumesCurrentChain: jump runs the target chain
// and then resumes the current chain.
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
        actions: [{report: {reason: after-jump, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
  - name: topic
    rules:
      - id: topic-match
        tracker: {track: rate, leak: 0, volume: 1}
        actions: [{report: {reason: topic-match, ttl: 1h, penalty: limit-req-rate, rate: 200}}]
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

// TestE2EFirstMatchPerChainEndsTraversal: a terminal rule's first match ends
// the chain; a non-terminal match lets traversal continue.
func TestE2EFirstMatchPerChainEndsTraversal(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: order
    rules:
      - id: first-match
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: first-match, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
      - id: second-match
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: second-match, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
  - name: continue
    rules:
      - id: non-terminal
        actions: [{log: "debug,CONT:"}]
      - id: after-non-terminal
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: after-non-terminal, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
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

// TestE2EStopEndsChainWithoutStoppingOtherChains: stop ends traversal of its
// chain only.
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
        actions: [{report: {reason: after-stop, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
  - name: topic
    rules:
      - id: topic-match
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: topic-match, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d.waitProcessed(t, 1)

	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 || doc.Reports[0].Rule != "topic-match" {
		t.Fatalf("reports = %+v, want only topic-match (stop ends its chain, not the others)", doc.Reports)
	}
}

// TestE2ELogActionLogsEventAndTrackerReading: log actions log the rule, its
// Target, the Event and the tracker reading in "level,message" shape.
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
          - report: {reason: overflow, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}
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

	// Log content is contractual here (logging is the contract).
	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 {
		t.Fatalf("reports = %+v, want the overflow rule's report", doc.Reports)
	}
	// The log record's reading must equal the report's trigger-time reading.
	reportReading := doc.Reports[0].Tracker
	if reportReading.Track != "bandwidth" || reportReading.Leak != 0 || reportReading.Volume != 100 {
		t.Errorf("report reading shape = %+v, want {bandwidth 0 100} from the rule's config", reportReading)
	}

	// The tracker-less rule logs an empty reading; the tracker rule logs
	// the trigger-time reading. Both use per-address aggregation.
	checkLog("SEEN:", zerolog.DebugLevel, "seen", "203.0.113.7/32", bandage.TrackerReading{})
	checkLog("OVERFLOW:", zerolog.InfoLevel, "overflow", "203.0.113.7/32", reportReading)
}

// TestE2ELevelFilteringDropsRecordsBelowConfiguredLevel: a configured log
// level keeps records at or above it and drops the rest.
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

// TestE2EChainFileOrderAndFirstMatchSemantics: chains run in file order;
// goto runs its target chain at dispatch and ends the current chain.
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
        actions: [{report: {reason: a3, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
  - name: beta
    rules:
      - id: b1
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{log: "debug,MARK:B1"}, {report: {reason: b1, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
  - name: gamma
    rules:
      - id: g1
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{log: "debug,MARK:G1"}, {report: {reason: g1, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/big", 200, 150))
	d.waitProcessed(t, 1)

	// a3 is absent (goto ended alpha), b1 reports (later chains still
	// ran), and the doubled MARK:G1 shows gamma ran twice.
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
	if g1.Tracker.Value != 150 {
		t.Errorf("g1 tracker value = %v, want 150 (each Trigger empties the bucket)", g1.Tracker.Value)
	}

	// The emission order is only observable as log content, which is the
	// contract for the log action.
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

// TestE2EFullActionListRunsBeforeTerminality: a terminal rule runs its full
// action list (goto mid-list included) before ending its chain.
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
          - report: {reason: routed, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}
      - id: after
        tracker: {track: bandwidth, leak: 0, volume: 100}
        actions: [{report: {reason: after, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
  - name: topic
    rules:
      - id: topic-match
        tracker: {track: bandwidth, leak: 0, volume: 250}
        actions: [{report: {reason: topic-match, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
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
	// The topic chain ran twice (goto dispatch plus its own file-order
	// traversal), so its tracker accumulated 2x150 bytes.
	if topic.Tracker.Value != 300 {
		t.Errorf("topic-match tracker value = %v, want 300 (dispatch plus file-order traversal)", topic.Tracker.Value)
	}
}

// TestE2ETargetAggregationSharesStatePerPrefix: sources in one aggregated
// prefix share tracker state and produce one Report Target (the prefix).
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
        actions: [{report: {reason: burst, ttl: 1h, penalty: limit-req-rate, rate: 200}}]
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
        actions: [{report: {reason: burst, ttl: 1h, penalty: limit-req-rate, rate: 200}}]
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

			// Another source in the same prefix lands in the emptied
			// bucket and stays quiet: still exactly one report.
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

// TestE2ETargetAggregationSeparatesPrefixes: different aggregated prefixes
// never share tracker state and produce one Report Target each.
func TestE2ETargetAggregationSeparatesPrefixes(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: abuse
    rules:
      - id: burst
        tracker: {track: rate, leak: 0, volume: 2, target_prefix: {ipv4: 24, ipv6: 64}}
        actions: [{report: {reason: burst, ttl: 1h, penalty: limit-req-rate, rate: 200}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)

	// Two sources per prefix give two buckets at value 2 each; nothing
	// overflows (value == volume does not overflow).
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

// TestE2EReplayWarmUpBlindThenReports: the replay tracker is blind until a
// path's file-size estimate warms, then accumulates and reports.
func TestE2EReplayWarmUpBlindThenReports(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	rules := `
version: 0
chains:
  - name: download-abuse
    rules:
      - id: iso-replay
        tracker: {track: replay, leak: 0, volume: 2}
        actions: [{report: {reason: iso-replay, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
`
	d := startTestDaemon(t, clock, "unixgram", ":memory:", rules)

	// Warm-up (the first 4 of 5 samples): the size estimate is unknown,
	// so every event is skipped entirely.
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

// TestE2EReplayVolumeMethodScalesTolerance: the volume method scales
// tolerance with file size; a small file overflows where a big one does not.
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
        actions: [{report: {reason: iso-replay, ttl: 1h, penalty: limit-bandwidth, rate: 1MB}}]
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
	// overflows its volume 1 (volume_low at size 100).
	if r.Tracker.Track != "replay" || r.Tracker.Value != 2 || r.Tracker.Volume != 1 {
		t.Errorf("tracker = %+v, want {replay 2 0 1} (volume_low at size 100)", r.Tracker)
	}
	if r.Sample.Path != "/small.iso" || r.Sample.Size != 100 {
		t.Errorf("sample = %+v, want /small.iso with enriched size 100", r.Sample)
	}
}

// TestStartupLogCarriesBuildIdentity: the startup log record carries the
// build identity fields, so the log stream identifies the running build.
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
