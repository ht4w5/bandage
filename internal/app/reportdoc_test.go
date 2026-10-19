package app

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"testing"
)

// canonicalRules drives the docs/reports.md canonical example: a
// bandwidth tracker overflowing into a limit-bandwidth penalty with its
// rate (the idiomatic pairing).
const canonicalRules = `
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

// getReportsRaw issues GET /reports and returns the raw response body.
func (d *testDaemon) getReportsRaw(t *testing.T) []byte {
	t.Helper()
	resp, err := apiClient.Get("http://" + d.apiAddr() + "/reports")
	if err != nil {
		t.Fatalf("GET /reports: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /reports status = %d, want 200 (body %q)", resp.StatusCode, body)
	}
	return body
}

// TestE2EReportsDocumentIsIndentedJSON: GET /reports serves the
// canonical v0 serialization -- two-space indented JSON terminated by
// exactly one newline (the readable shape /stats established).
func TestE2EReportsDocumentIsIndentedJSON(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	d := startTestDaemon(t, clock, "unixgram", ":memory:", canonicalRules)

	// 6000 + 6000 - 1000 = 11000 > 10000: the second event overflows.
	d.send(nginxLine(eventTime1, "203.0.113.7", "GET", "/releases/24.04.iso", 200, 6000))
	d.send(nginxLine(eventTime2, "203.0.113.7", "GET", "/releases/24.04.iso", 200, 6000))
	d.waitProcessed(t, 2)

	body := d.getReportsRaw(t)
	if !bytes.HasPrefix(body, []byte("{\n  \"")) {
		t.Errorf("GET /reports body = %q, want indented JSON", body)
	}
	if !bytes.HasSuffix(body, []byte("}\n")) {
		t.Errorf("GET /reports body = %q, want one trailing newline", body)
	}
}

// docsExample extracts the canonical example from the report-format doc:
// the first fenced ```json block of docs/reports.md is the example
// document, so the doc stays the single source of truth.
func docsExample(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	fenceOpen, fenceEnd := []byte("```json\n"), []byte("\n```")
	i := bytes.Index(data, fenceOpen)
	if i < 0 {
		t.Fatalf("%s: no fenced ```json block (the first one is the canonical example)", path)
	}
	rest := data[i+len(fenceOpen):]
	j := bytes.Index(rest, fenceEnd)
	if j < 0 {
		t.Fatalf("%s: unterminated ```json block", path)
	}
	if j == 0 {
		t.Fatalf("%s: empty ```json block", path)
	}
	return string(rest[:j])
}

// TestE2EReportsDocumentMatchesDocsExample: the document GET /reports
// serves for the canonical scenario equals the example fenced in
// docs/reports.md byte for byte, so the published contract and the
// implementation cannot drift. json.Encoder.Encode terminates the
// document with one newline, which the fenced example does not carry.
func TestE2EReportsDocumentMatchesDocsExample(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	d := startTestDaemon(t, clock, "unixgram", ":memory:", canonicalRules)

	// 6000 + 6000 - 1000 = 11000 > 10000: the second event overflows and
	// its sample ends up in the report.
	d.send(nginxLineAgent(eventTime1, "203.0.113.7", "GET", "/releases/24.04.iso", 200, 6000, "Wget/1.21"))
	d.send(nginxLineAgent(eventTime2, "203.0.113.7", "GET", "/releases/24.04.iso", 200, 6000, "Wget/1.21"))
	d.waitProcessed(t, 2)

	body := d.getReportsRaw(t)
	t.Logf("GET /reports body (the doc example is authored from this run):\n%s", body)
	got, found := bytes.CutSuffix(body, []byte("\n"))
	if !found {
		t.Fatalf("GET /reports body = %q, want one trailing newline", body)
	}
	want := docsExample(t, "../../docs/reports.md")
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("GET /reports document does not match the docs/reports.md example\n--- got ---\n%s--- want ---\n%s", got, want)
	}
}
