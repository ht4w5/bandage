package app

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The shipped nginx log format at the daemon seam: a line rendered from
// configs/nginx/bandage_log.conf parses into an Event whose agent field
// reaches filters (the tripwire pattern). The parser-side byte pin on the
// snippet lives in internal/infra/parse/nginx/nginx_test.go.

// shippedLogLine renders one access-log line the way nginx renders the
// shipped log_format template for a curl client hitting /. The snippet
// extraction regex and the render-and-check flow below are intentionally
// duplicated in internal/infra/parse/nginx/nginx_test.go (shippedLogFormat
// and TestParseShippedLogFormatLine): the two sides sit in different test
// packages, and a shared helper would need an exported package that exists
// purely for tests. Keep both copies in sync with the shipped snippet's
// contract (configs/nginx/bandage_log.conf).
func shippedLogLine(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../configs/nginx/bandage_log.conf")
	if err != nil {
		t.Fatalf("read shipped snippet: %v", err)
	}
	pat := regexp.MustCompile(`\Alog_format bandage escape=json '([^']*)';\z`)
	m := pat.FindStringSubmatch(strings.TrimRight(string(data), "\n"))
	if m == nil {
		t.Fatalf("shipped snippet = %q, want one log_format bandage escape=json '<format>'; directive", data)
	}
	line := strings.NewReplacer(
		"$msec", eventTime1,
		"$remote_addr", "203.0.113.7",
		"$request_method", "GET",
		"$uri", "/",
		"$status", "200",
		"$body_bytes_sent", "0",
		"$http_user_agent", "curl/8.5.0",
	).Replace(m[1])
	if strings.Contains(line, "$") {
		t.Fatalf("rendered line %q leaves a variable unsubstituted", line)
	}
	return line
}

// TestE2EShippedLogFormatAgentReachesFilters: one line in the shipped
// format fires the agent-keyword tripwire, so the shipped snippet keeps
// agent-based rules working end to end.
func TestE2EShippedLogFormatAgentReachesFilters(t *testing.T) {
	clock := newTestClock(mustTime(t, wallBase))
	d := startTestDaemon(t, clock, "unixgram", ":memory:", tripwireRules)

	d.send(shippedLogLine(t))
	d.waitProcessed(t, 1)
	doc := d.getReports(t, nil)
	if len(doc.Reports) != 1 || doc.Reports[0].Target != "203.0.113.7/32" {
		t.Fatalf("reports = %+v, want one tripwire report for 203.0.113.7/32", doc.Reports)
	}
}
