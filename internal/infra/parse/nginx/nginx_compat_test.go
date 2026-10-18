package nginx

import (
	"errors"
	"testing"
	"time"
)

// Behavior pins for the encoding/json/v2 rewrite (v0-hot-path ticket 05):
// contract cases the fixture tests in nginx_test.go do not cover but the
// rewrite preserves byte-identically. Each case was characterized against
// the original map-based decoder before the rewrite.

// The optional agent field may be present with a JSON null, meaning
// absent (flux $http_user_agent is "-" or empty for agent-less clients).
func TestParseAgentNullIsAbsent(t *testing.T) {
	for _, line := range []string{
		`{"time":"1734345934","client":"203.0.113.7","method":"GET","url":"/","status":200,"sent":0,"agent":null}`,
		`{"time":"1734345934","client":"203.0.113.7","method":"GET","url":"/","status":200,"sent":0}`,
	} {
		ev, err := New().Parse([]byte(line))
		if err != nil {
			t.Fatalf("Parse(%q) error: %v", line, err)
		}
		if ev.Agent != "" {
			t.Errorf("Parse(%q) Agent = %q, want empty", line, ev.Agent)
		}
	}
}

// Duplicate member names keep map semantics: the last occurrence wins,
// including for the optional agent field.
func TestParseDuplicateNamesLastWins(t *testing.T) {
	ev, err := New().Parse([]byte(`{"time":"1734345934","time":"1734345935","client":"203.0.113.7","method":"GET","url":"/","status":200,"sent":0}`))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if want := time.Unix(1734345935, 0).UTC(); !ev.Time.Equal(want) {
		t.Errorf("Time = %v, want %v", ev.Time, want)
	}

	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "value then null drops agent",
			line: `{"time":"1734345934","client":"203.0.113.7","method":"GET","url":"/","status":200,"sent":0,"agent":"first","agent":null}`,
			want: "",
		},
		{
			name: "null then value keeps agent",
			line: `{"time":"1734345934","client":"203.0.113.7","method":"GET","url":"/","status":200,"sent":0,"agent":null,"agent":"last"}`,
			want: "last",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, err := New().Parse([]byte(tt.line))
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}
			if ev.Agent != tt.want {
				t.Errorf("Agent = %q, want %q", ev.Agent, tt.want)
			}
		})
	}
}

// A bare JSON null is syntactically valid but carries no fields: the line
// fails required-field validation on "time", exactly like a line missing
// the field, rather than counting as a malformed line.
func TestParseNullLineIsMissingField(t *testing.T) {
	_, err := New().Parse([]byte(`null`))
	var fe *FieldError
	if !errors.As(err, &fe) {
		t.Fatalf("Parse error %v is not a *FieldError", err)
	}
	if fe.Field != "time" {
		t.Errorf("FieldError.Field = %q, want %q", fe.Field, "time")
	}
}

// nginx escape=json passes raw non-UTF-8 bytes (e.g. legacy-encoded
// user agents) through unescaped. Such lines parse successfully and the
// invalid bytes are kept as U+FFFD, matching the historic decoder; they
// must not become malformed-line drops.
func TestParseInvalidUTF8InAgent(t *testing.T) {
	tests := []struct {
		name string
		raw  string // raw bytes inside the agent string
		want string
	}{
		{name: "invalid byte", raw: "a\xffb", want: "a\ufffdb"},
		{name: "lone surrogate escape", raw: `\ud800`, want: "\ufffd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line := `{"time":"1734345934","client":"203.0.113.7","method":"GET","url":"/","status":200,"sent":0,"agent":"` + tt.raw + `"}`
			ev, err := New().Parse([]byte(line))
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}
			if ev.Agent != tt.want {
				t.Errorf("Agent = %q, want %q", ev.Agent, tt.want)
			}
		})
	}
}
