package nginx

import (
	"errors"
	"testing"
	"time"
)

// Behavior pins for the encoding/json/v2 rewrite: contract cases the fixture
// tests do not cover, preserved byte-identically from the map-based decoder.

// TestParseAgentNullIsAbsent: a JSON null agent means absent
// (flux $http_user_agent is "-" or empty for agent-less clients).
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

// TestParseDuplicateNamesLastWins: duplicate member names keep map semantics (last wins).
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

// TestParseNullLineIsMissingField: a bare JSON null fails required-field
// validation on "time", not as a malformed line.
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

// TestParseInvalidUTF8InAgent: raw non-UTF-8 bytes parse successfully and are
// kept as U+FFFD (historic decoder), never malformed-line drops.
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
