package nginx

import (
	"errors"
	"testing"
	"time"
)

// fullLine is a full-shape flux log-format line (optional, reserved and
// unknown fields included).
const fullLine = `{"time":"1734345934.123","client":"203.0.113.7","server":"203.0.113.1","method":"GET","url":"/releases/24.04.iso","duration":"0.125","host":"example.org","status":200,"sent":123456,"agent":"Wget/1.21","extra":"ignored"}`

func TestParseFieldMapping(t *testing.T) {
	ev, err := New().Parse([]byte(fullLine))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if want := time.Unix(1734345934, 123000000).UTC(); !ev.Time.Equal(want) {
		t.Errorf("Time = %v, want %v", ev.Time, want)
	}
	if got := ev.RemoteAddr.String(); got != "203.0.113.7" {
		t.Errorf("RemoteAddr = %q, want %q", got, "203.0.113.7")
	}
	if ev.Method != "GET" {
		t.Errorf("Method = %q, want %q", ev.Method, "GET")
	}
	if ev.Path != "/releases/24.04.iso" {
		t.Errorf("Path = %q, want %q", ev.Path, "/releases/24.04.iso")
	}
	if ev.Status != 200 {
		t.Errorf("Status = %d, want 200", ev.Status)
	}
	if ev.SentBytes != 123456 {
		t.Errorf("SentBytes = %d, want 123456", ev.SentBytes)
	}
	if ev.Agent != "Wget/1.21" {
		t.Errorf("Agent = %q, want %q", ev.Agent, "Wget/1.21")
	}
	if ev.SizeBytes != 0 {
		t.Errorf("SizeBytes = %d, want 0 (file size unknown until enrichment)", ev.SizeBytes)
	}
}

func TestParseAgentOptional(t *testing.T) {
	line := `{"time":"1734345934","client":"203.0.113.7","method":"GET","url":"/","status":200,"sent":0}`
	ev, err := New().Parse([]byte(line))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if ev.Agent != "" {
		t.Errorf("Agent = %q, want empty", ev.Agent)
	}
	if want := time.Unix(1734345934, 0).UTC(); !ev.Time.Equal(want) {
		t.Errorf("Time = %v, want %v", ev.Time, want)
	}
}

func TestParseTimeAcceptsJSONNumber(t *testing.T) {
	line := `{"time":1734345934.5,"client":"203.0.113.7","method":"GET","url":"/","status":200,"sent":0}`
	ev, err := New().Parse([]byte(line))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if want := time.Unix(1734345934, 500000000).UTC(); !ev.Time.Equal(want) {
		t.Errorf("Time = %v, want %v", ev.Time, want)
	}
}

func TestParseIPv6Client(t *testing.T) {
	line := `{"time":"1734345934","client":"2001:db8::7","method":"GET","url":"/","status":200,"sent":0}`
	ev, err := New().Parse([]byte(line))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if got := ev.RemoteAddr.String(); got != "2001:db8::7" {
		t.Errorf("RemoteAddr = %q, want %q", got, "2001:db8::7")
	}
}

func TestParseMalformedLine(t *testing.T) {
	for _, line := range []string{
		``,
		`not json`,
		`{"time":`,
		`[]`,
		`5`,
	} {
		_, err := New().Parse([]byte(line))
		if err == nil {
			t.Errorf("Parse(%q) succeeded, want error", line)
			continue
		}
		var fe *FieldError
		if errors.As(err, &fe) {
			t.Errorf("Parse(%q) error %v is a *FieldError, want malformed-line error", line, err)
		}
	}
}

// TestParseMalformedLineErrorText pins the malformed-line error text to the
// historic decoder's (encoding/json v1 wording), byte for byte.
func TestParseMalformedLineErrorText(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		// Byte-identical with the historic decoder (encoding/json v1 text).
		{"empty", ``, `parse nginx json: unexpected end of JSON input`},
		{"truncated object", `{"time":`, `parse nginx json: unexpected end of JSON input`},
		{"truncated at open", `{`, `parse nginx json: unexpected end of JSON input`},
		{"truncated literal", `tru`, `parse nginx json: unexpected end of JSON input`},
		{"truncated string", `"unterminated`, `parse nginx json: unexpected end of JSON input`},
		{"truncated value", `{"time":1`, `parse nginx json: unexpected end of JSON input`},
		{"literal typo keeps its expectation", `not json`, `parse nginx json: invalid character 'o' in literal null (expecting 'u')`},
		{"missing value", `{"time":}`, `parse nginx json: invalid character '}' looking for beginning of value`},
		{"garbage prefix", `xyzzy}`, `parse nginx json: invalid character 'x' looking for beginning of value`},
		{"missing colon", `{"time" 1}`, `parse nginx json: invalid character '1' after object key`},
		{"missing comma", `{"time":"1" "client":"x"}`, `parse nginx json: invalid character '"' after object key:value pair`},
		{"trailing garbage", `{"time":"1"} 0`, `parse nginx json: invalid character '0' after top-level value`},

		// Type errors keep the old decode target's name and v1's kind
		// words; a syntax error anywhere still wins (v1 scanned the whole line first).
		{"top-level array", `[]`, `parse nginx json: json: cannot unmarshal array into Go value of type map[string]jsontext.Value`},
		{"top-level number", `5`, `parse nginx json: json: cannot unmarshal number into Go value of type map[string]jsontext.Value`},
		{"top-level bool", `true`, `parse nginx json: json: cannot unmarshal bool into Go value of type map[string]jsontext.Value`},
		{"top-level string", `""`, `parse nginx json: json: cannot unmarshal string into Go value of type map[string]jsontext.Value`},
		{"number with trailing garbage", `00`, `parse nginx json: invalid character '0' after top-level value`},
		{"number with trailing junk", `5x`, `parse nginx json: invalid character 'x' after top-level value`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New().Parse([]byte(tt.line))
			if err == nil {
				t.Fatalf("Parse(%q) succeeded, want error", tt.line)
			}
			if err.Error() != tt.want {
				t.Errorf("Parse(%q) error = %q, want %q", tt.line, err.Error(), tt.want)
			}
		})
	}
}

func TestParseInvalidRequiredField(t *testing.T) {
	tests := []struct {
		name  string
		line  string
		field string
	}{
		{name: "missing time", field: "time", line: `{"client":"203.0.113.7","method":"GET","url":"/","status":200,"sent":0}`},
		{name: "missing client", field: "client", line: `{"time":"1734345934","method":"GET","url":"/","status":200,"sent":0}`},
		{name: "missing method", field: "method", line: `{"time":"1734345934","client":"203.0.113.7","url":"/","status":200,"sent":0}`},
		{name: "missing url", field: "url", line: `{"time":"1734345934","client":"203.0.113.7","method":"GET","status":200,"sent":0}`},
		{name: "missing status", field: "status", line: `{"time":"1734345934","client":"203.0.113.7","method":"GET","url":"/","sent":0}`},
		{name: "missing sent", field: "sent", line: `{"time":"1734345934","client":"203.0.113.7","method":"GET","url":"/","status":200}`},
		{name: "bad time", field: "time", line: `{"time":"abc","client":"203.0.113.7","method":"GET","url":"/","status":200,"sent":0}`},
		{name: "bad time fraction", field: "time", line: `{"time":"1734345934.1x","client":"203.0.113.7","method":"GET","url":"/","status":200,"sent":0}`},
		{name: "time wrong type", field: "time", line: `{"time":{"sec":1},"client":"203.0.113.7","method":"GET","url":"/","status":200,"sent":0}`},
		{name: "bad client", field: "client", line: `{"time":"1734345934","client":"not-an-ip","method":"GET","url":"/","status":200,"sent":0}`},
		{name: "empty method", field: "method", line: `{"time":"1734345934","client":"203.0.113.7","method":"","url":"/","status":200,"sent":0}`},
		{name: "empty url", field: "url", line: `{"time":"1734345934","client":"203.0.113.7","method":"GET","url":"","status":200,"sent":0}`},
		{name: "status below range", field: "status", line: `{"time":"1734345934","client":"203.0.113.7","method":"GET","url":"/","status":99,"sent":0}`},
		{name: "status above range", field: "status", line: `{"time":"1734345934","client":"203.0.113.7","method":"GET","url":"/","status":600,"sent":0}`},
		{name: "status as string", field: "status", line: `{"time":"1734345934","client":"203.0.113.7","method":"GET","url":"/","status":"200","sent":0}`},
		{name: "sent negative", field: "sent", line: `{"time":"1734345934","client":"203.0.113.7","method":"GET","url":"/","status":200,"sent":-1}`},
		{name: "sent fractional", field: "sent", line: `{"time":"1734345934","client":"203.0.113.7","method":"GET","url":"/","status":200,"sent":1.5}`},
		{name: "agent wrong type", field: "agent", line: `{"time":"1734345934","client":"203.0.113.7","method":"GET","url":"/","status":200,"sent":0,"agent":7}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New().Parse([]byte(tt.line))
			if err == nil {
				t.Fatalf("Parse succeeded, want error on field %q", tt.field)
			}
			var fe *FieldError
			if !errors.As(err, &fe) {
				t.Fatalf("Parse error %v is not a *FieldError", err)
			}
			if fe.Field != tt.field {
				t.Errorf("FieldError.Field = %q, want %q", fe.Field, tt.field)
			}
		})
	}
}
