package bandage

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestReportMarshalJSON checks the document shape: RFC 3339 UTC
// timestamps at second precision, keys in document order with the
// nested penalty last.
func TestReportMarshalJSON(t *testing.T) {
	rec := Report{
		Rule:      "sustained-iso-egress",
		Chain:     "download-abuse",
		Reason:    "iso-egress-overflow",
		Target:    "203.0.113.0/24",
		CreatedAt: time.Date(2025, 10, 17, 10, 2, 11, 0, time.UTC),
		UpdatedAt: time.Date(2025, 10, 17, 18, 29, 40, 500, time.UTC), // sub-second truncated in document
		ExpiresAt: time.Date(2025, 10, 24, 18, 29, 40, 0, time.UTC),
		Tracker: TrackerReading{
			Track:  "bandwidth",
			Value:  102400000,
			Leak:   1000000,
			Volume: 100000000,
		},
		Sample: Sample{
			Time:   time.Date(2025, 10, 17, 18, 29, 40, 0, time.UTC),
			Path:   "/releases/24.04.iso",
			Agent:  "Wget/1.21",
			Status: 200,
			Sent:   123456,
			Size:   1234567890,
		},
		Penalty: &Penalty{Action: PenaltyLimitBandwidth, Rate: int64Ptr(1000000)},
	}
	got, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	want := `{
		"rule": "sustained-iso-egress",
		"chain": "download-abuse",
		"reason": "iso-egress-overflow",
		"target": "203.0.113.0/24",
		"created_at": "2025-10-17T10:02:11Z",
		"updated_at": "2025-10-17T18:29:40Z",
		"expires_at": "2025-10-24T18:29:40Z",
		"tracker": {"track": "bandwidth", "value": 102400000, "leak": 1000000, "volume": 100000000},
		"sample": {"time": "2025-10-17T18:29:40Z", "path": "/releases/24.04.iso", "agent": "Wget/1.21", "status": 200, "sent": 123456, "size": 1234567890},
		"penalty": {"action": "limit-bandwidth", "rate": 1000000}
	}`
	if compact(string(got)) != compact(want) {
		t.Errorf("Marshal = %s\nwant %s", got, compact(want))
	}
}

func TestSampleRoundTrip(t *testing.T) {
	// The sqlite adapter round-trips the sample through its JSON form.
	orig := Sample{
		Time:   time.Date(2025, 10, 17, 18, 29, 40, 0, time.UTC),
		Path:   "/releases/24.04.iso",
		Agent:  "Wget/1.21",
		Status: 200,
		Sent:   123456,
		Size:   0,
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	var back Sample
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if !back.Time.Equal(orig.Time) || back.Path != orig.Path || back.Agent != orig.Agent ||
		back.Status != orig.Status || back.Sent != orig.Sent || back.Size != orig.Size {
		t.Errorf("round trip = %+v, want %+v", back, orig)
	}
}

func compact(s string) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, []byte(s)); err != nil {
		return s
	}
	return buf.String()
}

// int64Ptr returns a pointer to v (a limit penalty's rate).
func int64Ptr(v int64) *int64 { return &v }

// TestPenaltyWireShape pins the nested penalty object: action always,
// rate exactly for a limit action (integer, never 0), and the penalty
// key itself omitted only when the report carries none.
func TestPenaltyWireShape(t *testing.T) {
	for _, tt := range []struct {
		name    string
		penalty *Penalty
		want    string // expected "penalty" fragment, "" when the key is omitted
	}{
		{"a limit carries its rate", &Penalty{Action: PenaltyLimitPktRate, Rate: int64Ptr(200)}, `"penalty":{"action":"limit-pkt-rate","rate":200}`},
		{"drop carries no rate", &Penalty{Action: PenaltyDrop}, `"penalty":{"action":"drop"}`},
		{"reject carries no rate even when one is set", &Penalty{Action: PenaltyReject, Rate: int64Ptr(200)}, `"penalty":{"action":"reject"}`},
		{"no penalty is omitted", nil, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rec := Report{Rule: "r", Penalty: tt.penalty}
			got, err := json.Marshal(rec)
			if err != nil {
				t.Fatalf("Marshal error: %v", err)
			}
			if tt.want == "" {
				if strings.Contains(string(got), `"penalty"`) {
					t.Errorf("Marshal = %s, want no penalty key", got)
				}
				return
			}
			if !strings.Contains(string(got), tt.want) {
				t.Errorf("Marshal = %s, want it to contain %s", got, tt.want)
			}
		})
	}
}
