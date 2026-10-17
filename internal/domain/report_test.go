package bandage

import (
	"encoding/json"
	"testing"
	"time"
)

// The report document shape is the consumption contract (spec: Report
// document, PLAN §6): RFC 3339 UTC timestamps at second precision.
func TestReportMarshalJSON(t *testing.T) {
	rec := Report{
		Rule:      "sustained-iso-egress",
		Chain:     "download-abuse",
		Reason:    "iso-egress-overflow",
		Target:    "203.0.113.7",
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
	}
	got, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	want := `{
		"rule": "sustained-iso-egress",
		"chain": "download-abuse",
		"reason": "iso-egress-overflow",
		"target": "203.0.113.7",
		"created_at": "2025-10-17T10:02:11Z",
		"updated_at": "2025-10-17T18:29:40Z",
		"expires_at": "2025-10-24T18:29:40Z",
		"tracker": {"track": "bandwidth", "value": 102400000, "leak": 1000000, "volume": 100000000},
		"sample": {"time": "2025-10-17T18:29:40Z", "path": "/releases/24.04.iso", "agent": "Wget/1.21", "status": 200, "sent": 123456, "size": 1234567890}
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
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}
