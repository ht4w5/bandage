package bandage

import (
	"encoding/json"
	"time"
)

// TrackerReading is the tracker values at trigger time, recorded as
// report evidence.
type TrackerReading struct {
	// Track is the tracker kind: "rate", "bandwidth", or "replay".
	Track  string  `json:"track"`
	Value  float64 `json:"value"`
	Leak   float64 `json:"leak"`
	Volume float64 `json:"volume"`
}

// Sample is the most recent event that created a report.
type Sample struct {
	Time   time.Time
	Path   string
	Agent  string
	Status int
	Sent   int64
	Size   int64
}

// Report is the record that a rule matched for a target, alive until
// expiry or deletion. Identity is (rule, target).
type Report struct {
	Rule      string
	Chain     string
	Reason    string
	Target    string
	CreatedAt time.Time
	UpdatedAt time.Time
	ExpiresAt time.Time
	Tracker   TrackerReading
	Sample    Sample
	// Penalty is the advisory enforcement stance the report recommends
	// for the target (ADR 0010); nil only for rows written before the
	// penalty existed (outside the canonical contract).
	Penalty *Penalty
}

// formatTime renders report timestamps: RFC 3339 UTC at second precision.
func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

// MarshalJSON renders the sample in the report document shape.
func (s Sample) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Time   string `json:"time"`
		Path   string `json:"path"`
		Agent  string `json:"agent"`
		Status int    `json:"status"`
		Sent   int64  `json:"sent"`
		Size   int64  `json:"size"`
	}{
		Time:   formatTime(s.Time),
		Path:   s.Path,
		Agent:  s.Agent,
		Status: s.Status,
		Sent:   s.Sent,
		Size:   s.Size,
	})
}

// UnmarshalJSON is the inverse of MarshalJSON (persistence round-trip).
func (s *Sample) UnmarshalJSON(b []byte) error {
	var wire struct {
		Time   string `json:"time"`
		Path   string `json:"path"`
		Agent  string `json:"agent"`
		Status int    `json:"status"`
		Sent   int64  `json:"sent"`
		Size   int64  `json:"size"`
	}
	if err := json.Unmarshal(b, &wire); err != nil {
		return err
	}
	t, err := parseTime(wire.Time)
	if err != nil {
		return err
	}
	*s = Sample{
		Time:   t,
		Path:   wire.Path,
		Agent:  wire.Agent,
		Status: wire.Status,
		Sent:   wire.Sent,
		Size:   wire.Size,
	}
	return nil
}

// MarshalJSON renders the report in the report document shape.
func (r Report) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Rule      string         `json:"rule"`
		Chain     string         `json:"chain"`
		Reason    string         `json:"reason"`
		Target    string         `json:"target"`
		CreatedAt string         `json:"created_at"`
		UpdatedAt string         `json:"updated_at"`
		ExpiresAt string         `json:"expires_at"`
		Tracker   TrackerReading `json:"tracker"`
		Sample    Sample         `json:"sample"`
		Penalty   *Penalty       `json:"penalty,omitempty"`
	}{
		Rule:      r.Rule,
		Chain:     r.Chain,
		Reason:    r.Reason,
		Target:    r.Target,
		CreatedAt: formatTime(r.CreatedAt),
		UpdatedAt: formatTime(r.UpdatedAt),
		ExpiresAt: formatTime(r.ExpiresAt),
		Tracker:   r.Tracker,
		Sample:    r.Sample,
		Penalty:   r.Penalty,
	})
}
