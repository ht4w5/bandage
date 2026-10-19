// Package splint is splint-nft's engine: it pulls the bandage report
// document, compiles ban rules from the document's reports and installs
// them through a firewall-driver port. It is a strict consumer of the
// published contract (docs/reports.md): the document is parsed into
// splint's own wire types and no daemon internals are imported.
package splint

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Document is the wire envelope of the version-0 report document
// (docs/reports.md): the format version, its generation time and the
// live report records.
type Document struct {
	Version     int      `json:"version"`
	GeneratedAt string   `json:"generated_at"`
	Reports     []Report `json:"reports"`
}

// Report is one wire report record (docs/reports.md "Report record"):
// the rule and chain a trigger fired on, the record's Target and
// timestamps, the tracker reading and sample that justified it, and the
// advisory Penalty. Fields the consumer does not act on still mirror
// the contract, so the published document stays the integration surface.
type Report struct {
	Rule      string   `json:"rule"`
	Chain     string   `json:"chain"`
	Reason    string   `json:"reason"`
	Target    string   `json:"target"`
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at"`
	ExpiresAt string   `json:"expires_at"`
	Tracker   Tracker  `json:"tracker"`
	Sample    Sample   `json:"sample"`
	Penalty   *Penalty `json:"penalty"`
}

// Tracker is the tracker reading that justified a report.
type Tracker struct {
	Track  string  `json:"track"`
	Value  float64 `json:"value"`
	Leak   float64 `json:"leak"`
	Volume float64 `json:"volume"`
}

// Sample is the most recent event that created a report.
type Sample struct {
	Time   string `json:"time"`
	Path   string `json:"path"`
	Agent  string `json:"agent"`
	Status int    `json:"status"`
	Sent   int64  `json:"sent"`
	Size   int64  `json:"size"`
}

// Penalty is the advisory enforcement stance a report carries
// (docs/reports.md "Penalty"): one action of the closed version-0
// vocabulary, and its rate exactly when the action is a limit.
type Penalty struct {
	Action PenaltyAction `json:"action"`
	Rate   *int64        `json:"rate"`
}

// PenaltyAction is a penalty's action — one of the five values the
// version-0 contract closes over.
type PenaltyAction string

const (
	// PenaltyDrop discards the target's traffic silently.
	PenaltyDrop PenaltyAction = "drop"
	// PenaltyReject refuses the target's traffic with an error signal.
	PenaltyReject PenaltyAction = "reject"
	// PenaltyLimitPktRate throttles the target to Rate packets per second.
	PenaltyLimitPktRate PenaltyAction = "limit-pkt-rate"
	// PenaltyLimitBandwidth throttles the target to Rate response-payload
	// bytes per second.
	PenaltyLimitBandwidth PenaltyAction = "limit-bandwidth"
	// PenaltyLimitReqRate throttles the target to Rate requests per second;
	// deliberately not applied at the packet layer (ADR 0011).
	PenaltyLimitReqRate PenaltyAction = "limit-req-rate"
)

// Known reports whether a is one of the five version-0 penalty actions.
func (a PenaltyAction) Known() bool {
	switch a {
	case PenaltyDrop, PenaltyReject, PenaltyLimitPktRate, PenaltyLimitBandwidth, PenaltyLimitReqRate:
		return true
	}
	return false
}

// IsLimit reports whether a throttles with a rate.
func (a PenaltyAction) IsLimit() bool {
	switch a {
	case PenaltyLimitPktRate, PenaltyLimitBandwidth, PenaltyLimitReqRate:
		return true
	}
	return false
}

// ParseDocument decodes a report document as the published contract.
// Unknown fields are ignored, per the contract's evolution policy. The
// envelope's version, generated_at and reports fields are required
// (docs/reports.md's Envelope table): a document missing one of them is
// malformed and refuses the whole cycle, and so does an unknown
// document version or JSON that does not match the contract's types —
// whole-cycle refusals, unlike the per-record tolerances Compile
// applies. A present but empty reports array is valid (every report
// expired) and decodes to an empty ruleset.
func ParseDocument(data []byte) (Document, error) {
	var envelope struct {
		Version     *int      `json:"version"`
		GeneratedAt *string   `json:"generated_at"`
		Reports     *[]Report `json:"reports"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return Document{}, fmt.Errorf("report document: parse: %w", err)
	}
	if envelope.Version == nil {
		return Document{}, errors.New("report document: version: required")
	}
	if envelope.GeneratedAt == nil {
		return Document{}, errors.New("report document: generated_at: required")
	}
	if envelope.Reports == nil {
		return Document{}, errors.New("report document: reports: required")
	}
	if *envelope.Version != 0 {
		return Document{}, fmt.Errorf("report document: version: unknown (got %d, want 0)", *envelope.Version)
	}
	return Document{
		Version:     *envelope.Version,
		GeneratedAt: *envelope.GeneratedAt,
		Reports:     *envelope.Reports,
	}, nil
}
