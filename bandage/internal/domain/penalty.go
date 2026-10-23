package domain

import (
	"encoding/json"
	"fmt"
)

// PenaltyAction is the penalty's stance value - the wire `action`
// field of a report's penalty, named after the webjail penalty field
// it mirrors. It is not a rule Action (the GLOSSARY's Action: a
// report, log, goto, jump or stop on a rule). The closed vocabulary of
// ADR 0010.
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
	// PenaltyLimitReqRate throttles the target to Rate requests per second.
	PenaltyLimitReqRate PenaltyAction = "limit-req-rate"
)

// PenaltyActions is the closed penalty vocabulary of ADR 0010 in the
// order the wire contract and the load errors enumerate it: the single
// source of truth the loader's validation, its error messages and the
// tests all read.
var PenaltyActions = []PenaltyAction{
	PenaltyDrop,
	PenaltyReject,
	PenaltyLimitPktRate,
	PenaltyLimitBandwidth,
	PenaltyLimitReqRate,
}

// penaltyLimits indexes the limit penalties: the vocabulary's limit
// dimension, the only kind carrying a Rate.
var penaltyLimits = map[PenaltyAction]bool{
	PenaltyLimitPktRate:   true,
	PenaltyLimitBandwidth: true,
	PenaltyLimitReqRate:   true,
}

// IsValid reports whether a is one of the closed penalty vocabulary.
func (a PenaltyAction) IsValid() bool {
	for _, action := range PenaltyActions {
		if a == action {
			return true
		}
	}
	return false
}

// IsLimit reports whether a is a limit penalty: the only kind carrying
// a Rate.
func (a PenaltyAction) IsLimit() bool { return penaltyLimits[a] }

// Penalty is the advisory enforcement stance a report carries for its
// target (ADR 0010). Rate is a limit action's per-second threshold in
// the unit the action name states, nil for drop and reject.
type Penalty struct {
	Action PenaltyAction `json:"action"`
	Rate   *int64        `json:"rate,omitempty"`
}

// MarshalJSON renders the penalty in the report document shape: the
// action always, the rate exactly for a limit action (an integer >= 1,
// never 0). A limit penalty without a valid rate never serializes:
// marshaling fails instead of emitting an incomplete recommendation.
func (p Penalty) MarshalJSON() ([]byte, error) {
	if p.Action.IsLimit() {
		if p.Rate == nil || *p.Rate < 1 {
			return nil, fmt.Errorf("penalty: limit action %q requires a rate of at least 1", p.Action)
		}
	} else {
		p.Rate = nil
	}
	type wire Penalty
	return json.Marshal(wire(p))
}
