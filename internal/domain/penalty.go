package bandage

// PenaltyAction is the enforcement stance a report recommends for its
// target: the closed vocabulary of ADR 0010.
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

// Penalty is the advisory enforcement stance a report carries for its
// target (ADR 0010). Rate is a limit action's per-second threshold in
// the unit the action name states, nil for drop and reject.
type Penalty struct {
	Action PenaltyAction
	Rate   *int64
}

// IsLimit reports whether Action is a limit penalty: the only kind
// carrying a Rate.
func (p Penalty) IsLimit() bool {
	switch p.Action {
	case PenaltyLimitPktRate, PenaltyLimitBandwidth, PenaltyLimitReqRate:
		return true
	}
	return false
}
