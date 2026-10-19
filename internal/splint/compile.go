package splint

import (
	"fmt"
	"net/netip"
)

// BanRule is one compiled ban rule (the GLOSSARY's Ban rule): a stance
// over Target prefixes, the unit the firewall driver installs. Rate is
// the stance's per-second rate in the unit the stance names (packets or
// response-payload bytes); it is non-nil exactly for the limit stances.
type BanRule struct {
	Targets []netip.Prefix `json:"targets"`
	Stance  Stance         `json:"stance"`
	Rate    *int64         `json:"rate,omitempty"`
}

// Stance is the enforcement stance a ban rule applies to its Targets,
// compiled from the reports' Penalties. (The GLOSSARY's Action is a
// rule step, so this is not called Action.)
type Stance string

const (
	// StanceDrop discards the target's traffic silently.
	StanceDrop Stance = "drop"
	// StanceReject refuses the target's traffic with an error signal.
	StanceReject Stance = "reject"
	// StanceLimitPktRate throttles the target to Rate packets per second.
	StanceLimitPktRate Stance = "limit-pkt-rate"
	// StanceLimitBandwidth throttles the target to Rate response-payload
	// bytes per second, metered in the response direction.
	StanceLimitBandwidth Stance = "limit-bandwidth"
)

// Chain names the two chains of the spec's nftables shape. The ingress
// chain at the configured hook carries drop, reject and packet-rate
// stances; the egress chain (output in input mode, forward in
// prerouting mode) carries bandwidth meters matched on destination ∈
// Target — the response direction the contract's unit names.
type Chain string

const (
	// ChainIngress carries the source-facing stances.
	ChainIngress Chain = "ingress"
	// ChainEgress carries the response-direction bandwidth meters.
	ChainEgress Chain = "egress"
)

// Chain reports the chain the stance installs in — the direction split
// of the penalty mapping. Unknown stances map to "" and the firewall
// driver refuses them loudly.
func (s Stance) Chain() Chain {
	switch s {
	case StanceDrop, StanceReject, StanceLimitPktRate:
		return ChainIngress
	case StanceLimitBandwidth:
		return ChainEgress
	}
	return ""
}

// Skip is a report record the compiler left out and why; every skip is
// logged and counted by the update cycle.
type Skip struct {
	Rule   string
	Target string
	Reason string
}

// Compile maps a version-0 report document's live reports to ban rules.
//
// Every report with a valid Penalty and a parseable Target compiles to
// one ban rule through the contract's penalty mapping (mapPenalty —
// total over the closed vocabulary): drop, reject and the two
// packet-layer limits become their stances with the rate travelling
// along, and limit-req-rate is deliberately not applied (ADR 0011) —
// skipped, logged and counted instead. Ticket 05 merges overlapping
// Targets and orders the result by specificity and strictness.
//
// Records with a missing or unknown Penalty or an unparseable Target
// are skipped and reported in the returned skips; the remaining records
// still compile.
func Compile(doc Document) ([]BanRule, []Skip) {
	rules := []BanRule{}
	var skips []Skip
	for _, r := range doc.Reports {
		rule, reason := compileRecord(r)
		if reason != "" {
			skips = append(skips, Skip{Rule: r.Rule, Target: r.Target, Reason: reason})
			continue
		}
		rules = append(rules, rule)
	}
	return rules, skips
}

// compileRecord maps one report record onto its ban rule: the record
// validation (parseRecord) followed by the penalty mapping
// (mapPenalty). The reason is "" exactly when the record compiles.
func compileRecord(r Report) (BanRule, string) {
	target, reason := parseRecord(r)
	if reason != "" {
		return BanRule{}, reason
	}
	stance, reason := mapPenalty(*r.Penalty)
	if reason != "" {
		return BanRule{}, reason
	}
	return BanRule{
		Targets: []netip.Prefix{target},
		Stance:  stance,
		Rate:    r.Penalty.Rate,
	}, ""
}

// mapPenalty maps a penalty's action onto the ban rule's stance — the
// penalty → nftables mapping, total over the closed version-0
// vocabulary so a consumer's switch is never silently wrong. The
// penalty's rate (validated by parseRecord) travels onto the ban rule
// unchanged. limit-req-rate maps to a skip reason instead of a stance:
// it is deliberately not applied (ADR 0011) and nothing installs for
// it. The default keeps unknown actions loud even if one slips past
// validation.
func mapPenalty(p Penalty) (Stance, string) {
	switch p.Action {
	case PenaltyDrop:
		return StanceDrop, ""
	case PenaltyReject:
		return StanceReject, ""
	case PenaltyLimitPktRate:
		return StanceLimitPktRate, ""
	case PenaltyLimitBandwidth:
		return StanceLimitBandwidth, ""
	case PenaltyLimitReqRate:
		return "", "penalty: limit-req-rate: not applied (ADR 0011)"
	default:
		return "", fmt.Sprintf("penalty: action: unknown (got %q)", p.Action)
	}
}

// parseRecord validates one record against the contract's penalty and
// target rules, returning its masked Target prefix or the reason the
// record is skipped ("" when it compiles).
func parseRecord(r Report) (netip.Prefix, string) {
	if r.Penalty == nil {
		return netip.Prefix{}, "penalty: missing"
	}
	p := r.Penalty
	if !p.Action.Known() {
		return netip.Prefix{}, fmt.Sprintf("penalty: action: unknown (got %q)", p.Action)
	}
	if p.Action.IsLimit() {
		if p.Rate == nil {
			return netip.Prefix{}, fmt.Sprintf("penalty: rate: required for %s", p.Action)
		}
		if *p.Rate < 1 {
			return netip.Prefix{}, fmt.Sprintf("penalty: rate: must be at least 1 (got %d)", *p.Rate)
		}
	} else if p.Rate != nil {
		return netip.Prefix{}, fmt.Sprintf("penalty: rate: not allowed for %s", p.Action)
	}
	target, err := netip.ParsePrefix(r.Target)
	if err != nil {
		return netip.Prefix{}, fmt.Sprintf("target: unparseable prefix (got %q)", r.Target)
	}
	return target.Masked(), ""
}
