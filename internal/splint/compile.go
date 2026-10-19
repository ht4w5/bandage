package splint

import (
	"fmt"
	"net/netip"
	"slices"
)

// BanRule is one compiled ban rule (the GLOSSARY's Ban rule): a stance
// over Target prefixes, the unit the firewall driver installs. Every
// rule leads with the service prefilter, so the ban only ever reaches
// service traffic. Rate is the stance's per-second rate in the unit
// the stance names (packets or response-payload bytes); it is non-nil
// exactly for the limit stances.
//
// Compile groups the ban rules by (family, prefix length, penalty), so
// every rule holds one address family's equal-length prefix set and the
// driver turns one rule into exactly one kernel rule per family.
type BanRule struct {
	Targets   []netip.Prefix `json:"targets"`
	Prefilter Prefilter      `json:"prefilter"`
	Stance    Stance         `json:"stance"`
	Rate      *int64         `json:"rate,omitempty"`
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

// Compile maps a version-0 report document's live reports to ban rules
// under policy p and the spec's merge policy.
//
// Every report with a valid Penalty and a parseable Target compiles
// through the contract's penalty mapping (mapPenalty — total over the
// closed vocabulary): drop, reject and the two packet-layer limits
// become their stances with the rate travelling along, and
// limit-req-rate is deliberately not applied (ADR 0011) — skipped,
// logged and counted instead.
//
// Reports that disagree about overlapping Targets then resolve by the
// merge policy (merge): the most specific Target wins even with a
// weaker stance, so a fine-grained report carves an exception under a
// broader ban and a fine-grained report tightens under a broader one;
// ties on specificity go to the strictest Penalty (drop, then reject,
// then the limits — smallest rate within one action), and tied limits
// of different actions combine instead — one meter per direction, both
// enforced (ADR 0011). The winning stances group by (family, prefix
// length, penalty) into one ban rule per group with an equal-length
// prefix set, ordered by prefix length descending, then strictness —
// so nftables first-match reproduces the merge policy. The result is
// canonical: permuting the document's report order compiles to an
// identical ruleset.
//
// Exclusions are subtracted compiler-side before the merge, overriding
// every report: the driver installs Targets verbatim, and a record
// whose Target is fully excluded compiles to no ban rule at all.
//
// Records with a missing or unknown Penalty, an unparseable Target or
// a fully excluded Target are skipped and reported in the returned
// skips; the remaining records still compile.
func Compile(doc Document, p Policy) ([]BanRule, []Skip) {
	var entries []entry
	var skips []Skip
	for _, r := range doc.Reports {
		e, reason := compileRecord(r, p)
		if reason != "" {
			skips = append(skips, Skip{Rule: r.Rule, Target: r.Target, Reason: reason})
			continue
		}
		entries = append(entries, e)
	}
	return merge(entries, p.Prefilter.normalized()), skips
}

// entry is one compiling report record's contribution to the merge:
// the masked Target that fixes the report's specificity, the penalty's
// stance and rate, and the ban-set prefixes the record draws — its
// Target's residual prefixes after the policy's exclusions subtract.
// The residuals may split the Target into mixed-length prefixes; the
// merge resolves them per prefix against the unsplit Target's
// specificity, so an exclusion can never demote a report's stance.
type entry struct {
	target    netip.Prefix
	residuals []netip.Prefix
	stance    Stance
	rate      *int64
}

// compileRecord maps one report record onto its merge entry: the
// record validation (parseRecord), the penalty mapping (mapPenalty)
// and the policy's exclusion subtraction, which leaves the record's
// residual Targets — a fully excluded Target contributes nothing and
// is skipped. The reason is "" exactly when the record compiles.
func compileRecord(r Report, p Policy) (entry, string) {
	target, reason := parseRecord(r)
	if reason != "" {
		return entry{}, reason
	}
	stance, reason := mapPenalty(*r.Penalty)
	if reason != "" {
		return entry{}, reason
	}
	residuals := p.Subtract(target)
	if len(residuals) == 0 {
		return entry{}, fmt.Sprintf("target: fully excluded (got %q)", r.Target)
	}
	return entry{
		target:    target,
		residuals: residuals,
		stance:    stance,
		rate:      r.Penalty.Rate,
	}, ""
}

// merge resolves the entries' disagreements per Target address and
// groups the winning stances into ban rules under prefilter.
//
// The values a ban set draws from are the distinct residual prefixes
// across the entries. Each value goes to the reports whose Target
// covers it, most specific Target first: the deepest covering reports
// win, ties among them resolved by strictest — so a weaker /32
// exceptions a stronger /16 and a stronger /32 tightens under a weaker
// /16 alike. The winners group by (family, prefix length, penalty)
// into one ban rule per group, and the rules order by prefix length
// descending, then strictness — nftables first-match over the ordered
// equal-length sets reproduces the per-address resolution.
func merge(entries []entry, prefilter Prefilter) []BanRule {
	var values []netip.Prefix
	seen := map[netip.Prefix]bool{}
	for _, e := range entries {
		for _, v := range e.residuals {
			if !seen[v] {
				seen[v] = true
				values = append(values, v)
			}
		}
	}
	slices.SortFunc(values, netip.Prefix.Compare)

	groups := map[groupKey][]netip.Prefix{}
	for _, v := range values {
		for _, w := range resolve(entries, v) {
			k := groupKey{is4: v.Addr().Is4(), bits: v.Bits(), stance: w.stance, rate: rateValue(w.rate)}
			groups[k] = append(groups[k], v)
		}
	}
	keys := make([]groupKey, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, compareGroups)

	rules := []BanRule{}
	for _, k := range keys {
		var rate *int64
		if k.rate != 0 { // the limit stances carry their rate; the rest carry none
			r := k.rate
			rate = &r
		}
		rules = append(rules, BanRule{Targets: groups[k], Prefilter: prefilter, Stance: k.stance, Rate: rate})
	}
	return rules
}

// resolve returns the winning stances over one ban-set prefix: the
// most specific Targets covering it win — a narrower report overrides a
// broader one whatever the stances — and ties among the deepest
// covering reports resolve to the strictest Penalty.
func resolve(entries []entry, v netip.Prefix) []stanceRate {
	best := -1
	var atLevel []entry
	for _, e := range entries {
		if !covers(e.target, v) {
			continue
		}
		switch b := e.target.Bits(); {
		case b > best:
			best, atLevel = b, []entry{e}
		case b == best:
			atLevel = append(atLevel, e)
		}
	}
	return strictest(atLevel)
}

// covers reports whether target contains the whole prefix v.
func covers(target, v netip.Prefix) bool {
	return target.Bits() <= v.Bits() && target.Contains(v.Addr())
}

// stanceRate is one winning stance over a prefix: the stance and its
// rate (nil for stances that carry none).
type stanceRate struct {
	stance Stance
	rate   *int64
}

// strictest resolves a specificity tie — several reports on one Target
// — to the strictest Penalty: drop beats reject beats the limits, and
// within one limit action the smallest rate is the strictest. Limits
// of different actions are dimensionally incomparable and combine
// instead of ordering: one meter per direction (the ingress
// packet-rate meter and the egress bandwidth meter — Stance.Chain),
// both enforced. No strictness ordering is invented between them.
func strictest(atLevel []entry) []stanceRate {
	drop, reject := false, false
	minRates := map[Stance]int64{}
	for _, e := range atLevel {
		switch e.stance {
		case StanceDrop:
			drop = true
		case StanceReject:
			reject = true
		default:
			r := rateValue(e.rate)
			if cur, ok := minRates[e.stance]; !ok || r < cur {
				minRates[e.stance] = r
			}
		}
	}
	switch {
	case drop:
		return []stanceRate{{stance: StanceDrop}}
	case reject:
		return []stanceRate{{stance: StanceReject}}
	}
	var out []stanceRate
	for _, s := range []Stance{StanceLimitPktRate, StanceLimitBandwidth} {
		if r, ok := minRates[s]; ok {
			rate := r
			out = append(out, stanceRate{stance: s, rate: &rate})
		}
	}
	return out
}

// groupKey identifies the ban rule one group compiles to: a family, a
// prefix length and the winning penalty (stance and rate).
type groupKey struct {
	is4    bool
	bits   int
	stance Stance
	rate   int64 // 0 for stances without a rate
}

// compareGroups orders the ban rules: prefix length descending (the
// first-match lever that makes the most specific Target win), then
// strictness — drop before reject before the limits, and the smallest
// rate first within one action. The two limit actions are
// incomparable, so no strictness decides between them; their
// serialization order is fixed — the ingress meter before the egress
// meter — purely so the same reports always compile to the same
// ruleset, and equal-length sets are disjoint across stances, so the
// order is unobservable to nftables. The family breaks the last tie.
func compareGroups(a, b groupKey) int {
	if a.bits != b.bits {
		return b.bits - a.bits
	}
	if r := strictRank(a.stance) - strictRank(b.stance); r != 0 {
		return r
	}
	if r := meterRank(a.stance) - meterRank(b.stance); r != 0 {
		return r
	}
	if a.rate != b.rate {
		if a.rate < b.rate {
			return -1
		}
		return 1
	}
	if a.is4 != b.is4 {
		if a.is4 {
			return -1
		}
		return 1
	}
	return 0
}

// strictRank orders stances by strictness: drop, then reject, then the
// limits (incomparable among themselves).
func strictRank(s Stance) int {
	switch s {
	case StanceDrop:
		return 0
	case StanceReject:
		return 1
	default:
		return 2
	}
}

// meterRank fixes the serialization order of the two limit stances —
// the ingress packet-rate meter before the egress bandwidth meter. It
// is not a strictness ordering: the merge never resolves a tie with it
// (see strictest).
func meterRank(s Stance) int {
	if s == StanceLimitBandwidth {
		return 1
	}
	return 0
}

// rateValue reports the rate a penalty carries (0 when it carries
// none).
func rateValue(r *int64) int64 {
	if r == nil {
		return 0
	}
	return *r
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
