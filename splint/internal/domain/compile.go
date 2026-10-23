package domain

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/HT4w5/webmedkit/splint/internal/firewall"
)

// Skip is a report record the compiler left out and why; every skip is
// logged and counted by the update cycle.
type Skip struct {
	Rule   string
	Target string
	Reason string
}

// Compile maps a version-0 report document's live reports to ban rules
// under policy p. The Penalty as stated reaches the firewall driver —
// the compiler drops none — and records with an invalid Penalty or
// Target or a fully excluded Target land in the returned skips; the
// remaining records still compile.
func Compile(doc Document, p Policy) ([]firewall.BanRule, []Skip) {
	var entries []entry
	var skips []Skip
	for _, r := range doc.Reports {
		e, reason := compileReport(r, p)
		if reason != "" {
			skips = append(skips, Skip{Rule: r.Rule, Target: r.Target, Reason: reason})
			continue
		}
		entries = append(entries, e)
	}
	return merge(entries), skips
}

// entry is one report record's merge contribution. The residuals
// resolve against the unsplit Target's specificity, so an exclusion
// can never demote a report's stance.
type entry struct {
	target    netip.Prefix
	residuals []netip.Prefix
	stance    firewall.Stance
	rate      *int64
}

func compileReport(r Report, p Policy) (entry, string) {
	target, reason := parseReport(r)
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

// merge resolves each residual prefix to the deepest covering reports
// (specificity ties go to the strictest Penalty) and groups the winners
// by (family, prefix length, penalty). The rules order by prefix length
// descending, then strictness — nftables first-match reproduces the
// resolution — and the result is canonical across report orderings.
func merge(entries []entry) []firewall.BanRule {
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

	rules := []firewall.BanRule{}
	for _, k := range keys {
		var rate *int64
		if k.rate != 0 { // the limit stances carry their rate; the rest carry none
			r := k.rate
			rate = &r
		}
		rules = append(rules, firewall.BanRule{Targets: groups[k], Stance: k.stance, Rate: rate})
	}
	return rules
}

// resolve returns the winning stances over one residual prefix: the
// deepest covering reports win, ties resolved to the strictest Penalty.
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

func covers(target, v netip.Prefix) bool {
	return target.Bits() <= v.Bits() && target.Contains(v.Addr())
}

// stanceRate is one winning stance over a prefix; rate is nil when it
// carries none.
type stanceRate struct {
	stance firewall.Stance
	rate   *int64
}

// strictest resolves a specificity tie to the strictest Penalty: drop
// beats reject beats the limits (smallest rate within one action).
// Limits of different actions combine — one meter per dimension —
// instead of ordering.
func strictest(atLevel []entry) []stanceRate {
	drop, reject := false, false
	minRates := map[firewall.Stance]int64{}
	for _, e := range atLevel {
		switch e.stance {
		case firewall.StanceDrop:
			drop = true
		case firewall.StanceReject:
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
		return []stanceRate{{stance: firewall.StanceDrop}}
	case reject:
		return []stanceRate{{stance: firewall.StanceReject}}
	}
	var out []stanceRate
	for _, s := range []firewall.Stance{firewall.StanceLimitPktRate, firewall.StanceLimitBandwidth, firewall.StanceLimitReqRate} {
		if r, ok := minRates[s]; ok {
			rate := r
			out = append(out, stanceRate{stance: s, rate: &rate})
		}
	}
	return out
}

type groupKey struct {
	is4    bool
	bits   int
	stance firewall.Stance
	rate   int64 // 0 for stances without a rate
}

// compareGroups orders ban rules by prefix length descending (the
// first-match lever behind most-specific-wins), then strictness. The
// limit stances' fixed serialization order is determinism only — the
// equal-length sets are disjoint, so nftables never observes it.
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

func strictRank(s firewall.Stance) int {
	switch s {
	case firewall.StanceDrop:
		return 0
	case firewall.StanceReject:
		return 1
	default:
		return 2
	}
}

// meterRank fixes the limit stances' serialization order; it is not a
// strictness ordering and never resolves a merge tie (see strictest).
func meterRank(s firewall.Stance) int {
	switch s {
	case firewall.StanceLimitBandwidth:
		return 1
	case firewall.StanceLimitReqRate:
		return 2
	default:
		return 0
	}
}

// rateValue returns the penalty's rate, 0 when it carries none.
func rateValue(r *int64) int64 {
	if r == nil {
		return 0
	}
	return *r
}

// mapPenalty maps a penalty action onto the ban rule's stance, total
// over the closed vocabulary. The rate travels unchanged: the Penalty
// as stated reaches the driver, which applies or declines it.
func mapPenalty(p Penalty) (firewall.Stance, string) {
	switch p.Action {
	case PenaltyDrop:
		return firewall.StanceDrop, ""
	case PenaltyReject:
		return firewall.StanceReject, ""
	case PenaltyLimitPktRate:
		return firewall.StanceLimitPktRate, ""
	case PenaltyLimitBandwidth:
		return firewall.StanceLimitBandwidth, ""
	case PenaltyLimitReqRate:
		return firewall.StanceLimitReqRate, ""
	default:
		return "", fmt.Sprintf("penalty: action: unknown (got %q)", p.Action)
	}
}

// parseReport validates one record, returning its masked Target prefix
// or the skip reason ("" when the record compiles).
func parseReport(r Report) (netip.Prefix, string) {
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
