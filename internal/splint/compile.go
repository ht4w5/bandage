package splint

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/HT4w5/bandage/internal/firewall"
)

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
// closed vocabulary): every action becomes its ban rule's stance with
// the rate travelling along, limit-req-rate included — the Penalty as
// stated reaches the firewall driver, which decides what its
// enforcement surface can honour and reports the rest as declines
// (ADR 0012). The compiler drops no penalty before a driver sees it.
//
// Reports that disagree about overlapping Targets then resolve by the
// merge policy (merge): the most specific Target wins even with a
// weaker stance, so a fine-grained report carves an exception under a
// broader ban and a fine-grained report tightens under a broader one;
// ties on specificity go to the strictest Penalty (drop, then reject,
// then the limits — smallest rate within one action), and tied limits
// of different actions combine instead — one meter per dimension
// (packet rate, bandwidth, request rate), all enforced, with no
// strictness ordering invented between them (ADR 0011). The winning
// stances group by (family, prefix length, penalty) into one ban rule
// per group with an equal-length prefix set, ordered by prefix length
// descending, then strictness — so nftables first-match reproduces the
// merge policy. The result is canonical: permuting the document's
// report order compiles to an identical ruleset.
//
// Exclusions are subtracted compiler-side before the merge, overriding
// every report: the driver installs Targets verbatim, and a record
// whose Target is fully excluded compiles to no ban rule at all.
//
// Records with a missing or unknown Penalty, an unparseable Target or
// a fully excluded Target are skipped and reported in the returned
// skips; the remaining records still compile.
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
	return merge(entries, p.Prefilter.Normalized()), skips
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
	stance    firewall.Stance
	rate      *int64
}

// compileReport maps one report record onto its merge entry: the
// record validation (parseReport), the penalty mapping (mapPenalty)
// and the policy's exclusion subtraction, which leaves the record's
// residual Targets — a fully excluded Target contributes nothing and
// is skipped. The reason is "" exactly when the record compiles.
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
func merge(entries []entry, prefilter firewall.Prefilter) []firewall.BanRule {
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
		rules = append(rules, firewall.BanRule{Targets: groups[k], Prefilter: prefilter, Stance: k.stance, Rate: rate})
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
	stance firewall.Stance
	rate   *int64
}

// strictest resolves a specificity tie — several reports on one Target
// — to the strictest Penalty: drop beats reject beats the limits, and
// within one limit action the smallest rate is the strictest. Limits
// of different actions are dimensionally incomparable and combine
// instead of ordering — one meter per dimension (the ingress
// packet-rate meter, the egress bandwidth meter and the request-rate
// limit), all enforced. No strictness ordering is invented between
// them: a request rate never loses to a packet rate or a bandwidth.
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

// groupKey identifies the ban rule one group compiles to: a family, a
// prefix length and the winning penalty (stance and rate).
type groupKey struct {
	is4    bool
	bits   int
	stance firewall.Stance
	rate   int64 // 0 for stances without a rate
}

// compareGroups orders the ban rules: prefix length descending (the
// first-match lever that makes the most specific Target win), then
// strictness — drop before reject before the limits, and the smallest
// rate first within one action. The limit actions are incomparable, so
// no strictness decides between them; their serialization order is
// fixed — the ingress meter, then the egress meter, then the request
// rate — purely so the same reports always compile to the same
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

// meterRank fixes the serialization order of the three limit stances —
// the ingress packet-rate meter, then the egress bandwidth meter, then
// the request rate. It is not a strictness ordering: the merge never
// resolves a tie with it (see strictest).
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

// rateValue reports the rate a penalty carries (0 when it carries
// none).
func rateValue(r *int64) int64 {
	if r == nil {
		return 0
	}
	return *r
}

// mapPenalty maps a penalty's action onto the ban rule's stance — the
// penalty → stance mapping, total over the closed version-0
// vocabulary so a consumer's switch is never silently wrong. The
// penalty's rate (validated by parseReport) travels onto the ban rule
// unchanged: the Penalty as stated reaches the firewall driver, which
// applies it or declines it — the compiler never drops, substitutes,
// weakens or tunes a penalty. The default keeps unknown actions loud
// even if one slips past validation.
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

// parseReport validates one record against the contract's penalty and
// target rules, returning its masked Target prefix or the reason the
// record is skipped ("" when it compiles).
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
