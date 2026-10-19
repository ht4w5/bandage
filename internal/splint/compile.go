package splint

import (
	"fmt"
	"net/netip"
)

// BanRule is one compiled ban rule (the GLOSSARY's Ban rule): a stance
// over Target prefixes, the unit the firewall driver installs.
type BanRule struct {
	Targets []netip.Prefix `json:"targets"`
	Stance  Stance         `json:"stance"`
}

// Stance is the enforcement stance a ban rule applies to its Targets,
// compiled from the reports' Penalties. (The GLOSSARY's Action is a
// rule step, so this is not called Action.)
type Stance string

// StanceDrop discards the target's traffic silently.
const StanceDrop Stance = "drop"

// Skip is a report record the compiler left out and why; every skip is
// logged and counted by the update cycle.
type Skip struct {
	Rule   string
	Target string
	Reason string
}

// Compile maps a version-0 report document's live reports to ban rules.
//
// PLACEHOLDER MAPPING — explicitly superseded by ticket 04 (penalty
// mapping and direction split) and ticket 05 (merge policy): every
// report with a valid Penalty and a parseable Target compiles to one
// drop ban rule over that Target, whatever the penalty advises.
// Ticket 04 maps each penalty action onto its nftables stance (and
// skips limit-req-rate, ADR 0011); ticket 05 merges overlapping
// Targets and orders the result by specificity and strictness.
//
// Records with a missing or unknown Penalty or an unparseable Target
// are skipped and reported in the returned skips; the remaining records
// still compile.
func Compile(doc Document) ([]BanRule, []Skip) {
	rules := []BanRule{}
	var skips []Skip
	for _, r := range doc.Reports {
		target, reason := parseRecord(r)
		if reason != "" {
			skips = append(skips, Skip{Rule: r.Rule, Target: r.Target, Reason: reason})
			continue
		}
		rules = append(rules, BanRule{
			Targets: []netip.Prefix{target},
			Stance:  StanceDrop,
		})
	}
	return rules, skips
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
