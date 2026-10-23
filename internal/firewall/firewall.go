// Package firewall is splint's firewall seam: the shared vocabulary the
// engine compiles to and every firewall driver enforces — ban rules
// carrying the Penalty as stated — plus the driver port, the factory
// registrations, and the registry that selects the one factory serving
// a run (its name, its flags, its validation, its enforcement points). The engine and the adapters
// both depend on this seam; the engine never imports an adapter
// (deps_test.go enforces the module shape's dependency rule).
package firewall

import "net/netip"

// BanRule is one compiled ban rule (the GLOSSARY's Ban rule): the
// report's Target prefixes and the Penalty as stated — the stance and,
// for the limit stances, the exact rate. Nothing else. Targeting and
// enforcement scope are deliberately not part of the ban rule: they
// are driver configuration, because they are precisely what differs
// between enforcement surfaces (a web-server driver needs neither
// nsfs paths nor destination-port prefiltering). The engine groups the
// ban rules by (family, prefix length, penalty), so every rule holds
// one address family's equal-length prefix set and a firewall driver
// turns one rule into exactly one enforcement rule per family. A
// driver applies each Penalty exactly as stated or declines it — never
// substitutes, weakens or tunes it.
type BanRule struct {
	Targets []netip.Prefix `json:"targets"`
	Stance  Stance         `json:"stance"`
	Rate    *int64         `json:"rate,omitempty"`
}

// Stance is the enforcement stance a ban rule applies to its Targets,
// compiled from the reports' Penalties — the closed five-value
// vocabulary, carried as stated. (The GLOSSARY's Action is a rule step,
// so this is not called Action.) Every value survives compilation;
// each firewall driver decides what its surface can honour and reports
// the rest as declines.
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
	// StanceLimitReqRate throttles the target to Rate requests per second
	// — application-layer intent. A packet-layer driver declines it
	// loudly (ADR 0012 narrows ADR 0011: non-application is the nftables
	// driver's decision, not a blanket policy); a driver whose surface is
	// the application layer may apply it as stated.
	StanceLimitReqRate Stance = "limit-req-rate"
)
