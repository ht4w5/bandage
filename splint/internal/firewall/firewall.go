// Package firewall is splint's firewall seam: the compiled ban rules
// (the GLOSSARY's Ban rule, carrying the Penalty as stated), the
// firewall driver port, and the registry selecting the one firewall
// driver serving a run. The engine and the firewall drivers both
// depend on this seam; the engine never imports a driver
// (deps_test.go enforces that).
package firewall

import "net/netip"

// BanRule is one compiled ban rule (the GLOSSARY's Ban rule): the
// report's Target prefixes and the Penalty as stated — the stance and,
// for the limit stances, the exact rate. A firewall driver applies the
// Penalty as stated or declines it. Targeting and enforcement scope
// are deliberately not rule fields: they are driver configuration,
// precisely what differs between enforcement surfaces.
type BanRule struct {
	Targets []netip.Prefix `json:"targets"`
	Stance  Stance         `json:"stance"`
	Rate    *int64         `json:"rate,omitempty"`
}

// Stance is the enforcement stance a ban rule applies to its Targets,
// compiled from the reports' Penalties — the GLOSSARY's closed
// five-value vocabulary, carried as stated (the GLOSSARY's Action is a
// rule step, so this is not Action).
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
	// (ADR 0012: the nftables driver's call, not a blanket policy).
	StanceLimitReqRate Stance = "limit-req-rate"
)
