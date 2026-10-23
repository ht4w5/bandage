// Package firewall is splint's firewall seam: the shared vocabulary the
// engine compiles to and every firewall driver enforces — ban rules
// carrying the Penalty as stated — plus the driver port. The engine and
// the adapters both depend on this seam; the engine never imports an
// adapter (deps_test.go enforces the module shape's dependency rule).
package firewall

import "net/netip"

// BanRule is one compiled ban rule (the GLOSSARY's Ban rule): the
// report's Target prefixes and the Penalty as stated — the stance and,
// for the limit stances, the exact rate. Nothing else. The engine
// groups the ban rules by (family, prefix length, penalty), so every
// rule holds one address family's equal-length prefix set and a
// firewall driver turns one rule into exactly one enforcement rule per
// family. A driver applies each Penalty exactly as stated or declines
// it — never substitutes, weakens or tunes it.
type BanRule struct {
	Targets   []netip.Prefix `json:"targets"`
	Prefilter Prefilter      `json:"prefilter"`
	Stance    Stance         `json:"stance"`
	Rate      *int64         `json:"rate,omitempty"`
}

// Prefilter is the service prefilter every ban rule leads with: the
// protected destinations' ports and addresses. A ban rule matches only
// traffic whose destination port is in DstPorts and whose destination
// address is in DstAddrs — so a ban applies only to service traffic,
// never to SSH, monitoring, or unrelated forwarded traffic. Either set
// may be empty, meaning all; both are operator configuration.
//
// Transitional: enforcement scope is driver configuration, not part of
// the ban rule (the spec is explicit). Until the nftables driver owns
// its enforcement scope, the engine-configured prefilter travels on the
// ban rule as the driver's configured input; the field then slims the
// ban rule to Target prefixes plus the Penalty as stated.
type Prefilter struct {
	DstPorts []uint16       `json:"dst_ports"`
	DstAddrs []netip.Prefix `json:"dst_addrs"`
}

// Normalized returns pf with non-nil set slices, so every ban rule's
// dry-run JSON shows its sets as arrays.
func (pf Prefilter) Normalized() Prefilter {
	if pf.DstPorts == nil {
		pf.DstPorts = []uint16{}
	}
	if pf.DstAddrs == nil {
		pf.DstAddrs = []netip.Prefix{}
	}
	return pf
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

// Chain names the two chains of the spec's nftables shape: the ingress
// chain at the configured hook carries drop, reject and packet-rate
// stances; the egress chain (output in input mode, forward in
// prerouting mode) carries bandwidth meters matched on destination ∈
// Target — the response direction the contract's unit names.
//
// Transitional placement vocabulary: direction placement is the
// nftables driver's own shape and leaves the seam when the driver's
// plan carries placement labels.
type Chain string

const (
	// ChainIngress carries the source-facing stances.
	ChainIngress Chain = "ingress"
	// ChainEgress carries the response-direction bandwidth meters.
	ChainEgress Chain = "egress"
)

// Chain reports the chain the stance installs in — the direction split
// of the penalty mapping. limit-req-rate has no packet-layer chain (it
// is application-layer intent) and maps to the zero Chain; the
// firewall driver declines it. Unknown stances map to "" too and the
// firewall driver refuses them loudly.
func (s Stance) Chain() Chain {
	switch s {
	case StanceDrop, StanceReject, StanceLimitPktRate:
		return ChainIngress
	case StanceLimitBandwidth:
		return ChainEgress
	}
	return ""
}
