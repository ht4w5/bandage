package bandage

import "net/netip"

// TargetPrefix is a tracker's target aggregation (rules key
// "target_prefix"): the per-family prefix length the event's source
// address is aggregated to before it keys tracker state and becomes the
// report Target (GLOSSARY: Target). IPv6 is never finer than /64 (spec:
// out of scope: "IPv6 aggregation finer than /64").
type TargetPrefix struct {
	IPv4 int
	IPv6 int
}

// DefaultTargetPrefix is the aggregation used when a tracker declares
// none: per address for IPv4, per /64 for IPv6 (PLAN §1).
var DefaultTargetPrefix = TargetPrefix{IPv4: 32, IPv6: 64}

// Aggregate masks addr to the prefix of its family (IPv4-mapped IPv6
// addresses aggregate as IPv4). Bits are clamped into range so IPv4 is
// never finer than /32 and IPv6 never finer than /64 regardless of
// construction; out-of-range config is rejected at load (spec: load-time
// validation).
func (p TargetPrefix) Aggregate(addr netip.Addr) netip.Prefix {
	addr = addr.Unmap()
	bits, limit := p.IPv6, 64
	if addr.Is4() {
		bits, limit = p.IPv4, 32
	}
	if bits < 0 {
		bits = 0
	}
	if bits > limit {
		bits = limit
	}
	return netip.PrefixFrom(addr, bits).Masked()
}

// Target aggregates addr to this tracker's Target prefix. A nil tracker
// (a report without a tracker cannot be loaded) falls back to the
// default aggregation.
func (c *TrackerConfig) Target(addr netip.Addr) netip.Prefix {
	prefix := DefaultTargetPrefix
	if c != nil {
		prefix = c.TargetPrefix
	}
	return prefix.Aggregate(addr)
}

// TargetString aggregates addr to this tracker's Target prefix and
// renders it canonically (e.g. "203.0.113.0/24"): the report Target and
// the base of the tracker cache key (the domain's key convention).
// Every target derivation goes through here.
func (c *TrackerConfig) TargetString(addr netip.Addr) string {
	return c.Target(addr).String()
}
