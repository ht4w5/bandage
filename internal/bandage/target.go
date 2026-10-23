package bandage

import "net/netip"

// TargetPrefix is a tracker's target aggregation (rules key
// "target_prefix"); IPv6 is never finer than /64.
type TargetPrefix struct {
	IPv4 int
	IPv6 int
}

// DefaultTargetPrefix is the aggregation when a tracker declares none:
// per address for IPv4, per /64 for IPv6.
var DefaultTargetPrefix = TargetPrefix{IPv4: 32, IPv6: 64}

// Aggregate masks addr to its family's prefix (IPv4-mapped IPv6
// aggregates as IPv4). Bits clamp to /32 (IPv4) and /64 (IPv6).
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
// falls back to DefaultTargetPrefix.
func (c *TrackerConfig) Target(addr netip.Addr) netip.Prefix {
	prefix := DefaultTargetPrefix
	if c != nil {
		prefix = c.TargetPrefix
	}
	return prefix.Aggregate(addr)
}

// TargetString renders the aggregated prefix canonically (e.g.
// "203.0.113.0/24"): the report Target and tracker cache key base.
func (c *TrackerConfig) TargetString(addr netip.Addr) string {
	return c.Target(addr).String()
}
