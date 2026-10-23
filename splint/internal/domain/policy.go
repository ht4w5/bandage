package domain

import (
	"net/netip"
	"slices"
)

// Policy is the compilation policy: the exclusion prefixes subtracted
// from every report's Target, overriding every report. The zero Policy
// keeps the always-on safety exclusions.
type Policy struct {
	Exclude []netip.Prefix
}

// Safety exclusions in two tiers: loopback and link-local are always
// subtracted (they cannot be re-included); RFC1918 and ULA are
// subtracted unless the operator opts out of --exclude-private.
var (
	alwaysExcluded = []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),    // loopback
		netip.MustParsePrefix("::1/128"),        // loopback
		netip.MustParsePrefix("169.254.0.0/16"), // link-local
		netip.MustParsePrefix("fe80::/10"),      // link-local
	}
	privateExcluded = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),     // RFC1918
		netip.MustParsePrefix("172.16.0.0/12"),  // RFC1918
		netip.MustParsePrefix("192.168.0.0/16"), // RFC1918
		netip.MustParsePrefix("fc00::/7"),       // ULA
	}
)

func NewPolicy(exclude []netip.Prefix, excludePrivate bool) Policy {
	if excludePrivate {
		exclude = slices.Concat(privateExcluded, exclude)
	}
	return Policy{Exclude: exclude}
}

// Subtract returns target's residual prefixes after the exclusions; a
// fully excluded target returns none. Residuals come back ascending.
func (p Policy) Subtract(target netip.Prefix) []netip.Prefix {
	res := []netip.Prefix{target.Masked()}
	res = subtractAll(res, alwaysExcluded)
	res = subtractAll(res, p.Exclude)
	slices.SortFunc(res, netip.Prefix.Compare)
	return res
}

func subtractAll(res, exs []netip.Prefix) []netip.Prefix {
	for _, ex := range exs {
		if len(res) == 0 {
			break
		}
		var next []netip.Prefix
		for _, r := range res {
			next = append(next, subtractPrefix(r, ex.Masked())...)
		}
		res = next
	}
	return res
}

// subtractPrefix returns p's residual with ex removed: p itself
// (disjoint), nothing (ex covers p), or the sibling prefixes along the
// split path from p down to ex.
func subtractPrefix(p, ex netip.Prefix) []netip.Prefix {
	if !p.Overlaps(ex) {
		return []netip.Prefix{p}
	}
	if ex.Bits() <= p.Bits() {
		return nil // p lies inside ex
	}
	var out []netip.Prefix
	for cur := p; ex.Bits() > cur.Bits(); {
		lo, hi := splitPrefix(cur)
		if lo.Overlaps(ex) {
			out = append(out, hi)
			cur = lo
		} else {
			out = append(out, lo)
			cur = hi
		}
	}
	return out // the last cur is ex itself: dropped
}

func splitPrefix(p netip.Prefix) (lo, hi netip.Prefix) {
	bits := p.Bits() + 1
	lo = netip.PrefixFrom(p.Addr(), bits)
	hi = netip.PrefixFrom(setBit(p.Addr(), p.Bits()), bits)
	return lo, hi
}

// setBit sets bit n of a (bit 0 is the most significant).
func setBit(a netip.Addr, n int) netip.Addr {
	b := a.AsSlice()
	b[n/8] |= 1 << (7 - n%8)
	out, ok := netip.AddrFromSlice(b)
	if !ok {
		panic("splint: setBit: address length out of range") // unreachable: AsSlice is 4 or 16 bytes
	}
	return out
}
