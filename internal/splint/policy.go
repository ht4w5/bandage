package splint

import (
	"fmt"
	"net/netip"
	"slices"
)

// Prefilter is the service prefilter every ban rule leads with: the
// protected destinations' ports and addresses. A ban rule matches only
// traffic whose destination port is in DstPorts and whose destination
// address is in DstAddrs — so a ban applies only to service traffic,
// never to SSH, monitoring, or unrelated forwarded traffic. Either
// set may be empty, meaning all; both are operator configuration.
type Prefilter struct {
	DstPorts []uint16       `json:"dst_ports"`
	DstAddrs []netip.Prefix `json:"dst_addrs"`
}

// normalized returns pf with non-nil set slices, so every ban rule's
// dry-run JSON shows its sets as arrays.
func (pf Prefilter) normalized() Prefilter {
	if pf.DstPorts == nil {
		pf.DstPorts = []uint16{}
	}
	if pf.DstAddrs == nil {
		pf.DstAddrs = []netip.Prefix{}
	}
	return pf
}

// Policy is the compilation policy the ban sets are compiled under:
// the exclusion prefixes subtracted from every ban set, overriding
// every report, and the service prefilter every ban rule leads with.
// NewPolicy assembles it from the operator's flags; the zero Policy
// keeps the always-on safety exclusions and an all-traffic prefilter.
type Policy struct {
	Exclude   []netip.Prefix
	Prefilter Prefilter
}

// The safety exclusions, in two tiers: loopback and link-local are
// always subtracted (they cannot be re-included), and RFC1918 and ULA
// are subtracted by default — NewPolicy drops that tier when the
// operator opts out of --exclude-private.
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

// NewPolicy assembles the compilation policy from the operator's
// configuration: their exclusion prefixes and service prefilter, plus
// the RFC1918 and ULA tier unless excludePrivate opts out of it. The
// loopback and link-local tier needs no assembly — Subtract always
// applies it.
func NewPolicy(exclude []netip.Prefix, excludePrivate bool, prefilter Prefilter) Policy {
	if excludePrivate {
		exclude = slices.Concat(privateExcluded, exclude)
	}
	return Policy{Exclude: exclude, Prefilter: prefilter}
}

// ParsePrefixOrAddr parses an operator-supplied prefix flag value: a
// CIDR prefix as given (masked), a bare address as its host prefix —
// bandaid's whitelist-entry semantics.
func ParsePrefixOrAddr(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("unparseable prefix (got %q)", s)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Subtract returns the residual prefixes of target after the safety
// exclusions: loopback and link-local are always subtracted (they
// cannot be re-included), then the policy's exclusion prefixes. Every
// exclusion is removed from the target, and a fully excluded target
// returns no residual prefix — the caller drops its ban rule.
// Residuals come back in ascending order.
func (p Policy) Subtract(target netip.Prefix) []netip.Prefix {
	res := []netip.Prefix{target.Masked()}
	res = subtractAll(res, alwaysExcluded)
	res = subtractAll(res, p.Exclude)
	slices.SortFunc(res, netip.Prefix.Compare)
	return res
}

// subtractAll removes every exclusion prefix of exs from the residuals
// of one target.
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

// subtractPrefix returns the residual prefixes of p with ex removed.
// Two prefixes are disjoint or one contains the other, so the residual
// is p itself (disjoint), nothing (ex covers p), or the sibling
// prefixes along the split path from p down to ex.
func subtractPrefix(p, ex netip.Prefix) []netip.Prefix {
	if !p.Overlaps(ex) {
		return []netip.Prefix{p}
	}
	if ex.Bits() <= p.Bits() {
		return nil // p lies inside ex
	}
	// ex lies strictly inside p: split p in half repeatedly and keep
	// every half that does not contain ex.
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

// splitPrefix halves p into its two covering prefixes of one more bit.
func splitPrefix(p netip.Prefix) (lo, hi netip.Prefix) {
	bits := p.Bits() + 1
	lo = netip.PrefixFrom(p.Addr(), bits)
	hi = netip.PrefixFrom(setBit(p.Addr(), p.Bits()), bits)
	return lo, hi
}

// setBit returns a with bit number n set (bit 0 is the most
// significant).
func setBit(a netip.Addr, n int) netip.Addr {
	b := a.AsSlice()
	b[n/8] |= 1 << (7 - n%8)
	out, ok := netip.AddrFromSlice(b)
	if !ok {
		panic("splint: setBit: address length out of range") // unreachable: AsSlice is 4 or 16 bytes
	}
	return out
}
