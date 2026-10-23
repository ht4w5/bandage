package firewall

import (
	"fmt"
	"net/netip"
)

// ParsePrefixOrAddr parses an operator-supplied prefix flag value: a
// CIDR prefix as given (masked), a bare address as its host prefix —
// bandaid's whitelist-entry semantics. It is the shared parser for
// every prefix-valued flag on the seam's side of the fence: the
// engine's --exclude-prefix and a driver's own scope flags (the
// nftables factory's --nft-service-address).
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
