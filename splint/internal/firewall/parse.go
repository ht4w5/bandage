package firewall

import (
	"fmt"
	"net/netip"
)

// ParsePrefixOrAddr parses an operator-supplied prefix flag value: a
// CIDR prefix as given (masked), or a bare address as its host prefix
// (bandaid's whitelist-entry semantics).
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
