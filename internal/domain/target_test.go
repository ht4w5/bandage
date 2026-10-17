package bandage

import (
	"net/netip"
	"testing"
)

// Target aggregation (spec: target_prefix, GLOSSARY "Target"): the
// source address is masked to the tracker's per-family prefix length and
// rendered canonically as a prefix string (DECISIONS §9). Expected
// strings are worked examples from the spec, not derived by the code.
func TestTargetPrefixAggregate(t *testing.T) {
	tests := []struct {
		name   string
		prefix TargetPrefix
		addr   string
		want   string
	}{
		// IPv4.
		{"ipv4 default aggregates per address", DefaultTargetPrefix, "203.0.113.5", "203.0.113.5/32"},
		{"ipv4 /24", TargetPrefix{IPv4: 24, IPv6: 64}, "203.0.113.7", "203.0.113.0/24"},
		{"ipv4 /24 upper edge", TargetPrefix{IPv4: 24, IPv6: 64}, "203.0.113.255", "203.0.113.0/24"},
		{"ipv4 /24 next prefix stays separate", TargetPrefix{IPv4: 24, IPv6: 64}, "203.0.114.1", "203.0.114.0/24"},
		{"ipv4 /31 pair", TargetPrefix{IPv4: 31, IPv6: 64}, "203.0.113.7", "203.0.113.6/31"},
		{"ipv4 /0 aggregates every source", TargetPrefix{IPv4: 0, IPv6: 64}, "10.1.2.3", "0.0.0.0/0"},
		{"ipv4 never finer than /32", TargetPrefix{IPv4: 64, IPv6: 64}, "203.0.113.7", "203.0.113.7/32"},

		// IPv6.
		{"ipv6 default aggregates per /64", DefaultTargetPrefix, "2001:db8::1", "2001:db8::/64"},
		{"ipv6 /64 upper edge", DefaultTargetPrefix, "2001:db8:0:1:ffff:ffff:ffff:ffff", "2001:db8:0:1::/64"},
		{"ipv6 /48", TargetPrefix{IPv4: 32, IPv6: 48}, "2001:db8:1234:5678::1", "2001:db8:1234::/48"},
		{"ipv6 /0 aggregates every source", TargetPrefix{IPv4: 32, IPv6: 0}, "2001:db8::1", "::/0"},
		{"ipv6 never finer than /64", TargetPrefix{IPv4: 32, IPv6: 128}, "2001:db8::1", "2001:db8::/64"},

		// Address forms.
		{"ipv4-mapped ipv6 unmapped first", TargetPrefix{IPv4: 24, IPv6: 64}, "::ffff:203.0.113.7", "203.0.113.0/24"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := netip.ParseAddr(tt.addr)
			if err != nil {
				t.Fatalf("ParseAddr(%q) error: %v", tt.addr, err)
			}
			got := tt.prefix.Aggregate(addr)
			if s := got.String(); s != tt.want {
				t.Errorf("Aggregate(%q) = %q, want %q", tt.addr, s, tt.want)
			}
		})
	}
}

// Two sources in one aggregated prefix produce the same Target string
// (shared tracker state and one Report Target); different prefixes do
// not.
func TestTargetPrefixAggregateGroupsSources(t *testing.T) {
	p := TargetPrefix{IPv4: 24, IPv6: 64}
	a := p.Aggregate(netip.MustParseAddr("203.0.113.7"))
	b := p.Aggregate(netip.MustParseAddr("203.0.113.254"))
	c := p.Aggregate(netip.MustParseAddr("203.0.114.7"))
	if a != b {
		t.Errorf("same prefix aggregates differently: %q vs %q", a, b)
	}
	if a == c {
		t.Errorf("different prefixes aggregate equally: %q", a)
	}
}

// TrackerConfig.Target is the tracker-state key and report Target. A nil
// tracker (report without tracker cannot be loaded) falls back to the
// default per-address aggregation.
func TestTrackerConfigTarget(t *testing.T) {
	addr := netip.MustParseAddr("203.0.113.7")
	var nilCfg *TrackerConfig
	if got := nilCfg.Target(addr).String(); got != "203.0.113.7/32" {
		t.Errorf("nil tracker Target = %q, want %q", got, "203.0.113.7/32")
	}
	cfg := &TrackerConfig{TargetPrefix: TargetPrefix{IPv4: 24, IPv6: 64}}
	if got := cfg.Target(addr).String(); got != "203.0.113.0/24" {
		t.Errorf("Target = %q, want %q", got, "203.0.113.0/24")
	}
}
