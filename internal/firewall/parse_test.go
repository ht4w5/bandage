package firewall

import (
	"net/netip"
	"strings"
	"testing"
)

// Primary seam: the shared operator-prefix flag value — the parser
// behind the engine's --exclude-prefix and the nftables factory's
// --nft-service-address. One failing and one passing case per
// validation; exclusion subtraction and the safety tiers are verified
// at the update-cycle seam, the service scope at the driver's.

// TestParsePrefixOrAddr: a prefix flag value is a CIDR prefix as given
// (masked) or a bare address as its host prefix; anything else is
// refused.
func TestParsePrefixOrAddr(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    netip.Prefix
		wantErr string
	}{
		{
			name:    "an unparseable value is refused",
			in:      "not-a-prefix",
			wantErr: `unparseable prefix (got "not-a-prefix")`,
		},
		{
			name:    "an empty value is refused",
			in:      "",
			wantErr: `unparseable prefix (got "")`,
		},
		{
			name: "a CIDR prefix parses as given",
			in:   "203.0.113.0/24",
			want: netip.MustParsePrefix("203.0.113.0/24"),
		},
		{
			name: "a CIDR prefix is masked",
			in:   "203.0.113.7/24",
			want: netip.MustParsePrefix("203.0.113.0/24"),
		},
		{
			name: "a bare IPv4 address parses as its host prefix",
			in:   "198.51.100.7",
			want: netip.MustParsePrefix("198.51.100.7/32"),
		},
		{
			name: "a bare IPv6 address parses as its host prefix",
			in:   "2001:db8::5",
			want: netip.MustParsePrefix("2001:db8::5/128"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePrefixOrAddr(tt.in)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("ParsePrefixOrAddr(%q) = %q, want error containing %q", tt.in, got, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("ParsePrefixOrAddr(%q) error %q does not contain %q", tt.in, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePrefixOrAddr(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ParsePrefixOrAddr(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
