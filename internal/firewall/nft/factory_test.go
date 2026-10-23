package nft

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/HT4w5/bandage/internal/firewall"
)

// Primary seam: the nftables driver factory — its own flag group, its
// startup validation and the opening of its enforcement points. The
// command run seam is deliberately untested; what would be asserted
// through the command is verified here, at the module that owns it
// (the spec's Testing Decisions): namespace-path and service
// port/address validations keep a failing and a passing pair each.

// newTestFactory binds the factory's flag group and parses args the
// way the command does.
func newTestFactory(t *testing.T, args ...string) *Factory {
	t.Helper()
	f := NewFactory()
	fs := pflag.NewFlagSet("splint", pflag.ContinueOnError)
	f.BindFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	return f
}

// TestFactoryValidations drives the factory's startup validation, one
// failing and one passing case per validation.
func TestFactoryValidations(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "an unknown enforcement hook is refused",
			args:    []string{"--nft-hook", "postrouting"},
			wantErr: `hook: must be input or prerouting (got "postrouting")`,
		},
		{
			name: "the prerouting enforcement hook is accepted",
			args: []string{"--nft-hook", "prerouting"},
		},
		{
			name:    "an empty namespace path is refused",
			args:    []string{"--nft-netns", ""},
			wantErr: "netns: namespace path must not be empty",
		},
		{
			name: "namespace paths are accepted",
			args: []string{"--nft-netns", "/var/run/netns/a", "--nft-netns", "/var/run/netns/b"},
		},
		{
			name:    "a duplicate namespace path is refused",
			args:    []string{"--nft-netns", "/var/run/netns/a", "--nft-netns", "/var/run/netns/a"},
			wantErr: `netns: duplicate namespace path "/var/run/netns/a"`,
		},
		{
			name: "distinct namespace paths are accepted",
			args: []string{"--nft-netns", "/var/run/netns/a", "--nft-netns", "/run/netns/b"},
		},
		{
			name:    "an out-of-range service port is refused",
			args:    []string{"--nft-service-port", "0"},
			wantErr: "service port: must be between 1 and 65535 (got 0)",
		},
		{
			name: "service ports in range are accepted",
			args: []string{"--nft-service-port", "53", "--nft-service-port", "443"},
		},
		{
			name:    "an unparseable service address is refused",
			args:    []string{"--nft-service-address", "not-an-address"},
			wantErr: `service address: unparseable prefix (got "not-an-address")`,
		},
		{
			name: "service addresses parse as prefixes or bare addresses",
			args: []string{"--nft-service-address", "203.0.113.5/32", "--nft-service-address", "2001:db8::5"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newTestFactory(t, tt.args...)
			err := f.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate succeeded, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestFactoryOpensItsEnforcementPoints: the factory expands its
// repeatable namespace-path flag into one driver instance per
// enforcement point — defaulting to the current namespace when none is
// given — each labeled with its path for the engine's logs. Opening is
// lazy: no I/O and no privileges, so --dry-run works anywhere.
func TestFactoryOpensItsEnforcementPoints(t *testing.T) {
	t.Run("one driver instance per namespace path, labeled with its path", func(t *testing.T) {
		f := newTestFactory(t, "--nft-netns", "/var/run/netns/a", "--nft-netns", "/run/netns/b")
		if err := f.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
		points, err := f.Open()
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		var labels []string
		for _, p := range points {
			labels = append(labels, p.Label)
		}
		want := []string{"/var/run/netns/a", "/run/netns/b"}
		if strings.Join(labels, ",") != strings.Join(want, ",") {
			t.Errorf("point labels = %q, want %q", labels, want)
		}
		if points[0].Driver == points[1].Driver {
			t.Error("the points share one driver instance: skip-if-unchanged must follow each instance")
		}
	})

	t.Run("without namespace paths the single point is the current namespace", func(t *testing.T) {
		points, err := newTestFactory(t).Open()
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if len(points) != 1 || points[0].Label != "current" {
			t.Errorf("points = %+v, want the single current-namespace point", points)
		}
	})

	t.Run("each instance enforces at its own target handle", func(t *testing.T) {
		// A handle that cannot be opened surfaces as the unreachable
		// enforcement point the update cycle warns and skips — the
		// error names the path the instance is bound to.
		points, err := newTestFactory(t, "--nft-netns", "/nonexistent/splint-test/netns").Open()
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		_, err = points[0].Driver.Apply(nil)
		if !errors.Is(err, firewall.ErrUnreachable) {
			t.Errorf("Apply at a vanished point = %v, want a firewall.ErrUnreachable", err)
		}
		if err == nil || !strings.Contains(err.Error(), "/nonexistent/splint-test/netns") {
			t.Errorf("Apply error %v does not name the instance's target handle", err)
		}
	})
}

// TestFactoryFlagGroup: the nftables driver's flag group is complete
// — the enforcement hook, the repeatable namespace targeting and the
// service prefilter's ports and addresses — and every flag in it is
// the driver's own --nft-* group: the hook is a driver flag, never an
// engine flag (the spec's Command surface).
func TestFactoryFlagGroup(t *testing.T) {
	f := NewFactory()
	fs := pflag.NewFlagSet("splint", pflag.ContinueOnError)
	f.BindFlags(fs)
	var got []string
	fs.VisitAll(func(fl *pflag.Flag) { got = append(got, fl.Name) })
	want := []string{"nft-hook", "nft-netns", "nft-service-address", "nft-service-port"}
	if !slices.Equal(got, want) {
		t.Errorf("flag group = %q, want %q", got, want)
	}
}

// TestFactoryName: the registry name the --firewall value selects.
func TestFactoryName(t *testing.T) {
	if got := NewFactory().Name(); got != "nftables" {
		t.Errorf("Name() = %q, want %q", got, "nftables")
	}
}
