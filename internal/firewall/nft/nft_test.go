package nft

import (
	"strings"
	"testing"
)

// Primary seam: the driver's own surface. Hook parsing and driver
// construction are validated here without privileges; where netlink is
// unusable the driver must fail loudly (the exact complement of the
// root gate below); and one root-gated integration test — install,
// read the kernel state back, reset — verifies the encoding wherever
// privileges exist.

// TestParseHook: the --hook value validation, a failing and a passing
// case per validation.
func TestParseHook(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    Hook
		wantErr string
	}{
		{
			name:    "an unknown hook is rejected",
			in:      "postrouting",
			wantErr: `hook: must be input or prerouting (got "postrouting")`,
		},
		{
			name:    "an empty hook is rejected",
			in:      "",
			wantErr: `hook: must be input or prerouting (got "")`,
		},
		{
			name: "the input hook parses",
			in:   "input",
			want: HookInput,
		},
		{
			name: "the prerouting hook parses",
			in:   "prerouting",
			want: HookPrerouting,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseHook(tt.in)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("ParseHook(%q) = %q, want error containing %q", tt.in, got, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("ParseHook(%q) error %q does not contain %q", tt.in, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseHook(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ParseHook(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestNewValidatesTheHook: driver construction refuses a hook that is
// not one of the two enforcement hooks, a failing and a passing case.
func TestNewValidatesTheHook(t *testing.T) {
	tests := []struct {
		name    string
		hook    Hook
		wantErr string
	}{
		{
			name:    "an unknown hook is refused",
			hook:    Hook("forward"),
			wantErr: `hook: must be input or prerouting (got "forward")`,
		},
		{
			name:    "the zero hook is refused",
			hook:    Hook(""),
			wantErr: `hook: must be input or prerouting (got "")`,
		},
		{
			name: "the input hook is accepted",
			hook: HookInput,
		},
		{
			name: "the prerouting hook is accepted",
			hook: HookPrerouting,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := New(Config{Hook: tt.hook})
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("New(%q) succeeded, want error containing %q", tt.hook, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("New(%q) error %q does not contain %q", tt.hook, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("New(%q): %v", tt.hook, err)
			}
			if d == nil {
				t.Fatalf("New(%q) = nil driver", tt.hook)
			}
		})
	}
}

// TestApplyWithoutNetlinkPrivilegesFailsLoudly: where the kernel
// test surface is unavailable there is no silent success — applying
// (probe included) and resetting fail loudly, which is what surfaces
// at the startup test install. It is the exact complement of the root
// gate below.
func TestApplyWithoutNetlinkPrivilegesFailsLoudly(t *testing.T) {
	if reason := netlinkUnusable(); reason == "" {
		t.Skip("nftables is available here; the root-gated integration test covers the driver")
	}
	d, err := New(Config{Hook: HookInput})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := d.Apply(nil); err == nil {
		t.Error("Apply succeeded without netlink, want a loud failure")
	}
	if err := d.Reset(); err == nil {
		t.Error("Reset succeeded without netlink, want a loud failure")
	}
}
