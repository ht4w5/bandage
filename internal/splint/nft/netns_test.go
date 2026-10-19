package nft

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/google/nftables"

	"github.com/HT4w5/bandage/internal/splint"
)

// The netns targeting surface: the per-namespace constructor without
// privileges, and the root-gated scratch-namespace integration test —
// install through an nsfs handle into a fresh network namespace, read
// the state back there, reset there, then watch the handle vanish. The
// scratch namespace is born empty and dies with the test, so the run
// is safe next to a live deployment: the current namespace is only
// ever probed, never modified.

// TestNewNetNSValidatesTheHook: the namespace-targeting constructor
// shares the hook validation — a failing and a passing case.
func TestNewNetNSValidatesTheHook(t *testing.T) {
	tests := []struct {
		name    string
		hook    string
		wantErr string
	}{
		{
			name:    "an unknown hook is rejected for a namespace target",
			hook:    "postrouting",
			wantErr: `hook: must be input or prerouting (got "postrouting")`,
		},
		{
			name: "a valid hook builds a namespace-targeting driver",
			hook: "input",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewNetNS(Hook(tt.hook), "/var/run/netns/x")
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("NewNetNS(%q) succeeded, want error containing %q", tt.hook, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("NewNetNS(%q) error %q does not contain %q", tt.hook, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewNetNS(%q): %v", tt.hook, err)
			}
			if d == nil {
				t.Fatalf("NewNetNS(%q) = nil driver", tt.hook)
			}
		})
	}
}

// TestKernelInstallInAScratchNetNS is the netns targeting integration
// test: the driver installs its table into a non-default scratch
// network namespace through the nsfs handle — the current namespace
// stays untouched — reads it back there, resets it there, and a
// handle whose namespace vanished surfaces as the splint.ErrUnreachable
// the update cycle warns, skips and tolerates at exit. It is skipped
// where root, netlink or unshare(1) is absent.
func TestKernelInstallInAScratchNetNS(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: netlink requires CAP_NET_ADMIN")
	}
	if reason := netlinkUnusable(); reason != "" {
		t.Skip(reason)
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("needs unshare(1) to create the scratch network namespace")
	}
	path, stop := startScratchNetNS(t, unshare)

	// Whatever happens in the scratch namespace, the current one must
	// come out exactly as it went in — possibly under a live
	// splint-nft. Its table is probed, never touched.
	conn, err := nftables.New()
	if err != nil {
		t.Fatalf("nftables.New: %v", err)
	}
	existsBefore, err := tableExists(conn, ownedTable())
	if err != nil {
		t.Fatalf("probe current namespace: %v", err)
	}

	// The encoding fixture of TestKernelInstallReadBackReset, copied
	// deliberately so both kernel tests pin their own expectations.
	rules := []splint.BanRule{
		{Targets: []netip.Prefix{
			netip.MustParsePrefix("203.0.113.0/24"),
			netip.MustParsePrefix("198.51.100.7/32"),
		}, Stance: splint.StanceDrop},
		{Targets: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}, Stance: splint.StanceReject},
		{Targets: []netip.Prefix{netip.MustParsePrefix("198.51.100.9/32")}, Stance: splint.StanceLimitPktRate, Rate: ratePtr(250)},
		{Targets: []netip.Prefix{netip.MustParsePrefix("203.0.113.9/32")}, Stance: splint.StanceLimitBandwidth, Rate: ratePtr(1000000)},
		{Targets: []netip.Prefix{netip.MustParsePrefix("255.255.255.0/24")}, Stance: splint.StanceDrop},
		{
			Targets: []netip.Prefix{
				netip.MustParsePrefix("203.0.113.7/32"),
				netip.MustParsePrefix("2001:db8::7/128"),
			},
			Prefilter: splint.Prefilter{
				DstPorts: []uint16{53, 443},
				DstAddrs: []netip.Prefix{
					netip.MustParsePrefix("198.51.100.5/32"),
					netip.MustParsePrefix("2001:db8::5/128"),
				},
			},
			Stance: splint.StanceDrop,
		},
		{
			Targets: []netip.Prefix{netip.MustParsePrefix("2001:db8::9/128")},
			Prefilter: splint.Prefilter{
				DstPorts: []uint16{443},
				DstAddrs: []netip.Prefix{netip.MustParsePrefix("198.51.100.5/32")},
			},
			Stance: splint.StanceDrop,
		},
	}
	d, err := NewNetNS(HookInput, path)
	if err != nil {
		t.Fatalf("NewNetNS: %v", err)
	}
	if err := d.Install(rules); err != nil {
		t.Fatalf("Install into the scratch namespace: %v", err)
	}

	nsConn := scratchConn(t, path)
	assertKernelState(t, nsConn, HookInput)

	existsAfter, err := tableExists(conn, ownedTable())
	if err != nil {
		t.Fatalf("probe current namespace: %v", err)
	}
	if existsAfter != existsBefore {
		t.Errorf("current namespace table existence = %v, want %v (installing elsewhere must not touch it)", existsAfter, existsBefore)
	}

	// Reset removes the table in the scratch namespace only ...
	if err := d.Reset(); err != nil {
		t.Fatalf("Reset in the scratch namespace: %v", err)
	}
	if exists, err := tableExists(nsConn, ownedTable()); err != nil {
		t.Fatalf("probe scratch namespace after Reset: %v", err)
	} else if exists {
		t.Errorf("table %q still exists in the scratch namespace", tableName)
	}
	// ... and tolerates it being already absent.
	if err := d.Reset(); err != nil {
		t.Errorf("second Reset: %v", err)
	}

	// A vanished namespace: the handle path is gone once the process
	// holding the namespace is reaped. Both driver calls surface
	// splint.ErrUnreachable — the error the update cycle warns and
	// skips for the cycle and tolerates at reset.
	stop()
	if err := d.Reset(); !errors.Is(err, splint.ErrUnreachable) {
		t.Errorf("Reset on a vanished namespace = %v, want a splint.ErrUnreachable", err)
	}
	if err := d.Install(rules); !errors.Is(err, splint.ErrUnreachable) {
		t.Errorf("Install into a vanished namespace = %v, want a splint.ErrUnreachable", err)
	}
}

// startScratchNetNS starts a process in a fresh network namespace and
// returns its nsfs handle path and a stop function that kills and
// reaps the holding process (idempotent; also the test cleanup). The
// namespace dies with the process. The ready line is printed from
// inside the new namespace, so reading it pins the namespace switch.
func startScratchNetNS(t *testing.T, unshare string) (string, func()) {
	t.Helper()
	cmd := exec.Command(unshare, "--net", "sh", "-c", "echo ready; exec sleep 300")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("scratch namespace stdout: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot create a scratch network namespace: %v", err)
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cmd.Process.Kill()
		cmd.Wait()
	}
	t.Cleanup(stop)
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "ready" {
		t.Skipf("cannot create a scratch network namespace: ready line %q (err %v)", line, err)
	}
	selfNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Skipf("cannot read the current namespace handle: %v", err)
	}
	procNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", cmd.Process.Pid))
	if err != nil || procNS == selfNS {
		t.Skipf("the scratch namespace is not distinct from the current one: %q (err %v)", procNS, err)
	}
	return fmt.Sprintf("/proc/%d/ns/net", cmd.Process.Pid), stop
}

// scratchConn opens a netlink connection into the scratch namespace.
// The handle file must stay open for the connection's whole lifetime —
// the library dials lazily per operation — so it is closed only with
// the test.
func scratchConn(t *testing.T, path string) *nftables.Conn {
	t.Helper()
	nsFile, err := os.Open(path)
	if err != nil {
		t.Fatalf("open scratch namespace handle: %v", err)
	}
	t.Cleanup(func() { nsFile.Close() })
	conn, err := nftables.New(nftables.WithNetNSFd(int(nsFile.Fd())))
	if err != nil {
		t.Fatalf("connect to the scratch namespace: %v", err)
	}
	return conn
}
