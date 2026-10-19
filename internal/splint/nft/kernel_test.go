package nft

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/HT4w5/bandage/internal/splint"
)

// TestKernelInstallReadBackReset is the real driver's one integration
// test: install, read the kernel state back, reset. It is skipped
// where root or nftables is absent, and it verifies the driver's own
// encoding, nothing else. It also refuses to run where a splint table
// already exists: the test rebuilds and resets that table, which would
// drop a live deployment's bans.
func TestKernelInstallReadBackReset(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: netlink requires CAP_NET_ADMIN")
	}
	if reason := netlinkUnusable(); reason != "" {
		t.Skip(reason)
	}
	conn, err := nftables.New()
	if err != nil {
		t.Fatalf("nftables.New: %v", err)
	}
	if exists, err := tableExists(conn, ownedTable()); err != nil {
		t.Fatalf("probe owned table: %v", err)
	} else if exists {
		t.Skipf("table %q exists: a splint-nft instance may be enforcing here", tableName)
	}
	// Whatever the test does halfway, the owned table must not outlive it.
	t.Cleanup(func() {
		d, err := New(HookInput)
		if err != nil {
			t.Errorf("New: %v", err)
			return
		}
		if err := d.Reset(); err != nil {
			t.Errorf("cleanup reset: %v", err)
		}
	})

	// One ban rule per shape the compiler can emit: a mixed v4 rule, a
	// v6 rule, and a rule whose range reaches the top of the space
	// (encoded with the null end).
	rules := []splint.BanRule{
		{Targets: []netip.Prefix{
			netip.MustParsePrefix("203.0.113.0/24"),
			netip.MustParsePrefix("198.51.100.7/32"),
		}, Stance: splint.StanceDrop},
		{Targets: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}, Stance: splint.StanceDrop},
		{Targets: []netip.Prefix{netip.MustParsePrefix("255.255.255.0/24")}, Stance: splint.StanceDrop},
	}
	input, err := New(HookInput)
	if err != nil {
		t.Fatalf("New(input): %v", err)
	}
	if err := input.Install(rules); err != nil {
		t.Fatalf("first Install: %v", err)
	}
	assertKernelState(t, conn, HookInput)

	// Rebuilding over the live table proves the delete and the rebuild
	// share one atomic batch; the second install is also the --hook
	// prerouting case.
	prerouting, err := New(HookPrerouting)
	if err != nil {
		t.Fatalf("New(prerouting): %v", err)
	}
	if err := prerouting.Install(rules); err != nil {
		t.Fatalf("rebuild Install: %v", err)
	}
	assertKernelState(t, conn, HookPrerouting)

	// Reset removes the owned table ...
	if err := prerouting.Reset(); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if exists, err := tableExists(conn, ownedTable()); err != nil {
		t.Fatalf("probe after Reset: %v", err)
	} else if exists {
		t.Errorf("table %q still exists after Reset", tableName)
	}
	// ... and tolerates it being already absent.
	if err := prerouting.Reset(); err != nil {
		t.Errorf("second Reset: %v", err)
	}
}

// assertKernelState reads the owned table back from the kernel and
// asserts the driver's encoding: table, ingress chain at hook, one
// source-lookup drop rule per ban rule and family, and the interval
// sets behind them. Expectations are hand-written from the test's
// fixtures, never computed the way the implementation does.
func assertKernelState(t *testing.T, conn *nftables.Conn, hook Hook) {
	t.Helper()
	table, err := conn.ListTableOfFamily(tableName, nftables.TableFamilyINet)
	if err != nil {
		t.Fatalf("read table back: %v", err)
	}
	if table.Name != tableName || table.Family != nftables.TableFamilyINet {
		t.Errorf("table = (%q, %v), want (%q, inet)", table.Name, table.Family, tableName)
	}

	chain, err := conn.ListChain(table, ingressName)
	if err != nil {
		t.Fatalf("read ingress chain back: %v", err)
	}
	wantHook, wantPrio := nftables.ChainHookInput, nftables.ChainPriorityFilter
	if hook == HookPrerouting {
		wantHook, wantPrio = nftables.ChainHookPrerouting, nftables.ChainPriorityRaw
	}
	if chain.Type != nftables.ChainTypeFilter {
		t.Errorf("chain type = %q, want %q", chain.Type, nftables.ChainTypeFilter)
	}
	if chain.Hooknum == nil || *chain.Hooknum != *wantHook {
		t.Errorf("chain hook = %v, want %v", chain.Hooknum, *wantHook)
	}
	if chain.Priority == nil || *chain.Priority != *wantPrio {
		t.Errorf("chain priority = %v, want %v", chain.Priority, *wantPrio)
	}

	// The kernel rules, in install order — one per ban rule and family
	// with targets — and the interval sets behind them: every range is
	// [start, end) with end the first address after it; the
	// top-touching range gets the null end.
	want := []struct {
		proto   byte
		srcOff  uint32
		srcLen  uint32
		setName string
	}{
		{unix.NFPROTO_IPV4, 12, 4, "v4_0"}, // 203.0.113.0/24 + 198.51.100.7/32
		{unix.NFPROTO_IPV6, 8, 16, "v6_1"}, // 2001:db8::/32
		{unix.NFPROTO_IPV4, 12, 4, "v4_2"}, // 255.255.255.0/24
	}
	wantSets := map[string][]string{
		"v4_0": {"end 198.51.100.8", "end 203.0.114.0", "start 198.51.100.7", "start 203.0.113.0"},
		"v6_1": {"end 2001:db9::", "start 2001:db8::"},
		"v4_2": {"end 0.0.0.0", "start 255.255.255.0"},
	}

	krules, err := conn.GetRules(table, chain)
	if err != nil {
		t.Fatalf("read rules back: %v", err)
	}
	if len(krules) != len(want) {
		t.Fatalf("kernel rules = %d, want %d", len(krules), len(want))
	}
	for i, w := range want {
		assertDropRule(t, krules[i], w.proto, w.srcOff, w.srcLen, w.setName)
	}

	sets, err := conn.GetSets(table)
	if err != nil {
		t.Fatalf("read sets back: %v", err)
	}
	if len(sets) != len(wantSets) {
		t.Fatalf("kernel sets = %d, want %d", len(sets), len(wantSets))
	}
	for _, s := range sets {
		wantElems, ok := wantSets[s.Name]
		if !ok {
			t.Errorf("unexpected kernel set %q", s.Name)
			continue
		}
		if !s.Interval {
			t.Errorf("set %q is not an interval set", s.Name)
		}
		elems, err := conn.GetSetElements(s)
		if err != nil {
			t.Fatalf("read set %q elements: %v", s.Name, err)
		}
		var got []string
		for _, e := range elems {
			got = append(got, setElementString(e))
		}
		slices.Sort(got)
		if !slices.Equal(got, wantElems) {
			t.Errorf("set %q elements = %v, want %v", s.Name, got, wantElems)
		}
	}
}

// assertDropRule asserts one kernel rule's encoding: the family gate,
// the source-address lookup into setName and the drop verdict.
func assertDropRule(t *testing.T, r *nftables.Rule, proto byte, srcOff, srcLen uint32, setName string) {
	t.Helper()
	if len(r.Exprs) != 5 {
		t.Fatalf("rule exprs = %d, want 5: %v", len(r.Exprs), r.Exprs)
	}
	meta, ok := r.Exprs[0].(*expr.Meta)
	if !ok || meta.Key != expr.MetaKeyNFPROTO || meta.Register != 1 {
		t.Errorf("exprs[0] = %+v, want the NFPROTO meta load into register 1", r.Exprs[0])
	}
	gate, ok := r.Exprs[1].(*expr.Cmp)
	if !ok || gate.Op != expr.CmpOpEq || gate.Register != 1 || !bytes.Equal(gate.Data, []byte{proto}) {
		t.Errorf("exprs[1] = %+v, want the NFPROTO %d gate", r.Exprs[1], proto)
	}
	payload, ok := r.Exprs[2].(*expr.Payload)
	if !ok || payload.Base != expr.PayloadBaseNetworkHeader ||
		payload.Offset != srcOff || payload.Len != srcLen ||
		payload.DestRegister != 1 || payload.OperationType != expr.PayloadLoad {
		t.Errorf("exprs[2] = %+v, want the source-address load at %d:%d into register 1", r.Exprs[2], srcOff, srcLen)
	}
	lookup, ok := r.Exprs[3].(*expr.Lookup)
	if !ok || lookup.SourceRegister != 1 || lookup.SetName != setName {
		t.Errorf("exprs[3] = %+v, want the lookup of %q from register 1", r.Exprs[3], setName)
	}
	verdict, ok := r.Exprs[4].(*expr.Verdict)
	if !ok || verdict.Kind != expr.VerdictDrop {
		t.Errorf("exprs[4] = %+v, want the drop verdict", r.Exprs[4])
	}
}

// setElementString renders one set element as its kind and key.
func setElementString(e nftables.SetElement) string {
	kind := "start"
	if e.IntervalEnd {
		kind = "end"
	}
	return fmt.Sprintf("%s %s", kind, net.IP(e.Key))
}

// netlinkUnusable reports why the kernel nftables surface cannot be
// tested here ("" when it can): the root gate of the integration test
// and the inverse gate of the loud-failure test share it.
func netlinkUnusable() string {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Sprintf("netlink: %v", err)
	}
	if _, err := conn.ListTablesOfFamily(nftables.TableFamilyINet); err != nil {
		return fmt.Sprintf("nftables: %v", err)
	}
	return ""
}
