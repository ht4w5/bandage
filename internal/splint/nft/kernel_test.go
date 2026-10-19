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

	// One ban rule per shape the compiler can emit: a mixed v4 drop, a
	// v6 reject, a packet-rate meter, a bandwidth meter (the one egress
	// rule, matched on destination), and a drop whose range reaches the
	// top of the space (encoded with the null end).
	rules := []splint.BanRule{
		{Targets: []netip.Prefix{
			netip.MustParsePrefix("203.0.113.0/24"),
			netip.MustParsePrefix("198.51.100.7/32"),
		}, Stance: splint.StanceDrop},
		{Targets: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}, Stance: splint.StanceReject},
		{Targets: []netip.Prefix{netip.MustParsePrefix("198.51.100.9/32")}, Stance: splint.StanceLimitPktRate, Rate: ratePtr(250)},
		{Targets: []netip.Prefix{netip.MustParsePrefix("203.0.113.9/32")}, Stance: splint.StanceLimitBandwidth, Rate: ratePtr(1000000)},
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

// ratePtr points at a ban rule rate fixture.
func ratePtr(n int64) *int64 { return &n }

// assertKernelState reads the owned table back from the kernel and
// asserts the driver's encoding: table, both chains at their hooks, one
// match-lookup rule per ban rule and family (source-matched on the
// ingress chain, the bandwidth meter destination-matched on the egress
// chain) with the stance's verdict tail, and the interval sets behind
// them. Expectations are hand-written from the test's fixtures, never
// computed the way the implementation does.
func assertKernelState(t *testing.T, conn *nftables.Conn, hook Hook) {
	t.Helper()
	table, err := conn.ListTableOfFamily(tableName, nftables.TableFamilyINet)
	if err != nil {
		t.Fatalf("read table back: %v", err)
	}
	if table.Name != tableName || table.Family != nftables.TableFamilyINet {
		t.Errorf("table = (%q, %v), want (%q, inet)", table.Name, table.Family, tableName)
	}

	// Both chains, at their hooks: ingress at the configured hook, and
	// egress at output (input mode) or forward (prerouting mode) — the
	// response direction bandwidth limits meter.
	ingressHook, ingressPrio := nftables.ChainHookInput, nftables.ChainPriorityFilter
	egressHook := nftables.ChainHookOutput
	if hook == HookPrerouting {
		ingressHook, ingressPrio = nftables.ChainHookPrerouting, nftables.ChainPriorityRaw
		egressHook = nftables.ChainHookForward
	}
	ingress := assertChain(t, conn, table, ingressName, ingressHook, ingressPrio)
	egress := assertChain(t, conn, table, egressName, egressHook, nftables.ChainPriorityFilter)

	// The kernel rules, in install order: one per ban rule and family
	// with targets. The verdict tails are hand-written from the
	// fixtures: the silent drop, the inet-family reject with icmpx
	// admin-prohibited, the packet-rate meter over 250/second with its
	// derived burst 250 then drop, and the byte-rate meter over
	// 1000000 bytes/second with its derived burst 1000000 then drop.
	type wantRule struct {
		proto   byte
		off     uint32
		length  uint32
		setName string
		tail    tailCheck
	}
	ingressRules := []wantRule{
		{unix.NFPROTO_IPV4, 12, 4, "v4_0", dropTail},                                // 203.0.113.0/24 + 198.51.100.7/32
		{unix.NFPROTO_IPV6, 8, 16, "v6_1", rejectTail},                              // 2001:db8::/32
		{unix.NFPROTO_IPV4, 12, 4, "v4_2", limitTail(expr.LimitTypePkts, 250, 250)}, // 198.51.100.9/32
		{unix.NFPROTO_IPV4, 12, 4, "v4_4", dropTail},                                // 255.255.255.0/24
	}
	egressRules := []wantRule{
		{unix.NFPROTO_IPV4, 16, 4, "v4_3", limitTail(expr.LimitTypePktBytes, 1000000, 1000000)}, // 203.0.113.9/32
	}
	assertRules := func(t *testing.T, chain *nftables.Chain, want []wantRule) {
		t.Helper()
		krules, err := conn.GetRules(table, chain)
		if err != nil {
			t.Fatalf("read %s rules back: %v", chain.Name, err)
		}
		if len(krules) != len(want) {
			t.Fatalf("chain %s rules = %d, want %d: %v", chain.Name, len(krules), len(want), krules)
		}
		for i, w := range want {
			tail := assertMatch(t, krules[i], w.proto, w.off, w.length, w.setName)
			w.tail(t, tail)
		}
	}
	assertRules(t, ingress, ingressRules)
	assertRules(t, egress, egressRules)

	// The interval sets behind the rules: every range is [start, end)
	// with end the first address after it; the top-touching range gets
	// the null end.
	wantSets := map[string][]string{
		"v4_0": {"end 198.51.100.8", "end 203.0.114.0", "start 198.51.100.7", "start 203.0.113.0"},
		"v6_1": {"end 2001:db9::", "start 2001:db8::"},
		"v4_2": {"end 198.51.100.10", "start 198.51.100.9"},
		"v4_3": {"end 203.0.113.10", "start 203.0.113.9"},
		"v4_4": {"end 0.0.0.0", "start 255.255.255.0"},
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

// assertChain reads one base chain back and asserts its shape: filter
// type at hook/prio.
func assertChain(t *testing.T, conn *nftables.Conn, table *nftables.Table, name string, hook *nftables.ChainHook, prio *nftables.ChainPriority) *nftables.Chain {
	t.Helper()
	chain, err := conn.ListChain(table, name)
	if err != nil {
		t.Fatalf("read %s chain back: %v", name, err)
	}
	if chain.Type != nftables.ChainTypeFilter {
		t.Errorf("chain %s type = %q, want %q", name, chain.Type, nftables.ChainTypeFilter)
	}
	if chain.Hooknum == nil || *chain.Hooknum != *hook {
		t.Errorf("chain %s hook = %v, want %v", name, chain.Hooknum, *hook)
	}
	if chain.Priority == nil || *chain.Priority != *prio {
		t.Errorf("chain %s priority = %v, want %v", name, chain.Priority, *prio)
	}
	return chain
}

// tailCheck asserts a kernel rule's verdict tail.
type tailCheck func(t *testing.T, exprs []expr.Any)

// assertMatch asserts the shared rule prefix — the family gate and the
// address load at off:len into register 1 followed by the lookup of
// setName — and returns the verdict tail for the caller.
func assertMatch(t *testing.T, r *nftables.Rule, proto byte, off, length uint32, setName string) []expr.Any {
	t.Helper()
	exprs := r.Exprs
	if len(exprs) < 5 {
		t.Fatalf("rule exprs = %d, want at least 4 match + 1 verdict: %v", len(exprs), exprs)
	}
	meta, ok := exprs[0].(*expr.Meta)
	if !ok || meta.Key != expr.MetaKeyNFPROTO || meta.Register != 1 {
		t.Errorf("exprs[0] = %+v, want the NFPROTO meta load into register 1", exprs[0])
	}
	gate, ok := exprs[1].(*expr.Cmp)
	if !ok || gate.Op != expr.CmpOpEq || gate.Register != 1 || !bytes.Equal(gate.Data, []byte{proto}) {
		t.Errorf("exprs[1] = %+v, want the NFPROTO %d gate", exprs[1], proto)
	}
	payload, ok := exprs[2].(*expr.Payload)
	if !ok || payload.Base != expr.PayloadBaseNetworkHeader ||
		payload.Offset != off || payload.Len != length ||
		payload.DestRegister != 1 || payload.OperationType != expr.PayloadLoad {
		t.Errorf("exprs[2] = %+v, want the address load at %d:%d into register 1", exprs[2], off, length)
	}
	lookup, ok := exprs[3].(*expr.Lookup)
	if !ok || lookup.SourceRegister != 1 || lookup.SetName != setName {
		t.Errorf("exprs[3] = %+v, want the lookup of %q from register 1", exprs[3], setName)
	}
	return exprs[4:]
}

// dropTail asserts the silent drop verdict.
func dropTail(t *testing.T, exprs []expr.Any) {
	t.Helper()
	if len(exprs) != 1 {
		t.Fatalf("verdict exprs = %d, want 1: %v", len(exprs), exprs)
	}
	verdict, ok := exprs[0].(*expr.Verdict)
	if !ok || verdict.Kind != expr.VerdictDrop {
		t.Errorf("verdict = %+v, want the drop verdict", exprs[0])
	}
}

// rejectTail asserts the inet-family reject: icmpx admin-prohibited
// (TCP peers get a reset automatically).
func rejectTail(t *testing.T, exprs []expr.Any) {
	t.Helper()
	if len(exprs) != 1 {
		t.Fatalf("verdict exprs = %d, want 1: %v", len(exprs), exprs)
	}
	rej, ok := exprs[0].(*expr.Reject)
	if !ok || rej.Type != unix.NFT_REJECT_ICMPX_UNREACH || rej.Code != unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED {
		t.Errorf("verdict = %+v, want reject with icmpx admin-prohibited", exprs[0])
	}
}

// limitTail asserts a rate meter tail: the limit expression matching
// once the rate is exceeded (type, rate per second, derived burst)
// followed by the drop of the excess.
func limitTail(limitType expr.LimitType, rate uint64, burst uint32) tailCheck {
	return func(t *testing.T, exprs []expr.Any) {
		t.Helper()
		if len(exprs) != 2 {
			t.Fatalf("verdict exprs = %d, want 2: %v", len(exprs), exprs)
		}
		lim, ok := exprs[0].(*expr.Limit)
		if !ok || lim.Type != limitType || lim.Rate != rate || !lim.Over ||
			lim.Unit != expr.LimitTimeSecond || lim.Burst != burst {
			t.Errorf("meter = %+v, want limit rate over %d/second burst %d", exprs[0], rate, burst)
		}
		verdict, ok := exprs[1].(*expr.Verdict)
		if !ok || verdict.Kind != expr.VerdictDrop {
			t.Errorf("verdict = %+v, want the drop verdict", exprs[1])
		}
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
