package nft

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/HT4w5/webmedkit/splint/internal/firewall"
)

// TestKernelInstallReadBackReset is skipped where root or nftables
// is absent, and refuses to run where a splint table already exists:
// it rebuilds and resets that table, which would drop a live
// deployment's bans.
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
		t.Skipf("table %q exists: a splint instance may be enforcing here", tableName)
	}
	// Whatever the test does halfway, the owned table must not outlive it.
	t.Cleanup(func() {
		d, err := New(Config{Hook: HookInput})
		if err != nil {
			t.Errorf("New: %v", err)
			return
		}
		if err := d.Reset(); err != nil {
			t.Errorf("cleanup reset: %v", err)
		}
	})

	// Phase 1: the unscoped encoding. The 255.255.255.0/24 drop
	// exercises the null-end encoding of a top-touching range.
	rules := []firewall.BanRule{
		{Targets: []netip.Prefix{
			netip.MustParsePrefix("203.0.113.0/24"),
			netip.MustParsePrefix("198.51.100.7/32"),
		}, Stance: firewall.StanceDrop},
		{Targets: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}, Stance: firewall.StanceReject},
		{Targets: []netip.Prefix{netip.MustParsePrefix("198.51.100.9/32")}, Stance: firewall.StanceLimitPktRate, Rate: ratePtr(250)},
		{Targets: []netip.Prefix{netip.MustParsePrefix("203.0.113.9/32")}, Stance: firewall.StanceLimitBandwidth, Rate: ratePtr(1000000)},
		{Targets: []netip.Prefix{netip.MustParsePrefix("255.255.255.0/24")}, Stance: firewall.StanceDrop},
	}
	input, err := New(Config{Hook: HookInput})
	if err != nil {
		t.Fatalf("New(input): %v", err)
	}
	first, err := input.Apply(rules)
	if err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	if len(first.Hits) != 0 {
		t.Errorf("first Apply reported %d hits, want none (nothing was installed to count)", len(first.Hits))
	}
	if exists, err := tableExists(conn, ownedTable()); err != nil || !exists {
		t.Errorf("table exists after Apply = (%v, %v), want (true, nil)", exists, err)
	}
	assertUnscopedKernelState(t, conn, HookInput)

	// Phase 2: the scoped encoding at prerouting, rebuilding over the
	// live table. Hit counts vary: only the mapping is asserted.
	scope := Prefilter{
		DstPorts: []uint16{53, 443},
		DstAddrs: []netip.Prefix{
			netip.MustParsePrefix("198.51.100.5/32"),
			netip.MustParsePrefix("2001:db8::5/128"),
		},
	}
	scopedRules := []firewall.BanRule{{
		Targets: []netip.Prefix{
			netip.MustParsePrefix("203.0.113.7/32"),
			netip.MustParsePrefix("2001:db8::7/128"),
		},
		Stance: firewall.StanceDrop,
	}}
	prerouting, err := New(Config{Hook: HookPrerouting, Prefilter: scope})
	if err != nil {
		t.Fatalf("New(prerouting): %v", err)
	}
	rebuild, err := prerouting.Apply(scopedRules)
	if err != nil {
		t.Fatalf("rebuild Apply: %v", err)
	}
	for _, h := range rebuild.Hits {
		if h.Rule < 0 || h.Rule >= len(rules) {
			t.Errorf("counter read-back mapped to ban rule %d, want 0..%d (the replaced rules)", h.Rule, len(rules)-1)
		}
	}
	assertScopedKernelState(t, conn, HookPrerouting)

	// Phase 3: the rule's only family has no destination in the scope,
	// so it gets no kernel rule at all.
	v4Only, err := New(Config{Hook: HookInput, Prefilter: Prefilter{
		DstPorts: []uint16{443},
		DstAddrs: []netip.Prefix{netip.MustParsePrefix("198.51.100.5/32")},
	}})
	if err != nil {
		t.Fatalf("New(v4-only scope): %v", err)
	}
	if _, err := v4Only.Apply([]firewall.BanRule{{
		Targets: []netip.Prefix{netip.MustParsePrefix("2001:db8::9/128")},
		Stance:  firewall.StanceDrop,
	}}); err != nil {
		t.Fatalf("unreachable-family Apply: %v", err)
	}
	assertEmptyKernelState(t, conn)

	if err := prerouting.Reset(); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if exists, err := tableExists(conn, ownedTable()); err != nil || exists {
		t.Errorf("table exists after Reset = (%v, %v), want (false, nil)", exists, err)
	}
	if exists, err := tableExists(conn, ownedTable()); err != nil {
		t.Fatalf("probe after Reset: %v", err)
	} else if exists {
		t.Errorf("table %q still exists after Reset", tableName)
	}
	if err := prerouting.Reset(); err != nil {
		t.Errorf("second Reset: %v", err)
	}
}

func TestKernelDeclinesInstallNothing(t *testing.T) {
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
		t.Skipf("table %q exists: a splint instance may be enforcing here", tableName)
	}
	t.Cleanup(func() {
		d, err := New(Config{Hook: HookInput})
		if err != nil {
			t.Errorf("New: %v", err)
			return
		}
		if err := d.Reset(); err != nil {
			t.Errorf("cleanup reset: %v", err)
		}
	})

	rules := []firewall.BanRule{
		{Targets: []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32")}, Stance: firewall.StanceDrop},
		{Targets: []netip.Prefix{netip.MustParsePrefix("198.51.100.9/32")}, Stance: firewall.StanceLimitReqRate, Rate: ratePtr(300)},
	}
	d, err := New(Config{Hook: HookInput})
	if err != nil {
		t.Fatalf("New(input): %v", err)
	}
	out, err := d.Apply(rules)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(out.Declined) != 1 {
		t.Fatalf("Install reported %d declines, want 1: %+v", len(out.Declined), out.Declined)
	}
	if got := out.Declined[0]; got.Rule != 1 || got.Feature != "limit-req-rate" || got.Reason == "" {
		t.Errorf("Declined = %+v, want rule 1's limit-req-rate with a reason", got)
	}

	table, err := conn.ListTableOfFamily(tableName, nftables.TableFamilyINet)
	if err != nil {
		t.Fatalf("read table back: %v", err)
	}
	for chainName, want := range map[string]int{ingressName: 1, egressName: 0} {
		chain, err := conn.ListChain(table, chainName)
		if err != nil {
			t.Fatalf("read chain %s back: %v", chainName, err)
		}
		krules, err := conn.GetRules(table, chain)
		if err != nil {
			t.Fatalf("read rules of %s back: %v", chainName, err)
		}
		if len(krules) != want {
			t.Errorf("chain %s carries %d kernel rules, want %d (the declined rule installs nothing)", chainName, len(krules), want)
		}
	}

	if err := d.Reset(); err != nil {
		t.Fatalf("Reset: %v", err)
	}
}

func ratePtr(n int64) *int64 { return &n }

// assertUnscopedKernelState reads the owned table back and asserts
// the unscoped fixture's encoding. Expectations are hand-written
// from the fixtures, never computed the way the implementation does.
func assertUnscopedKernelState(t *testing.T, conn *nftables.Conn, hook Hook) {
	t.Helper()
	// The kernel rules, in install order.
	ingressRules := []wantRule{
		{proto: unix.NFPROTO_IPV4, off: 12, length: 4, setName: "v4_0", tail: dropTail},                                // 203.0.113.0/24 + 198.51.100.7/32
		{proto: unix.NFPROTO_IPV6, off: 8, length: 16, setName: "v6_1", tail: rejectTail},                              // 2001:db8::/32
		{proto: unix.NFPROTO_IPV4, off: 12, length: 4, setName: "v4_2", tail: limitTail(expr.LimitTypePkts, 250, 250)}, // 198.51.100.9/32
		{proto: unix.NFPROTO_IPV4, off: 12, length: 4, setName: "v4_4", tail: dropTail},                                // 255.255.255.0/24
	}
	egressRules := []wantRule{
		{proto: unix.NFPROTO_IPV4, off: 16, length: 4, setName: "v4_3", tail: limitTail(expr.LimitTypePktBytes, 1000000, 1000000)}, // 203.0.113.9/32
	}
	// The sets behind the rules; v4_4's top-touching range gets the
	// null end (its "end 0.0.0.0" element).
	wantSets := map[string]wantSet{
		"v4_0": {interval: true, elems: []string{"end 198.51.100.8", "end 203.0.114.0", "start 198.51.100.7", "start 203.0.113.0"}},
		"v6_1": {interval: true, elems: []string{"end 2001:db9::", "start 2001:db8::"}},
		"v4_2": {interval: true, elems: []string{"end 198.51.100.10", "start 198.51.100.9"}},
		"v4_3": {interval: true, elems: []string{"end 203.0.113.10", "start 203.0.113.9"}},
		"v4_4": {interval: true, elems: []string{"end 0.0.0.0", "start 255.255.255.0"}},
	}
	assertKernelState(t, conn, hook, ingressRules, egressRules, wantSets)
}

// assertScopedKernelState reads the owned table back and asserts the
// scoped fixture's encoding: the rule under the full service
// prefilter, in both families.
func assertScopedKernelState(t *testing.T, conn *nftables.Conn, hook Hook) {
	t.Helper()
	ingressRules := []wantRule{
		{
			proto: unix.NFPROTO_IPV4, off: 12, length: 4, setName: "v4_0",
			l4Set: "l4_0", portSet: "port_0",
			dstSet: "dp4_0", dstOff: 16, dstLen: 4,
			tail: dropTail, // 203.0.113.7/32 under the full service prefilter
		},
		{
			proto: unix.NFPROTO_IPV6, off: 8, length: 16, setName: "v6_0",
			l4Set: "l4_0", portSet: "port_0",
			dstSet: "dp6_0", dstOff: 24, dstLen: 16,
			tail: dropTail, // 2001:db8::7/128 under the full service prefilter
		},
	}
	wantSets := map[string]wantSet{
		"v4_0":   {interval: true, elems: []string{"end 203.0.113.8", "start 203.0.113.7"}},
		"dp4_0":  {interval: true, elems: []string{"end 198.51.100.6", "start 198.51.100.5"}},
		"v6_0":   {interval: true, elems: []string{"end 2001:db8::8", "start 2001:db8::7"}},
		"dp6_0":  {interval: true, elems: []string{"end 2001:db8::6", "start 2001:db8::5"}},
		"port_0": {elems: []string{"443", "53"}}, // udp and tcp dports; sorted as strings
		"l4_0":   {elems: []string{"17", "6"}},   // udp and tcp; sorted as strings
	}
	assertKernelState(t, conn, hook, ingressRules, nil, wantSets)
}

// assertEmptyKernelState asserts a rebuild that installed nothing:
// both chains carry no kernel rules and there are no sets at all.
func assertEmptyKernelState(t *testing.T, conn *nftables.Conn) {
	t.Helper()
	table, err := conn.ListTableOfFamily(tableName, nftables.TableFamilyINet)
	if err != nil {
		t.Fatalf("read table back: %v", err)
	}
	for _, name := range []string{ingressName, egressName} {
		chain, err := conn.ListChain(table, name)
		if err != nil {
			t.Fatalf("read chain %s back: %v", name, err)
		}
		krules, err := conn.GetRules(table, chain)
		if err != nil {
			t.Fatalf("read rules of %s back: %v", name, err)
		}
		if len(krules) != 0 {
			t.Errorf("chain %s carries %d kernel rules, want 0 (the unreachable ban rule installs nothing)", name, len(krules))
		}
	}
	sets, err := conn.GetSets(table)
	if err != nil {
		t.Fatalf("read sets back: %v", err)
	}
	if len(sets) != 0 {
		t.Errorf("kernel sets = %d, want 0 (the unreachable ban rule installs nothing)", len(sets))
	}
}

// assertKernelState asserts the shared encoding shape the wrappers
// above hand-write their wants for: chains at their hooks, each
// wanted rule's match order ending in its verdict tail, and the sets.
func assertKernelState(t *testing.T, conn *nftables.Conn, hook Hook, ingressRules, egressRules []wantRule, wantSets map[string]wantSet) {
	t.Helper()
	table, err := conn.ListTableOfFamily(tableName, nftables.TableFamilyINet)
	if err != nil {
		t.Fatalf("read table back: %v", err)
	}
	if table.Name != tableName || table.Family != nftables.TableFamilyINet {
		t.Errorf("table = (%q, %v), want (%q, inet)", table.Name, table.Family, tableName)
	}

	// Egress sits where the response direction flows: output in input
	// mode, forward in prerouting mode.
	ingressHook, ingressPrio := nftables.ChainHookInput, nftables.ChainPriorityFilter
	egressHook := nftables.ChainHookOutput
	if hook == HookPrerouting {
		ingressHook, ingressPrio = nftables.ChainHookPrerouting, nftables.ChainPriorityRaw
		egressHook = nftables.ChainHookForward
	}
	ingress := assertChain(t, conn, table, ingressName, ingressHook, ingressPrio)
	egress := assertChain(t, conn, table, egressName, egressHook, nftables.ChainPriorityFilter)

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
			tail := assertMatch(t, krules[i], w)
			w.tail(t, tail)
		}
	}
	assertRules(t, ingress, ingressRules)
	assertRules(t, egress, egressRules)

	sets, err := conn.GetSets(table)
	if err != nil {
		t.Fatalf("read sets back: %v", err)
	}
	if len(sets) != len(wantSets) {
		t.Fatalf("kernel sets = %d, want %d", len(sets), len(wantSets))
	}
	for _, s := range sets {
		w, ok := wantSets[s.Name]
		if !ok {
			t.Errorf("unexpected kernel set %q", s.Name)
			continue
		}
		if s.Interval != w.interval {
			t.Errorf("set %q interval = %v, want %v", s.Name, s.Interval, w.interval)
		}
		elems, err := conn.GetSetElements(s)
		if err != nil {
			t.Fatalf("read set %q elements: %v", s.Name, err)
		}
		got := elementStrings(s, elems)
		if !slices.Equal(got, w.elems) {
			t.Errorf("set %q elements = %v, want %v", s.Name, got, w.elems)
		}
	}
}

// wantRule is one expected kernel rule: the match prefix in order,
// then the counter and the stance's verdict tail. The match load is
// the source address on ingress, the destination address on egress.
type wantRule struct {
	proto   byte
	off     uint32
	length  uint32
	setName string

	l4Set   string // non-empty: the port prefilter gates on l4proto ∈ l4Set
	portSet string
	dstSet  string // non-empty: the destination-address prefilter set
	dstOff  uint32
	dstLen  uint32

	tail tailCheck
}

// wantSet is one expected kernel set: interval flag and elements,
// already sorted as strings.
type wantSet struct {
	interval bool
	elems    []string
}

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

// assertMatch asserts the shared rule prefix in match order, then
// the counter immediately before the verdict, and returns the
// verdict tail for the caller.
func assertMatch(t *testing.T, r *nftables.Rule, w wantRule) []expr.Any {
	t.Helper()
	exprs := r.Exprs
	wantLen := 6
	if w.portSet != "" {
		wantLen += 4
	}
	if w.dstSet != "" {
		wantLen += 2
	}
	if len(exprs) < wantLen {
		t.Fatalf("rule exprs = %d, want at least %d: %v", len(exprs), wantLen, exprs)
	}
	assertMeta(t, "family gate", exprs[0], expr.MetaKeyNFPROTO)
	assertCmp(t, "family gate", exprs[1], []byte{w.proto})
	i := 2
	if w.portSet != "" {
		assertMeta(t, "l4proto gate", exprs[i], expr.MetaKeyL4PROTO)
		i++
		assertLookup(t, "l4proto set", exprs[i], w.l4Set)
		i++
		assertPayload(t, "destination-port load", exprs[i], expr.PayloadBaseTransportHeader, 2, 2)
		i++
		assertLookup(t, "destination-port set", exprs[i], w.portSet)
		i++
	}
	if w.dstSet != "" {
		assertPayload(t, "destination-address load", exprs[i], expr.PayloadBaseNetworkHeader, w.dstOff, w.dstLen)
		i++
		assertLookup(t, "destination-address set", exprs[i], w.dstSet)
		i++
	}
	assertPayload(t, "target-address load", exprs[i], expr.PayloadBaseNetworkHeader, w.off, w.length)
	i++
	assertLookup(t, "target set", exprs[i], w.setName)
	i++
	if _, ok := exprs[i].(*expr.Counter); !ok {
		t.Errorf("rule counter = %+v, want the packet/byte counter before the verdict", exprs[i])
	}
	i++
	return exprs[i:]
}

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

func assertMeta(t *testing.T, what string, e expr.Any, key expr.MetaKey) {
	t.Helper()
	meta, ok := e.(*expr.Meta)
	if !ok || meta.Key != key || meta.Register != 1 {
		t.Errorf("%s = %+v, want the meta load into register 1", what, e)
	}
}

func assertCmp(t *testing.T, what string, e expr.Any, data []byte) {
	t.Helper()
	cmp, ok := e.(*expr.Cmp)
	if !ok || cmp.Op != expr.CmpOpEq || cmp.Register != 1 || !bytes.Equal(cmp.Data, data) {
		t.Errorf("%s = %+v, want the register-1 comparison against %v", what, e, data)
	}
}

func assertPayload(t *testing.T, what string, e expr.Any, base expr.PayloadBase, off, length uint32) {
	t.Helper()
	payload, ok := e.(*expr.Payload)
	if !ok || payload.Base != base || payload.Offset != off || payload.Len != length ||
		payload.DestRegister != 1 || payload.OperationType != expr.PayloadLoad {
		t.Errorf("%s = %+v, want the %d:%d load into register 1", what, e, off, length)
	}
}

func assertLookup(t *testing.T, what string, e expr.Any, setName string) {
	t.Helper()
	lookup, ok := e.(*expr.Lookup)
	if !ok || lookup.SourceRegister != 1 || lookup.SetName != setName {
		t.Errorf("%s = %+v, want the lookup of %q from register 1", what, e, setName)
	}
}

// elementStrings renders one set's elements as sorted strings for
// the hand-written expectations.
func elementStrings(s *nftables.Set, elems []nftables.SetElement) []string {
	var got []string
	for _, e := range elems {
		switch s.KeyType {
		case nftables.TypeInetService:
			got = append(got, fmt.Sprintf("%d", binary.BigEndian.Uint16(e.Key)))
		case nftables.TypeInetProto:
			got = append(got, fmt.Sprintf("%d", e.Key[0]))
		default:
			kind := "start"
			if e.IntervalEnd {
				kind = "end"
			}
			got = append(got, fmt.Sprintf("%s %s", kind, net.IP(e.Key)))
		}
	}
	slices.Sort(got)
	return got
}

// netlinkUnusable reports why the kernel nftables surface cannot be
// tested here ("" when it can); shared by the root gate and the
// loud-failure test's inverse gate.
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
