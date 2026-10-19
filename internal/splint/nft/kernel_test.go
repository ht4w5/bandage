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
	// rule, matched on destination), a drop whose range reaches the top
	// of the space (encoded with the null end), a rule under the full
	// service prefilter, and a rule whose family the destination
	// prefilter cannot reach — no service traffic lives there, so it
	// gets no kernel rule at all.
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
	input, err := New(HookInput)
	if err != nil {
		t.Fatalf("New(input): %v", err)
	}
	firstHits, err := input.Install(rules)
	if err != nil {
		t.Fatalf("first Install: %v", err)
	}
	if len(firstHits) != 0 {
		t.Errorf("first Install reported %d hits, want none (nothing was installed to count)", len(firstHits))
	}
	if exists, err := input.TableExists(); err != nil || !exists {
		t.Errorf("TableExists after Install = (%v, %v), want (true, nil)", exists, err)
	}
	assertKernelState(t, conn, HookInput)

	// Rebuilding over the live table proves the delete and the rebuild
	// share one atomic batch; the second install is also the --hook
	// prerouting case, and it reports the replaced rules' counter
	// readings mapped onto the ban rules they count (how many depends
	// on what traffic met the fixture rules; the mapping is what is
	// asserted).
	prerouting, err := New(HookPrerouting)
	if err != nil {
		t.Fatalf("New(prerouting): %v", err)
	}
	rebuildHits, err := prerouting.Install(rules)
	if err != nil {
		t.Fatalf("rebuild Install: %v", err)
	}
	for _, h := range rebuildHits {
		if h.Rule < 0 || h.Rule >= len(rules) {
			t.Errorf("counter read-back mapped to ban rule %d, want 0..%d", h.Rule, len(rules)-1)
		}
	}
	assertKernelState(t, conn, HookPrerouting)

	// Reset removes the owned table ...
	if err := prerouting.Reset(); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if exists, err := prerouting.TableExists(); err != nil || exists {
		t.Errorf("TableExists after Reset = (%v, %v), want (false, nil)", exists, err)
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
// kernel rule per ban rule and family the service prefilter can reach
// (source-matched on the ingress chain, the bandwidth meter
// destination-matched on the egress chain) with the stance's verdict
// tail, and the sets behind them. Expectations are hand-written from
// the test's fixtures, never computed the way the implementation does.
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
	// the prefilter can reach. The verdict tails are hand-written from
	// the fixtures: the silent drop, the inet-family reject with icmpx
	// admin-prohibited, the packet-rate meter over 250/second with its
	// derived burst 250 then drop, and the byte-rate meter over
	// 1000000 bytes/second with its derived burst 1000000 then drop.
	// Rule 5 leads with its destination-port and destination-address
	// sets in both families; rule 6's v6 family is unreachable through
	// the v4-only destination set and gets no kernel rule at all.
	ingressRules := []wantRule{
		{proto: unix.NFPROTO_IPV4, off: 12, length: 4, setName: "v4_0", tail: dropTail},                                // 203.0.113.0/24 + 198.51.100.7/32
		{proto: unix.NFPROTO_IPV6, off: 8, length: 16, setName: "v6_1", tail: rejectTail},                              // 2001:db8::/32
		{proto: unix.NFPROTO_IPV4, off: 12, length: 4, setName: "v4_2", tail: limitTail(expr.LimitTypePkts, 250, 250)}, // 198.51.100.9/32
		{proto: unix.NFPROTO_IPV4, off: 12, length: 4, setName: "v4_4", tail: dropTail},                                // 255.255.255.0/24
		{
			proto: unix.NFPROTO_IPV4, off: 12, length: 4, setName: "v4_5",
			l4Set: "l4_5", portSet: "port_5",
			dstSet: "dp4_5", dstOff: 16, dstLen: 4,
			tail: dropTail, // 203.0.113.7/32 under the full service prefilter
		},
		{
			proto: unix.NFPROTO_IPV6, off: 8, length: 16, setName: "v6_5",
			l4Set: "l4_5", portSet: "port_5",
			dstSet: "dp6_5", dstOff: 24, dstLen: 16,
			tail: dropTail, // 2001:db8::7/128 under the full service prefilter
		},
	}
	egressRules := []wantRule{
		{proto: unix.NFPROTO_IPV4, off: 16, length: 4, setName: "v4_3", tail: limitTail(expr.LimitTypePktBytes, 1000000, 1000000)}, // 203.0.113.9/32
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
			tail := assertMatch(t, krules[i], w)
			w.tail(t, tail)
		}
	}
	assertRules(t, ingress, ingressRules)
	assertRules(t, egress, egressRules)

	// The sets behind the rules: every address range is [start, end)
	// with end the first address after it; the top-touching range gets
	// the null end. The port and l4 prefilter sets hold exact keys.
	wantSets := map[string]wantSet{
		"v4_0":   {interval: true, elems: []string{"end 198.51.100.8", "end 203.0.114.0", "start 198.51.100.7", "start 203.0.113.0"}},
		"v6_1":   {interval: true, elems: []string{"end 2001:db9::", "start 2001:db8::"}},
		"v4_2":   {interval: true, elems: []string{"end 198.51.100.10", "start 198.51.100.9"}},
		"v4_3":   {interval: true, elems: []string{"end 203.0.113.10", "start 203.0.113.9"}},
		"v4_4":   {interval: true, elems: []string{"end 0.0.0.0", "start 255.255.255.0"}},
		"v4_5":   {interval: true, elems: []string{"end 203.0.113.8", "start 203.0.113.7"}},
		"dp4_5":  {interval: true, elems: []string{"end 198.51.100.6", "start 198.51.100.5"}},
		"v6_5":   {interval: true, elems: []string{"end 2001:db8::8", "start 2001:db8::7"}},
		"dp6_5":  {interval: true, elems: []string{"end 2001:db8::6", "start 2001:db8::5"}},
		"port_5": {elems: []string{"443", "53"}}, // udp and tcp dports; sorted as strings
		"l4_5":   {elems: []string{"17", "6"}},   // udp and tcp; sorted as strings
	}
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

// wantRule is one expected kernel rule: the leading packet/byte
// counter, the family gate, the service prefilter first (the
// destination-port set behind its l4 gate, then the
// destination-address set — either absent when its set is empty,
// meaning all), the target match and the stance's verdict tail. The
// match load is the source address on the ingress chain and the
// destination address on the egress chain.
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

// wantSet is one expected kernel set: whether it is an interval set
// and its elements, already sorted as strings.
type wantSet struct {
	interval bool
	elems    []string
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

// assertMatch asserts the shared rule prefix in match order — the
// leading packet/byte counter every ban rule carries, the family gate,
// the service prefilter, and the address load at off:len into register
// 1 followed by the lookup of setName — and returns the verdict tail
// for the caller.
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
	// Every ban rule carries its packet/byte counter first: the fixed
	// index the counter read-back finds it at.
	if _, ok := exprs[0].(*expr.Counter); !ok {
		t.Errorf("rule counter = %+v, want the leading packet/byte counter", exprs[0])
	}
	assertMeta(t, "family gate", exprs[1], expr.MetaKeyNFPROTO)
	assertCmp(t, "family gate", exprs[2], []byte{w.proto})
	i := 3
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
	return exprs[i:]
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

// assertMeta checks one meta load into register 1.
func assertMeta(t *testing.T, what string, e expr.Any, key expr.MetaKey) {
	t.Helper()
	meta, ok := e.(*expr.Meta)
	if !ok || meta.Key != key || meta.Register != 1 {
		t.Errorf("%s = %+v, want the meta load into register 1", what, e)
	}
}

// assertCmp checks one comparison of register 1 against data.
func assertCmp(t *testing.T, what string, e expr.Any, data []byte) {
	t.Helper()
	cmp, ok := e.(*expr.Cmp)
	if !ok || cmp.Op != expr.CmpOpEq || cmp.Register != 1 || !bytes.Equal(cmp.Data, data) {
		t.Errorf("%s = %+v, want the register-1 comparison against %v", what, e, data)
	}
}

// assertPayload checks one header-field load into register 1.
func assertPayload(t *testing.T, what string, e expr.Any, base expr.PayloadBase, off, length uint32) {
	t.Helper()
	payload, ok := e.(*expr.Payload)
	if !ok || payload.Base != base || payload.Offset != off || payload.Len != length ||
		payload.DestRegister != 1 || payload.OperationType != expr.PayloadLoad {
		t.Errorf("%s = %+v, want the %d:%d load into register 1", what, e, off, length)
	}
}

// assertLookup checks one set lookup of register 1.
func assertLookup(t *testing.T, what string, e expr.Any, setName string) {
	t.Helper()
	lookup, ok := e.(*expr.Lookup)
	if !ok || lookup.SourceRegister != 1 || lookup.SetName != setName {
		t.Errorf("%s = %+v, want the lookup of %q from register 1", what, e, setName)
	}
}

// elementStrings renders one set's elements as strings — address keys
// with their start/end kind, port and protocol keys as their numbers —
// sorted, for the hand-written expectations.
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
