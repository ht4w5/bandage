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

	// One ban rule per shape the compiler can emit: a mixed v4 rule, a
	// v6 rule, a rule whose range reaches the top of the space (encoded
	// with the null end), a rule under the full service prefilter, and a
	// rule whose family the destination prefilter cannot reach — no
	// service traffic lives there, so it gets no kernel rule at all.
	rules := []splint.BanRule{
		{Targets: []netip.Prefix{
			netip.MustParsePrefix("203.0.113.0/24"),
			netip.MustParsePrefix("198.51.100.7/32"),
		}, Stance: splint.StanceDrop},
		{Targets: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}, Stance: splint.StanceDrop},
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
// kernel rule per ban rule and family the prefilter can reach, and the
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

	// The kernel rules, in install order: rules 0-2 have no prefilter,
	// rule 3 leads with its destination-port and destination-address
	// sets in both families, rule 4's v6 family is unreachable through
	// the v4-only destination set and gets no rule.
	want := []wantBanRule{
		{proto: unix.NFPROTO_IPV4, srcOff: 12, srcLen: 4, setName: "v4_0"}, // 203.0.113.0/24 + 198.51.100.7/32
		{proto: unix.NFPROTO_IPV6, srcOff: 8, srcLen: 16, setName: "v6_1"}, // 2001:db8::/32
		{proto: unix.NFPROTO_IPV4, srcOff: 12, srcLen: 4, setName: "v4_2"}, // 255.255.255.0/24
		{
			proto: unix.NFPROTO_IPV4, srcOff: 12, srcLen: 4, setName: "v4_3",
			l4Set: "l4_3", portSet: "port_3",
			dstSet: "dp4_3", dstOff: 16, dstLen: 4,
		},
		{
			proto: unix.NFPROTO_IPV6, srcOff: 8, srcLen: 16, setName: "v6_3",
			l4Set: "l4_3", portSet: "port_3",
			dstSet: "dp6_3", dstOff: 24, dstLen: 16,
		},
	}
	wantSets := map[string]wantSet{
		"v4_0":   {interval: true, elems: []string{"end 198.51.100.8", "end 203.0.114.0", "start 198.51.100.7", "start 203.0.113.0"}},
		"v6_1":   {interval: true, elems: []string{"end 2001:db9::", "start 2001:db8::"}},
		"v4_2":   {interval: true, elems: []string{"end 0.0.0.0", "start 255.255.255.0"}},
		"v4_3":   {interval: true, elems: []string{"end 203.0.113.8", "start 203.0.113.7"}},
		"dp4_3":  {interval: true, elems: []string{"end 198.51.100.6", "start 198.51.100.5"}},
		"v6_3":   {interval: true, elems: []string{"end 2001:db8::8", "start 2001:db8::7"}},
		"dp6_3":  {interval: true, elems: []string{"end 2001:db8::6", "start 2001:db8::5"}},
		"port_3": {elems: []string{"443", "53"}}, // udp and tcp dports; sorted as strings
		"l4_3":   {elems: []string{"17", "6"}},   // udp and tcp; sorted as strings
	}

	krules, err := conn.GetRules(table, chain)
	if err != nil {
		t.Fatalf("read rules back: %v", err)
	}
	if len(krules) != len(want) {
		t.Fatalf("kernel rules = %d, want %d", len(krules), len(want))
	}
	for i, w := range want {
		assertBanRule(t, krules[i], w)
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

// wantBanRule is one expected kernel rule: the family gate, the
// service prefilter first (the destination-port set behind its l4
// gate, then the destination-address set — either absent when its set
// is empty, meaning all), the source lookup and the drop verdict.
type wantBanRule struct {
	proto   byte
	srcOff  uint32
	srcLen  uint32
	setName string

	l4Set   string // non-empty: the port prefilter gates on l4proto ∈ l4Set
	portSet string
	dstSet  string // non-empty: the destination-address prefilter set
	dstOff  uint32
	dstLen  uint32
}

// wantSet is one expected kernel set: whether it is an interval set
// and its elements, already sorted as strings.
type wantSet struct {
	interval bool
	elems    []string
}

// assertBanRule asserts one kernel rule's encoding, walking the
// expressions in match order: the family gate, the service prefilter,
// the source lookup, the verdict.
func assertBanRule(t *testing.T, r *nftables.Rule, w wantBanRule) {
	t.Helper()
	exprs := r.Exprs
	wantLen := 5
	if w.portSet != "" {
		wantLen += 4
	}
	if w.dstSet != "" {
		wantLen += 2
	}
	if len(exprs) != wantLen {
		t.Fatalf("rule exprs = %d, want %d: %v", len(exprs), wantLen, exprs)
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
	assertPayload(t, "source-address load", exprs[i], expr.PayloadBaseNetworkHeader, w.srcOff, w.srcLen)
	i++
	assertLookup(t, "source set", exprs[i], w.setName)
	i++
	verdict, ok := exprs[i].(*expr.Verdict)
	if !ok || verdict.Kind != expr.VerdictDrop {
		t.Errorf("%s = %+v, want the drop verdict", "verdict", exprs[i])
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
