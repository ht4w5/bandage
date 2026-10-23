// Package nft is splint's nftables firewall driver: it enforces the
// firewall seam's ban rules through netlink
// (github.com/google/nftables) — one wholly-owned inet table named
// splint in the target namespace, rebuilt wholesale in a single
// atomic batch per apply (fluxc's delete-then-rebuild gap is
// deliberately not copied), removed on reset. It applies each Penalty
// exactly as stated or declines it: limit-req-rate is application-layer
// intent and is never faked at the packet layer (ADR 0012).
//
// The driver owns its identity: the rolling hash over its effective
// rules, the skip-if-unchanged decision with its existence probe and
// the counter read-back live here, because only this driver knows
// which ban rules are actually effective and which it drops.
package nft

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/HT4w5/bandage/internal/firewall"
)

// The wholly-owned nftables objects: one inet table per target
// namespace, carrying the ingress chain at the configured hook and the
// egress chain behind the bandwidth limits. The chain names are the
// placement labels the driver's plan reports (the --dry-run mapping
// lines name these chains).
const (
	tableName   = "splint"
	ingressName = "ingress"
	egressName  = "egress"
)

// Hook is the enforcement hook the ingress chain attaches to: input
// catches locally-destined traffic (a web server host), prerouting
// catches transit and local traffic (a routing box).
type Hook string

// The two v0 enforcement hooks (--hook).
const (
	HookInput      Hook = "input"
	HookPrerouting Hook = "prerouting"
)

// ParseHook maps the --hook flag value onto a Hook.
func ParseHook(s string) (Hook, error) {
	h := Hook(s)
	if !h.valid() {
		return "", fmt.Errorf("hook: must be input or prerouting (got %q)", s)
	}
	return h, nil
}

// valid reports whether h is one of the two enforcement hooks.
func (h Hook) valid() bool {
	return h == HookInput || h == HookPrerouting
}

// Driver is the nftables implementation of the firewall.Driver port.
// It owns one table per target namespace and its identity: plan is
// pure, apply rebuilds that table wholesale in one atomic batch —
// skipping the install when the plan's hash matches the ruleset it
// last applied and the table still exists — reset removes it. One
// Driver targets one namespace: netns is its nsfs handle path, "" the
// current namespace.
type Driver struct {
	hook  Hook
	netns string

	// open dials the netlink surface of the target namespace —
	// openNetlink in production, the fake kernel stand-in in the
	// driver's tests.
	open func() (kernelConn, io.Closer, error)

	// The skip-if-unchanged state, per driver instance: the ruleset
	// hash last applied here (installed marks that an apply has
	// succeeded — the zero hash is a legal hash).
	hash      uint32
	installed bool
}

var _ firewall.Driver = (*Driver)(nil)

// kernelConn is the netlink surface the driver flushes through —
// *nftables.Conn in production, the fake kernel stand-in in the
// driver's tests. The driver's plan/apply logic is verified against
// the stand-in without privileges (fakekernel_test.go); the real
// encoding is verified by the root-gated kernel test.
type kernelConn interface {
	AddTable(*nftables.Table) *nftables.Table
	AddChain(*nftables.Chain) *nftables.Chain
	AddSet(*nftables.Set, []nftables.SetElement) error
	AddRule(*nftables.Rule) *nftables.Rule
	DelTable(*nftables.Table)
	Flush() error
	ListTableOfFamily(name string, family nftables.TableFamily) (*nftables.Table, error)
	ListChain(table *nftables.Table, chain string) (*nftables.Chain, error)
	GetRules(table *nftables.Table, chain *nftables.Chain) ([]*nftables.Rule, error)
}

var _ kernelConn = (*nftables.Conn)(nil)

// New builds a driver whose ingress chain attaches at hook in the
// current namespace.
func New(hook Hook) (*Driver, error) {
	return NewNetNS(hook, "")
}

// NewNetNS builds a driver targeting the network namespace at the
// nsfs handle path ("" is the current namespace). The handle is
// re-opened on every apply and reset — a recreated container is
// picked up through its stable handle.
func NewNetNS(hook Hook, netnsPath string) (*Driver, error) {
	if !hook.valid() {
		return nil, fmt.Errorf("hook: must be input or prerouting (got %q)", hook)
	}
	d := &Driver{hook: hook, netns: netnsPath}
	d.open = d.openNetlink
	return d, nil
}

// openNetlink dials the real netlink connection to this driver's
// target namespace — the current one for an empty path. The
// per-namespace connection is created through the library's
// namespace-fd option (no setns, no thread locking in application
// code), and the nsfs handle is re-opened on every call and kept open
// until the connection's Flush returns: the library dials lazily at
// flush time and the open handle is what keeps the namespace alive
// meanwhile. A handle that cannot be opened is a vanished namespace:
// it wraps firewall.ErrUnreachable, which the update cycle warns and
// skips.
func (d *Driver) openNetlink() (kernelConn, io.Closer, error) {
	if d.netns == "" {
		conn, err := nftables.New()
		if err != nil {
			return nil, nil, fmt.Errorf("connect: %w", err)
		}
		return conn, nil, nil
	}
	nsFile, err := os.Open(d.netns)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: open netns %s: %w", firewall.ErrUnreachable, d.netns, err)
	}
	conn, err := nftables.New(nftables.WithNetNSFd(int(nsFile.Fd())))
	if err != nil {
		nsFile.Close()
		return nil, nil, fmt.Errorf("%w: connect netns %s: %w", firewall.ErrUnreachable, d.netns, err)
	}
	return conn, nsFile, nil
}

// ownedTable is the wholly-owned table both Install and Reset address.
func ownedTable() *nftables.Table {
	return &nftables.Table{Family: nftables.TableFamilyINet, Name: tableName}
}

// tableExists probes for the owned table: the cheap existence check
// every apply consults before anything is decided (only a table known
// to exist may skip, and only a present table's delete may join the
// batch — a delete of a missing table aborts the whole batch with
// ENOENT).
func tableExists(conn kernelConn, table *nftables.Table) (bool, error) {
	if _, err := conn.ListTableOfFamily(table.Name, table.Family); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Plan is the pure planning step — no I/O, no privileges: it derives
// the effective rules this driver would install (the ban rules it can
// honour, after the declines and the drops, narrowed to the target
// prefixes that reach their address families), their placement labels
// (the chain each rule installs in at the hook that chain attaches to
// — so a change of --hook is a change of effective rules), the
// ruleset hash folding those effective rules, and the declines with
// reasons. --dry-run prints exactly this. A ban rule the driver can
// neither honour nor decline — an unknown stance, a limit without a
// usable rate — refuses the plan loudly.
func (d *Driver) Plan(rules []firewall.BanRule) (firewall.Plan, error) {
	plan := firewall.Plan{}
	for i, r := range rules {
		if r.Stance == firewall.StanceLimitReqRate {
			// A limit-req-rate Penalty throttles requests per second —
			// application-layer intent the packet layer cannot count —
			// so this driver declines it with a reason and installs
			// nothing for it, never faking the request rate as a packet
			// or byte meter (ADR 0012 narrows ADR 0011: non-application
			// is this driver's decision, not a blanket policy). The
			// decline references the ban rule by its index in the
			// ruleset handed to the driver.
			plan.Declined = append(plan.Declined, firewall.Decline{
				Rule:    i,
				Feature: string(r.Stance),
				Reason:  "application-layer intent; never faked at the packet layer",
			})
			continue
		}
		placement, err := d.placement(r.Stance)
		if err != nil {
			return firewall.Plan{}, fmt.Errorf("ban rule %d: %w", i, err)
		}
		if err := checkRate(r); err != nil {
			return firewall.Plan{}, fmt.Errorf("ban rule %d: %w", i, err)
		}
		fams := ruleFamilies(r)
		if len(fams) == 0 {
			continue // the service prefilter cannot reach it: it installs nothing
		}
		effective := r
		effective.Targets = nil
		for _, f := range fams {
			effective.Targets = append(effective.Targets, f.targets...)
		}
		plan.Rules = append(plan.Rules, firewall.PlannedRule{BanRule: effective, Placement: placement})
	}
	plan.Hash = firewall.Hash(plan.Rules)
	return plan, nil
}

// placement reports the ban rule's placement label — the chain it
// installs in at the hook that chain attaches to — and refuses a
// stance this driver cannot enforce at the packet layer.
func (d *Driver) placement(s firewall.Stance) (string, error) {
	name, matchDst, err := directionOf(s)
	if err != nil {
		return "", err
	}
	hook := string(d.hook) // the ingress chain attaches at the configured hook
	if matchDst {
		// The egress chain carries the response direction: locally
		// generated responses at output in input mode, transit
		// responses at forward in prerouting mode.
		hook = "output"
		if d.hook == HookPrerouting {
			hook = "forward"
		}
	}
	return name + "@" + hook, nil
}

// directionOf reports the chain a stance installs in and where its
// target match looks: source on the ingress chain for the
// source-facing stances, destination on the egress chain for the
// bandwidth meter (the response direction its unit names). Unknown
// stances are refused loudly.
func directionOf(s firewall.Stance) (name string, matchDst bool, err error) {
	switch s {
	case firewall.StanceDrop, firewall.StanceReject, firewall.StanceLimitPktRate:
		return ingressName, false, nil
	case firewall.StanceLimitBandwidth:
		return egressName, true, nil
	}
	return "", false, fmt.Errorf("stance %q: not supported", s)
}

// checkRate refuses a limit stance without a rate the kernel meter
// can honour exactly as stated — no rate means nothing to meter, and
// the driver never tunes a stated rate.
func checkRate(r firewall.BanRule) error {
	switch r.Stance {
	case firewall.StanceLimitPktRate, firewall.StanceLimitBandwidth:
		if r.Rate == nil {
			return fmt.Errorf("stance %q: rate required", r.Stance)
		}
		if *r.Rate < 1 {
			return fmt.Errorf("stance %q: rate must be at least 1 (got %d)", r.Stance, *r.Rate)
		}
	}
	return nil
}

// Apply replaces the owned table wholesale in one atomic batch — or
// skips the install when the plan's hash matches the ruleset it last
// applied here and the owned table still exists (probed fresh every
// apply) — and reports what happened: the ruleset hash, the nonzero
// packet/byte counters of the rules it replaced (the hits covering
// the period since the last change; none on a skipped cycle) and the
// ban-rule features it declines. The probe decides both the skip and
// whether the delete joins the batch; the replaced rules' counters
// are read back first; then the table, both chains and one kernel rule
// per honoureable ban rule and address family — each leading with the
// service prefilter and carrying its packet/byte counter immediately
// before the verdict — are buffered and flushed together. The table is
// never absent while the new one applies — there is no
// delete-then-rebuild window. A declined ban rule keeps its input
// index (the correlation the decline and the counter read-back share)
// and installs nothing.
func (d *Driver) Apply(rules []firewall.BanRule) (firewall.Outcome, error) {
	plan, err := d.Plan(rules)
	if err != nil {
		return firewall.Outcome{}, fmt.Errorf("apply: %w", err)
	}
	conn, closer, err := d.open()
	if err != nil {
		return firewall.Outcome{}, fmt.Errorf("apply: %w", err)
	}
	if closer != nil {
		// The handle stays open through Flush (see openNetlink).
		defer closer.Close()
	}
	table := ownedTable()
	// The existence probe — fresh every apply. Known limit: it is
	// existence, not rule bodies — tampering under a surviving table is
	// undetected. Only a table known to exist may skip (an unchanged
	// ruleset must not hide behind a vanished enforcement point), and
	// only a present table's delete may join the batch (deleting a
	// missing one aborts the whole transaction with ENOENT).
	exists, err := tableExists(conn, table)
	if err != nil {
		return firewall.Outcome{}, fmt.Errorf("apply: probe owned table: %w", err)
	}
	if d.installed && plan.Hash == d.hash && exists {
		return firewall.Outcome{Skipped: true, Hash: plan.Hash, Declined: plan.Declined}, nil
	}
	var hits []firewall.Hit
	if exists {
		hits, err = ruleHits(conn, table)
		if err != nil {
			return firewall.Outcome{}, fmt.Errorf("apply: read rule counters: %w", err)
		}
		conn.DelTable(table)
	}
	table = conn.AddTable(table)
	ingress := conn.AddChain(d.ingress(table))
	egress := conn.AddChain(d.egress(table))
	declined := map[int]bool{}
	for _, decline := range plan.Declined {
		declined[decline.Rule] = true
	}
	for i, r := range rules {
		if declined[i] {
			continue // a declined ban rule installs nothing, keeping its input index
		}
		if err := addBanRule(conn, table, ingress, egress, i, r); err != nil {
			return firewall.Outcome{}, fmt.Errorf("apply: ban rule %d: %w", i, err)
		}
	}
	if err := conn.Flush(); err != nil {
		return firewall.Outcome{}, fmt.Errorf("apply: %w", err)
	}
	d.hash, d.installed = plan.Hash, true
	return firewall.Outcome{Hash: plan.Hash, Hits: hits, Declined: plan.Declined}, nil
}

// ruleHits reads the owned table's per-rule counters back, one hit per
// ban rule: every kernel rule carries its counter immediately before
// its verdict (addBanRule) and its ban rule's index in its set names,
// so every reading maps onto the ban rule it counts — the index in the
// ruleset being replaced. Only the nonzero readings come back: they
// are the hits worth logging.
func ruleHits(conn kernelConn, table *nftables.Table) ([]firewall.Hit, error) {
	byRule := map[int]firewall.Hit{}
	for _, name := range []string{ingressName, egressName} {
		chain, err := conn.ListChain(table, name)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue // the chain is gone with the table
			}
			return nil, err
		}
		krules, err := conn.GetRules(table, chain)
		if err != nil {
			return nil, err
		}
		for _, r := range krules {
			c, ok := ruleCounter(r)
			if !ok || (c.Packets == 0 && c.Bytes == 0) {
				continue
			}
			i, ok := ruleIndex(r)
			if !ok {
				continue // not a kernel rule this driver wrote
			}
			h := byRule[i]
			byRule[i] = firewall.Hit{Rule: i, Packets: h.Packets + c.Packets, Bytes: h.Bytes + c.Bytes}
		}
	}
	hits := make([]firewall.Hit, 0, len(byRule))
	for _, h := range byRule {
		hits = append(hits, h)
	}
	slices.SortFunc(hits, func(a, b firewall.Hit) int { return a.Rule - b.Rule })
	return hits, nil
}

// ruleCounter is a kernel rule's packet/byte counter (every ban rule
// carries one immediately before its verdict), or false when the rule
// carries none. It is found by shape rather than a fixed index: the
// match exprs in front of it vary with the rule's prefilter.
func ruleCounter(r *nftables.Rule) (*expr.Counter, bool) {
	for _, e := range r.Exprs {
		if c, ok := e.(*expr.Counter); ok {
			return c, true
		}
	}
	return nil, false
}

// ruleIndex maps a kernel rule back onto its ban rule: the ban rule's
// index is baked into its set names (v4_3, port_3, … — the names
// addBanRule builds them with), so the mapping survives restarts.
func ruleIndex(r *nftables.Rule) (int, bool) {
	for _, e := range r.Exprs {
		l, ok := e.(*expr.Lookup)
		if !ok {
			continue
		}
		if i, err := strconv.Atoi(l.SetName[strings.LastIndex(l.SetName, "_")+1:]); err == nil {
			return i, true
		}
	}
	return 0, false
}

// Reset removes the owned table with everything in it, tolerating the
// table being already absent, and ends the skip state: after a reset
// the same ruleset installs again.
func (d *Driver) Reset() error {
	conn, closer, err := d.open()
	if err != nil {
		return fmt.Errorf("reset: %w", err)
	}
	if closer != nil {
		// The handle stays open through Flush (see openNetlink).
		defer closer.Close()
	}
	conn.DelTable(ownedTable())
	if err := conn.Flush(); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("reset: %w", err)
	}
	d.installed = false
	return nil
}

// ingress is the ingress base chain at the configured hook: filter
// priority at input, fluxc's raw priority at prerouting so bans run
// before conntrack.
func (d *Driver) ingress(table *nftables.Table) *nftables.Chain {
	c := &nftables.Chain{
		Name:  ingressName,
		Table: table,
		Type:  nftables.ChainTypeFilter,
	}
	switch d.hook {
	case HookPrerouting:
		c.Hooknum, c.Priority = nftables.ChainHookPrerouting, nftables.ChainPriorityRaw
	default:
		c.Hooknum, c.Priority = nftables.ChainHookInput, nftables.ChainPriorityFilter
	}
	return c
}

// egress is the egress base chain carrying the bandwidth limits:
// filter priority at output in input mode (locally generated
// responses) and at forward in prerouting mode (transit responses) —
// the response direction the limits' unit names.
func (d *Driver) egress(table *nftables.Table) *nftables.Chain {
	c := &nftables.Chain{
		Name:  egressName,
		Table: table,
		Type:  nftables.ChainTypeFilter,
	}
	switch d.hook {
	case HookPrerouting:
		c.Hooknum, c.Priority = nftables.ChainHookForward, nftables.ChainPriorityFilter
	default:
		c.Hooknum, c.Priority = nftables.ChainHookOutput, nftables.ChainPriorityFilter
	}
	return c
}

// addrFamily is one address family a ban rule can cover; the source
// and destination offsets are fluxc's (IPv4 source at network-header
// offset 12 and destination at 16, IPv6 source at 8 and destination at
// 24). srcLen is the address length both loads share.
type addrFamily struct {
	name    string
	proto   byte
	keyType nftables.SetDatatype
	srcOff  uint32
	srcLen  uint32
	dstOff  uint32
	is      func(netip.Prefix) bool
	setName func(i int) string
	// dstSetName names the family's destination-address prefilter set.
	dstSetName func(i int) string
}

// The two families an inet table covers. Set names are the ban rule's
// target prefixes per family and index (fluxc's naming); the
// destination-address prefilter sets follow the same shape.
var families = []addrFamily{
	{
		name:       "v4",
		proto:      unix.NFPROTO_IPV4,
		keyType:    nftables.TypeIPAddr,
		srcOff:     12,
		srcLen:     4,
		dstOff:     16,
		is:         func(p netip.Prefix) bool { return p.Addr().Is4() },
		setName:    func(i int) string { return fmt.Sprintf("v4_%d", i) },
		dstSetName: func(i int) string { return fmt.Sprintf("dp4_%d", i) },
	},
	{
		name:       "v6",
		proto:      unix.NFPROTO_IPV6,
		keyType:    nftables.TypeIP6Addr,
		srcOff:     8,
		srcLen:     16,
		dstOff:     24,
		is:         func(p netip.Prefix) bool { return !p.Addr().Is4() },
		setName:    func(i int) string { return fmt.Sprintf("v6_%d", i) },
		dstSetName: func(i int) string { return fmt.Sprintf("dp6_%d", i) },
	},
}

// The destination-port prefilter's own sets, per rule index: the l4
// gate (tcp and udp — the transports whose packets carry ports) and
// the port set itself. Family-independent, so both families' rules
// share them.
var (
	l4SetName   = func(i int) string { return fmt.Sprintf("l4_%d", i) }
	portSetName = func(i int) string { return fmt.Sprintf("port_%d", i) }
)

// familyRule is one ban rule's per-family slice: the family and the
// target and destination-address prefixes it installs there.
type familyRule struct {
	family   addrFamily
	targets  []netip.Prefix
	dstAddrs []netip.Prefix
}

// ruleFamilies splits one ban rule per address family the service
// prefilter can reach: a family with no target prefix is out, and when
// the operator configured destination addresses and none is in the
// family, nothing there is service traffic and the family is out too
// — it gets no kernel rule at all. All families out means the ban rule
// installs nothing — the drop the planning step folds away.
func ruleFamilies(r firewall.BanRule) []familyRule {
	var fams []familyRule
	for _, fam := range families {
		targets := familyPrefixes(r.Targets, fam)
		if len(targets) == 0 {
			continue
		}
		dstAddrs := familyPrefixes(r.Prefilter.DstAddrs, fam)
		if len(r.Prefilter.DstAddrs) > 0 && len(dstAddrs) == 0 {
			continue
		}
		fams = append(fams, familyRule{fam, targets, dstAddrs})
	}
	return fams
}

// addBanRule buffers one ban rule's sets and kernel rules: every
// address family the service prefilter can reach gets one interval set
// of the rule's Target prefixes and one kernel rule that leads with the
// service prefilter — the destination-port set first, then the
// destination-address set, either empty meaning all — before the
// target match, the packet/byte counter and the stance's verdict. The
// direction split of the penalty mapping: bandwidth meters the response direction on the
// egress chain, matched on destination ∈ Target; every other stance
// matches source on the ingress chain.
func addBanRule(conn kernelConn, table *nftables.Table, ingress, egress *nftables.Chain, i int, r firewall.BanRule) error {
	verdict, err := verdictExprs(r)
	if err != nil {
		return err
	}
	// The direction split of the penalty mapping (directionOf):
	// bandwidth meters the response direction on the egress chain,
	// matched on destination ∈ Target; every other stance matches
	// source on the ingress chain.
	_, matchDst, err := directionOf(r.Stance)
	if err != nil {
		return err
	}
	chain, matchOff := ingress, func(f addrFamily) uint32 { return f.srcOff }
	if matchDst {
		chain, matchOff = egress, func(f addrFamily) uint32 { return f.dstOff }
	}
	familyRules := ruleFamilies(r)
	if len(familyRules) == 0 {
		return nil
	}
	// The destination-port prefilter is family-independent: its sets
	// are built once per rule and lead every family's kernel rule.
	var portExprs []expr.Any
	if len(r.Prefilter.DstPorts) > 0 {
		if err := conn.AddSet(&nftables.Set{
			Table:   table,
			KeyType: nftables.TypeInetProto,
			Name:    l4SetName(i),
		}, l4Elements); err != nil {
			return err
		}
		if err := conn.AddSet(&nftables.Set{
			Table:   table,
			KeyType: nftables.TypeInetService,
			Name:    portSetName(i),
		}, portElements(r.Prefilter.DstPorts)); err != nil {
			return err
		}
		// Ports are transport-header bytes: gate on tcp and udp so no
		// other protocol's header bytes can match the port set by
		// accident — a ban reaches service traffic only.
		portExprs = []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Lookup{SourceRegister: 1, SetName: l4SetName(i)},
			&expr.Payload{DestRegister: 1, OperationType: expr.PayloadLoad,
				Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Lookup{SourceRegister: 1, SetName: portSetName(i)},
		}
	}
	for _, f := range familyRules {
		fam := f.family
		if err := conn.AddSet(&nftables.Set{
			Table:    table,
			KeyType:  fam.keyType,
			Name:     fam.setName(i),
			Interval: true,
		}, intervalElements(f.targets)); err != nil {
			return err
		}
		exprs := []expr.Any{
			// The family gate leads: only this family's packets can
			// reach the rule's matches at all.
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{fam.proto}},
		}
		exprs = append(exprs, portExprs...)
		if len(f.dstAddrs) > 0 {
			if err := conn.AddSet(&nftables.Set{
				Table:    table,
				KeyType:  fam.keyType,
				Name:     fam.dstSetName(i),
				Interval: true,
			}, intervalElements(f.dstAddrs)); err != nil {
				return err
			}
			exprs = append(exprs,
				&expr.Payload{DestRegister: 1, OperationType: expr.PayloadLoad,
					Base: expr.PayloadBaseNetworkHeader, Offset: fam.dstOff, Len: fam.srcLen},
				&expr.Lookup{SourceRegister: 1, SetName: fam.dstSetName(i)},
			)
		}
		exprs = append(exprs,
			&expr.Payload{DestRegister: 1, OperationType: expr.PayloadLoad,
				Base: expr.PayloadBaseNetworkHeader, Offset: matchOff(fam), Len: fam.srcLen},
			&expr.Lookup{SourceRegister: 1, SetName: fam.setName(i)},
			// The counter comes after every match expr and immediately
			// before the verdict: it counts only the packets this ban
			// rule matches, so its nonzero readings are the hits worth
			// logging at the next install.
			&expr.Counter{},
		)
		exprs = append(exprs, verdict...)
		conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: exprs,
		})
	}
	return nil
}

// familyPrefixes returns the prefixes of one address family.
func familyPrefixes(prefixes []netip.Prefix, fam addrFamily) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range prefixes {
		if fam.is(p) {
			out = append(out, p)
		}
	}
	return out
}

// l4Elements is the l4proto gate of the port prefilter: tcp and udp,
// the transports whose packets carry a destination port.
var l4Elements = []nftables.SetElement{
	{Key: []byte{unix.IPPROTO_TCP}},
	{Key: []byte{unix.IPPROTO_UDP}},
}

// portElements encodes destination ports as a service set's exact
// keys: two-byte big-endian port numbers, the transport header's own
// byte order.
func portElements(ports []uint16) []nftables.SetElement {
	elems := make([]nftables.SetElement, 0, len(ports))
	for _, p := range ports {
		elems = append(elems, nftables.SetElement{Key: []byte{byte(p >> 8), byte(p)}})
	}
	return elems
}

// verdictExprs maps a ban rule's stance onto its verdict expressions
// — the stance switch of the contract's penalty mapping (unknown
// stances error loudly). Reject is the inet family's icmpx
// admin-prohibited: TCP peers get a reset automatically. A rate meter
// matches only once its rate is exceeded (the nft "limit rate over …"
// flag), so the drop applies to the excess while in-rate traffic falls
// through to the next rule; its burst is one second's worth of the
// rate, floored (burstFor). The kernel accepts reject at prerouting
// only from ~5.9 — older kernels refuse the batch, the documented
// floor for --hook prerouting (ticket 09 documents it).
func verdictExprs(r firewall.BanRule) ([]expr.Any, error) {
	switch r.Stance {
	case firewall.StanceDrop:
		return []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}, nil
	case firewall.StanceReject:
		return []expr.Any{&expr.Reject{
			Type: unix.NFT_REJECT_ICMPX_UNREACH,
			Code: unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED,
		}}, nil
	case firewall.StanceLimitPktRate, firewall.StanceLimitBandwidth:
		if err := checkRate(r); err != nil {
			return nil, err
		}
		limitType := expr.LimitTypePkts
		if r.Stance == firewall.StanceLimitBandwidth {
			limitType = expr.LimitTypePktBytes
		}
		return []expr.Any{
			&expr.Limit{
				Type:  limitType,
				Rate:  uint64(*r.Rate),
				Over:  true,
				Unit:  expr.LimitTimeSecond,
				Burst: burstFor(*r.Rate),
			},
			&expr.Verdict{Kind: expr.VerdictDrop},
		}, nil
	default:
		return nil, fmt.Errorf("stance %q: not supported", r.Stance)
	}
}

// burstFor derives a rate meter's burst: one second's worth of the
// rate (Rate per second × 1s), floored to the kernel's 32-bit burst
// field. The spec derives the burst — there is no burst flag in v0:
// nft's tiny default burst would drop legitimate micro-bursts.
func burstFor(rate int64) uint32 {
	if rate > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(rate) // rate >= 1 where the compiler emits it
}

// intervalElements encodes masked Target prefixes as an interval set's
// element pairs (fluxc's encoding): every range starts at its base
// address and ends at the first address after it, flagged IntervalEnd
// — the kernel matches [start, end). A range that reaches the top of
// the address space has no representable end there, so it gets the
// kernel's null end (the all-zero key): [start, top].
func intervalElements(prefixes []netip.Prefix) []nftables.SetElement {
	var elems []nftables.SetElement
	for _, p := range prefixes {
		p = p.Masked()
		start := p.Addr().AsSlice()
		end := prefixEnd(p)
		if end == nil {
			end = make([]byte, len(start)) // the null end
		}
		elems = append(elems,
			nftables.SetElement{Key: start},
			nftables.SetElement{Key: end, IntervalEnd: true},
		)
	}
	return elems
}

// prefixEnd returns the first address after p's range as raw key
// bytes, or nil when the range reaches the top of the address space
// (no representable end; the caller uses the null end).
func prefixEnd(p netip.Prefix) []byte {
	start := p.Addr().AsSlice()
	end := make([]byte, len(start))
	bits := p.Bits()
	for i := range end {
		// Set every host bit of the base address: the last address of
		// the range. kept is how many leading bits of this byte the
		// prefix keeps.
		kept := min(max(bits-8*i, 0), 8)
		end[i] = start[i] | byte(0xff>>kept)
	}
	for i := len(end) - 1; i >= 0; i-- {
		end[i]++
		if end[i] != 0 {
			return end
		}
	}
	return nil // carried past the top of the address space
}
