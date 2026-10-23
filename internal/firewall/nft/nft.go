// Package nft is splint's nftables firewall driver: it enforces the
// firewall seam's ban rules through netlink
// (github.com/google/nftables) — one wholly-owned inet table named
// splint in the target namespace, rebuilt wholesale in a single
// atomic batch per apply (no delete-then-rebuild window), removed on
// reset. It applies each Penalty exactly as stated or declines it:
// limit-req-rate is application-layer intent and is never faked at
// the packet layer (ADR 0012).
//
// The driver owns its identity: the rolling hash over its effective
// rules, the skip-if-unchanged decision with its existence probe and
// the counter read-back live here.
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

// The wholly-owned nftables objects. The chain names are the
// placement labels the plan reports (the --dry-run mapping lines
// name these chains).
const (
	tableName   = "splint"
	ingressName = "ingress"
	egressName  = "egress"
)

// Hook is the enforcement hook the ingress chain attaches to: input
// catches locally-destined traffic, prerouting catches transit and
// local traffic.
type Hook string

// The two enforcement hooks (--hook).
const (
	HookInput      Hook = "input"
	HookPrerouting Hook = "prerouting"
)

func ParseHook(s string) (Hook, error) {
	h := Hook(s)
	if !h.valid() {
		return "", fmt.Errorf("hook: must be input or prerouting (got %q)", s)
	}
	return h, nil
}

func (h Hook) valid() bool {
	return h == HookInput || h == HookPrerouting
}

// Driver is the nftables implementation of the firewall.Driver port:
// one wholly-owned table per target namespace plus its identity —
// plan is pure, apply rebuilds the table in one atomic batch
// (skipping when the hash matches and the table exists), reset
// removes it. One Driver targets one namespace: netns is its nsfs
// handle path, "" the current namespace.
type Driver struct {
	hook      Hook
	prefilter Prefilter
	netns     string

	// open dials the target namespace's netlink surface: openNetlink in
	// production, the fake kernel in tests.
	open func() (kernelConn, io.Closer, error)

	// Skip-if-unchanged state: the hash last applied here; installed
	// marks a succeeded apply (the zero hash is a legal hash).
	hash      uint32
	installed bool
}

var _ firewall.Driver = (*Driver)(nil)

// Prefilter is this driver's enforcement scope: a ban reaches only
// traffic whose destination port is in DstPorts and whose destination
// address is in DstAddrs. Either set may be empty, meaning all
// (--nft-service-port, --nft-service-address). Scope is driver
// configuration, folded into the ruleset hash (ADR 0012), so
// changing it re-enforces.
type Prefilter struct {
	DstPorts []uint16
	DstAddrs []netip.Prefix
}

// Config is one enforcement point's configuration: hook, enforcement
// scope, and target namespace nsfs handle path ("" is the current
// namespace).
type Config struct {
	Hook      Hook
	Prefilter Prefilter
	NetNSPath string
}

// kernelConn is the netlink surface the driver flushes through:
// *nftables.Conn in production, the fake kernel in tests.
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

// New builds a driver for one enforcement point: one target
// namespace, one enforcement hook, one enforcement scope. The nsfs
// handle is re-opened on every apply/reset so a recreated container
// is picked up through its stable handle.
func New(cfg Config) (*Driver, error) {
	if !cfg.Hook.valid() {
		return nil, fmt.Errorf("hook: must be input or prerouting (got %q)", cfg.Hook)
	}
	d := &Driver{hook: cfg.Hook, prefilter: cfg.Prefilter, netns: cfg.NetNSPath}
	d.open = d.openNetlink
	return d, nil
}

// openNetlink dials netlink to this driver's target namespace (the
// current one for an empty path) through the library's namespace-fd
// option — no setns. The nsfs handle stays open until Flush returns:
// the library dials lazily at flush time and the handle is what
// keeps the namespace alive meanwhile. An unopenable handle is a
// vanished namespace: it wraps firewall.ErrUnreachable.
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

func ownedTable() *nftables.Table {
	return &nftables.Table{Family: nftables.TableFamilyINet, Name: tableName}
}

// tableExists probes for the owned table: a delete of a missing
// table aborts the whole batch with ENOENT, so only a present
// table's delete may join the batch.
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
// the effective rules (the ban rules it can honour, narrowed to the
// target prefixes that reach their address families), their
// placement labels (a change of --hook is a change of effective
// rules), the ruleset hash, and the declines with reasons. --dry-run
// prints exactly this. A ban rule neither honourable nor declinable
// refuses the plan loudly.
func (d *Driver) Plan(rules []firewall.BanRule) (firewall.Plan, error) {
	plan := firewall.Plan{}
	for i, r := range rules {
		if r.Stance == firewall.StanceLimitReqRate {
			// limit-req-rate is application-layer intent the packet layer
			// cannot count: declined, never faked as a meter (ADR 0012).
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
		fams := d.ruleFamilies(r)
		if len(fams) == 0 {
			continue // the configured enforcement scope cannot reach it: it installs nothing
		}
		effective := r
		effective.Targets = nil
		for _, f := range fams {
			effective.Targets = append(effective.Targets, f.targets...)
		}
		plan.Rules = append(plan.Rules, firewall.PlannedRule{BanRule: effective, Placement: placement})
	}
	plan.Hash = d.hashEffective(plan.Rules)
	return plan, nil
}

// hashEffective folds the effective rules into the ruleset hash:
// targets, the enforcement scope matched under (so changing it
// re-enforces), stance, rate, placement label.
func (d *Driver) hashEffective(rules []firewall.PlannedRule) uint32 {
	h := firewall.NewHasher()
	for _, r := range rules {
		fields := make([][]byte, 0, len(r.Targets)+len(d.prefilter.DstPorts)+len(d.prefilter.DstAddrs)+3)
		for _, t := range r.Targets {
			fields = append(fields, firewall.PrefixField(t))
		}
		for _, p := range d.prefilter.DstPorts {
			fields = append(fields, firewall.Uint16Field(p))
		}
		for _, a := range d.prefilter.DstAddrs {
			fields = append(fields, firewall.PrefixField(a))
		}
		fields = append(fields, firewall.StringField(string(r.Stance)))
		if r.Rate != nil {
			fields = append(fields, firewall.Uint64Field(uint64(*r.Rate)))
		}
		fields = append(fields, firewall.StringField(r.Placement))
		h.Step(fields...)
	}
	return h.Sum()
}

// placement reports the ban rule's placement label — the chain it
// installs in at the hook that chain attaches to.
func (d *Driver) placement(s firewall.Stance) (string, error) {
	name, matchDst, err := directionOf(s)
	if err != nil {
		return "", err
	}
	hook := string(d.hook) // the ingress chain attaches at the configured hook
	if matchDst {
		// The egress chain meters the response direction: output in
		// input mode (local responses), forward in prerouting mode.
		hook = "output"
		if d.hook == HookPrerouting {
			hook = "forward"
		}
	}
	return name + "@" + hook, nil
}

// directionOf reports the chain a stance installs in and where its
// target match looks: source on ingress, destination on egress for
// the bandwidth meter (the response direction its unit names).
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
// can honour exactly as stated — the driver never tunes a stated
// rate.
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
// skips when the plan's hash matches the ruleset it last applied and
// the owned table still exists (probed fresh every apply) — and
// reports the hash, the replaced rules' nonzero counters (the hits
// since the last change), and the declines. The table is never
// absent while the new one applies. A declined ban rule keeps its
// input index (the counter read-back indexes the replaced ruleset)
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
	// Known limit: existence only — tampering under a surviving table
	// is undetected. Fresh every apply — an unchanged ruleset must not
	// hide behind a vanished table.
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
		if err := d.addBanRule(conn, table, ingress, egress, i, r); err != nil {
			return firewall.Outcome{}, fmt.Errorf("apply: ban rule %d: %w", i, err)
		}
	}
	if err := conn.Flush(); err != nil {
		return firewall.Outcome{}, fmt.Errorf("apply: %w", err)
	}
	d.hash, d.installed = plan.Hash, true
	return firewall.Outcome{Hash: plan.Hash, Hits: hits, Declined: plan.Declined}, nil
}

// ruleHits reads the owned table's per-rule counters back, one hit
// per ban rule: the counter position and the set-name index map each
// reading onto the ban rule it counts — the ruleset being replaced.
// Only nonzero readings come back.
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

// ruleCounter is a kernel rule's packet/byte counter, or false when
// it carries none. Found by shape, not index: the match exprs in
// front vary with the rule's prefilter.
func ruleCounter(r *nftables.Rule) (*expr.Counter, bool) {
	for _, e := range r.Exprs {
		if c, ok := e.(*expr.Counter); ok {
			return c, true
		}
	}
	return nil, false
}

// ruleIndex maps a kernel rule back onto its ban rule: the index is
// baked into its set names (v4_3, port_3, …), so the mapping
// survives restarts.
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
// priority at input, raw priority at prerouting so bans run before
// conntrack.
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

// egress is the egress base chain carrying the bandwidth limits, at
// the response direction they meter: output in input mode (local
// responses), forward in prerouting mode (transit responses).
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

// addrFamily is one address family a ban rule can cover; srcOff and
// dstOff are the network-header offsets of its addresses, srcLen the
// address length both loads share.
type addrFamily struct {
	name       string
	proto      byte
	keyType    nftables.SetDatatype
	srcOff     uint32
	srcLen     uint32
	dstOff     uint32
	is         func(netip.Prefix) bool
	setName    func(i int) string
	dstSetName func(i int) string
}

// The two families an inet table covers. Set names carry the ban
// rule's index (parsed back by ruleIndex).
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

// The destination-port prefilter's sets, per rule index: the l4 gate
// and the port set. Family-independent — both families share them.
var (
	l4SetName   = func(i int) string { return fmt.Sprintf("l4_%d", i) }
	portSetName = func(i int) string { return fmt.Sprintf("port_%d", i) }
)

type familyRule struct {
	family   addrFamily
	targets  []netip.Prefix
	dstAddrs []netip.Prefix
}

// ruleFamilies splits one ban rule per address family the configured
// scope can reach: a family with no target prefix is out, as is one
// where configured destination addresses match none (no service
// traffic lives there). All out means the ban rule installs nothing.
func (d *Driver) ruleFamilies(r firewall.BanRule) []familyRule {
	var fams []familyRule
	for _, fam := range families {
		targets := familyPrefixes(r.Targets, fam)
		if len(targets) == 0 {
			continue
		}
		dstAddrs := familyPrefixes(d.prefilter.DstAddrs, fam)
		if len(d.prefilter.DstAddrs) > 0 && len(dstAddrs) == 0 {
			continue
		}
		fams = append(fams, familyRule{fam, targets, dstAddrs})
	}
	return fams
}

// addBanRule buffers one ban rule's sets and kernel rules: one
// interval set of the Target prefixes and one kernel rule per
// reachable family, leading with the enforcement scope (port set,
// then destination-address set, either empty meaning all), then the
// target match, the counter and the stance's verdict.
func (d *Driver) addBanRule(conn kernelConn, table *nftables.Table, ingress, egress *nftables.Chain, i int, r firewall.BanRule) error {
	verdict, err := verdictExprs(r)
	if err != nil {
		return err
	}
	_, matchDst, err := directionOf(r.Stance)
	if err != nil {
		return err
	}
	chain, matchOff := ingress, func(f addrFamily) uint32 { return f.srcOff }
	if matchDst {
		chain, matchOff = egress, func(f addrFamily) uint32 { return f.dstOff }
	}
	familyRules := d.ruleFamilies(r)
	if len(familyRules) == 0 {
		return nil
	}
	// The destination-port prefilter is family-independent: its sets
	// are built once per rule and lead every family's kernel rule.
	var portExprs []expr.Any
	if len(d.prefilter.DstPorts) > 0 {
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
		}, portElements(d.prefilter.DstPorts)); err != nil {
			return err
		}
		// Ports are transport-header bytes: the tcp/udp gate keeps
		// other protocols' header bytes from matching by accident.
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
			// The counter sits after every match and immediately before
			// the verdict, so it counts only the ban rule's own hits.
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

func familyPrefixes(prefixes []netip.Prefix, fam addrFamily) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range prefixes {
		if fam.is(p) {
			out = append(out, p)
		}
	}
	return out
}

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

// verdictExprs maps a stance onto its verdict expressions (unknown
// stances error loudly). Reject is icmpx admin-prohibited: TCP peers
// get a reset automatically. The rate meter's Over flag drops only
// the traffic past the rate. Reject at prerouting needs kernel ~5.9 —
// older kernels refuse the batch, the documented floor for --hook
// prerouting.
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
// rate, floored to the kernel's 32-bit field. nft's tiny default
// burst would drop legitimate micro-bursts.
func burstFor(rate int64) uint32 {
	if rate > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(rate) // rate >= 1 where the compiler emits it
}

// intervalElements encodes masked Target prefixes as an interval
// set's element pairs: [start, end), end flagged IntervalEnd and
// holding the first address after the range. A range reaching the top
// of the address space has no representable end, so it gets the
// kernel's null end: [start, top].
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
// bytes, or nil when the range reaches the top of the address space.
func prefixEnd(p netip.Prefix) []byte {
	start := p.Addr().AsSlice()
	end := make([]byte, len(start))
	bits := p.Bits()
	for i := range end {
		// Set the byte's host bits: end holds the range's last address.
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
