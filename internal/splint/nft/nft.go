// Package nft installs splint's ban rules through netlink
// (github.com/google/nftables): one wholly-owned inet table named
// splint in the target namespace, rebuilt wholesale in a single
// atomic batch per install (fluxc's delete-then-rebuild gap is
// deliberately not copied), removed on reset.
package nft

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/HT4w5/bandage/internal/splint"
)

// The wholly-owned nftables objects: one inet table per target
// namespace, carrying the ingress chain at the configured hook and the
// egress chain behind the bandwidth limits. The chain names are the
// ones splint.Stance.Chain() reports (the --dry-run mapping lines name
// these chains).
const (
	tableName   = "splint"
	ingressName = string(splint.ChainIngress)
	egressName  = string(splint.ChainEgress)
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

// Driver is the nftables implementation of the splint.Driver port.
// It owns nothing but one table per target namespace: Install
// rebuilds that table wholesale, Reset removes it.
type Driver struct {
	hook Hook
}

var _ splint.Driver = (*Driver)(nil)

// New builds a driver whose ingress chain attaches at hook.
func New(hook Hook) (*Driver, error) {
	if !hook.valid() {
		return nil, fmt.Errorf("hook: must be input or prerouting (got %q)", hook)
	}
	return &Driver{hook: hook}, nil
}

// connect opens the netlink connection to the target namespace — the
// current one for now. Ticket 07 reopens a per-namespace connection
// here every cycle.
func connect() (*nftables.Conn, error) {
	return nftables.New()
}

// ownedTable is the wholly-owned table both Install and Reset address.
func ownedTable() *nftables.Table {
	return &nftables.Table{Family: nftables.TableFamilyINet, Name: tableName}
}

// tableExists probes for the owned table: a cheap existence check the
// rebuild consults before batching its delete (a delete of a missing
// table aborts the whole batch with ENOENT). Ticket 06's
// skip-if-unchanged reuses the same probe.
func tableExists(conn *nftables.Conn, table *nftables.Table) (bool, error) {
	if _, err := conn.ListTableOfFamily(table.Name, table.Family); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Install rebuilds the owned table wholesale in one atomic batch:
// a probe decides whether the delete joins the batch, then the table,
// both chains and one lookup rule per ban rule and address family are
// buffered and flushed together. The table is
// never absent while the new one applies — there is no
// delete-then-rebuild window.
func (d *Driver) Install(rules []splint.BanRule) error {
	conn, err := connect()
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	table := ownedTable()
	exists, err := tableExists(conn, table)
	if err != nil {
		return fmt.Errorf("install: probe owned table: %w", err)
	}
	if exists {
		// Only a present table may join the batch: deleting a missing
		// one aborts the whole transaction with ENOENT.
		conn.DelTable(table)
	}
	table = conn.AddTable(table)
	ingress := conn.AddChain(d.ingress(table))
	egress := conn.AddChain(d.egress(table))
	for i, r := range rules {
		if err := addBanRule(conn, table, ingress, egress, i, r); err != nil {
			return fmt.Errorf("install: ban rule %d: %w", i, err)
		}
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	return nil
}

// Reset removes the owned table with everything in it, tolerating the
// table being already absent.
func (d *Driver) Reset() error {
	conn, err := connect()
	if err != nil {
		return fmt.Errorf("reset: %w", err)
	}
	conn.DelTable(ownedTable())
	if err := conn.Flush(); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("reset: %w", err)
	}
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
}

// The two families an inet table covers. Set names are the ban rule's
// target prefixes per family and index (fluxc's naming).
var families = []addrFamily{
	{
		name:    "v4",
		proto:   unix.NFPROTO_IPV4,
		keyType: nftables.TypeIPAddr,
		srcOff:  12,
		srcLen:  4,
		dstOff:  16,
		is:      func(p netip.Prefix) bool { return p.Addr().Is4() },
		setName: func(i int) string { return fmt.Sprintf("v4_%d", i) },
	},
	{
		name:    "v6",
		proto:   unix.NFPROTO_IPV6,
		keyType: nftables.TypeIP6Addr,
		srcOff:  8,
		srcLen:  16,
		dstOff:  24,
		is:      func(p netip.Prefix) bool { return !p.Addr().Is4() },
		setName: func(i int) string { return fmt.Sprintf("v6_%d", i) },
	},
}

// addBanRule buffers one ban rule's sets and kernel rules: every
// address family with targets gets one interval set of the rule's
// Target prefixes and one rule matching source ∈ set before the
// stance's verdict — except the bandwidth stance, which meters the
// response direction: its rules live on the egress chain matched on
// destination ∈ set. (Ticket 03 guards these matches with the service
// prefilter.)
func addBanRule(conn *nftables.Conn, table *nftables.Table, ingress, egress *nftables.Chain, i int, r splint.BanRule) error {
	verdict, err := verdictExprs(r)
	if err != nil {
		return err
	}
	// The direction split of the penalty mapping: bandwidth meters the
	// response direction on the egress chain, matched on destination ∈
	// Target; every other stance matches source on the ingress chain.
	chain, matchOff := ingress, func(f addrFamily) uint32 { return f.srcOff }
	switch r.Stance.Chain() {
	case splint.ChainIngress:
	case splint.ChainEgress:
		chain, matchOff = egress, func(f addrFamily) uint32 { return f.dstOff }
	default:
		return fmt.Errorf("stance %q: not supported", r.Stance)
	}
	for _, fam := range families {
		var prefixes []netip.Prefix
		for _, p := range r.Targets {
			if fam.is(p) {
				prefixes = append(prefixes, p)
			}
		}
		if len(prefixes) == 0 {
			continue
		}
		name := fam.setName(i)
		if err := conn.AddSet(&nftables.Set{
			Table:    table,
			KeyType:  fam.keyType,
			Name:     name,
			Interval: true,
		}, intervalElements(prefixes)); err != nil {
			return err
		}
		conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: append([]expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{fam.proto}},
				&expr.Payload{DestRegister: 1, OperationType: expr.PayloadLoad,
					Base: expr.PayloadBaseNetworkHeader, Offset: matchOff(fam), Len: fam.srcLen},
				&expr.Lookup{SourceRegister: 1, SetName: name},
			}, verdict...),
		})
	}
	return nil
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
func verdictExprs(r splint.BanRule) ([]expr.Any, error) {
	switch r.Stance {
	case splint.StanceDrop:
		return []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}, nil
	case splint.StanceReject:
		return []expr.Any{&expr.Reject{
			Type: unix.NFT_REJECT_ICMPX_UNREACH,
			Code: unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED,
		}}, nil
	case splint.StanceLimitPktRate, splint.StanceLimitBandwidth:
		if r.Rate == nil {
			return nil, fmt.Errorf("stance %q: rate required", r.Stance)
		}
		if *r.Rate < 1 {
			return nil, fmt.Errorf("stance %q: rate must be at least 1 (got %d)", r.Stance, *r.Rate)
		}
		limitType := expr.LimitTypePkts
		if r.Stance == splint.StanceLimitBandwidth {
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
