package nft

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"github.com/HT4w5/bandage/internal/firewall"
)

// The fake kernel replaces the real netlink path in these tests,
// never layers over it; the netlink encoding itself is verified only
// by the root-gated kernel test.

// fakeKernel is an in-memory kernel stand-in: batches apply to its
// own table state at Flush; read-backs serve what it recorded.
type fakeKernel struct {
	mu           sync.Mutex
	table        *nftables.Table             // the owned table while present
	chains       map[string][]*nftables.Rule // flushed kernel rules per chain name
	probes       int                         // existence probes served
	flushes      [][]kernelOp                // one entry per flushed batch
	batch        []kernelOp                  // the batch being buffered
	pendingRules []*nftables.Rule            // the batch's rules, flushed together
}

// kernelOp records one batch operation — the shape flushed, never
// its encoding.
type kernelOp struct {
	kind  string // del-table, add-table, add-chain, add-set or add-rule
	chain string // the chain name of add-chain and add-rule
}

func newFakeKernel() *fakeKernel {
	return &fakeKernel{chains: map[string][]*nftables.Rule{}}
}

// dial is the driver's open hook onto this kernel.
func (k *fakeKernel) dial() (kernelConn, io.Closer, error) {
	return k, nil, nil
}

func (k *fakeKernel) AddTable(t *nftables.Table) *nftables.Table {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.batch = append(k.batch, kernelOp{kind: "add-table"})
	return t
}

func (k *fakeKernel) AddChain(c *nftables.Chain) *nftables.Chain {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.batch = append(k.batch, kernelOp{kind: "add-chain", chain: c.Name})
	return c
}

func (k *fakeKernel) AddSet(s *nftables.Set, vals []nftables.SetElement) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.batch = append(k.batch, kernelOp{kind: "add-set"})
	return nil
}

func (k *fakeKernel) AddRule(r *nftables.Rule) *nftables.Rule {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.batch = append(k.batch, kernelOp{kind: "add-rule", chain: r.Chain.Name})
	k.pendingRules = append(k.pendingRules, r)
	return r
}

func (k *fakeKernel) DelTable(t *nftables.Table) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.batch = append(k.batch, kernelOp{kind: "del-table"})
}

// Flush applies the buffered batch to the fake kernel's state and
// records it — the same atomicity as the real flush: all at once or
// not at all.
func (k *fakeKernel) Flush() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, op := range k.batch {
		switch op.kind {
		case "del-table":
			k.table = nil
			k.chains = map[string][]*nftables.Rule{}
		case "add-table":
			k.table = &nftables.Table{Family: nftables.TableFamilyINet, Name: tableName}
		case "add-chain":
			if _, ok := k.chains[op.chain]; !ok {
				k.chains[op.chain] = nil
			}
		}
	}
	for _, r := range k.pendingRules {
		k.chains[r.Chain.Name] = append(k.chains[r.Chain.Name], r)
	}
	k.flushes = append(k.flushes, k.batch)
	k.batch, k.pendingRules = nil, nil
	return nil
}

func (k *fakeKernel) ListTableOfFamily(name string, family nftables.TableFamily) (*nftables.Table, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.probes++
	if k.table == nil || k.table.Name != name || k.table.Family != family {
		return nil, fmt.Errorf("table %s: %w", name, fs.ErrNotExist)
	}
	return k.table, nil
}

func (k *fakeKernel) ListChain(t *nftables.Table, name string) (*nftables.Chain, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.table == nil {
		return nil, fmt.Errorf("chain %s: %w", name, fs.ErrNotExist)
	}
	if _, ok := k.chains[name]; !ok {
		return nil, fmt.Errorf("chain %s: %w", name, fs.ErrNotExist)
	}
	return &nftables.Chain{Name: name, Table: k.table}, nil
}

func (k *fakeKernel) GetRules(t *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.table == nil {
		return nil, fmt.Errorf("rules of %s: %w", c.Name, fs.ErrNotExist)
	}
	return append([]*nftables.Rule(nil), k.chains[c.Name]...), nil
}

// seed installs a counter-read fixture behind the driver's back: the
// owned table with kernel rules already carrying readings, as if a
// previous install had been counting traffic.
func (k *fakeKernel) seed(rules map[string][]*nftables.Rule) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.table = &nftables.Table{Family: nftables.TableFamilyINet, Name: tableName}
	k.chains = map[string][]*nftables.Rule{}
	for chain, rs := range rules {
		k.chains[chain] = rs
	}
}

// vanish removes the owned table behind the driver's back — an
// external reset or a recreated container.
func (k *fakeKernel) vanish() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.table = nil
	k.chains = map[string][]*nftables.Rule{}
}

func (k *fakeKernel) flushCount() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.flushes)
}

func (k *fakeKernel) lastFlush() []kernelOp {
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.flushes) == 0 {
		return nil
	}
	return k.flushes[len(k.flushes)-1]
}

func (k *fakeKernel) rulesIn(chain string) int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.chains[chain])
}

func (k *fakeKernel) probeCount() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.probes
}

// counterRule builds the fixture shape a ban rule's counter read-back
// maps: its set lookup (index baked into the name) and the reading.
func counterRule(setName string, packets, bytes uint64) *nftables.Rule {
	return &nftables.Rule{Exprs: []expr.Any{
		&expr.Lookup{SourceRegister: 1, SetName: setName},
		&expr.Counter{Packets: packets, Bytes: bytes},
	}}
}

// newFakeDriver builds a driver whose enforcement point is the fake
// kernel — the same constructor the command uses, with the netlink
// open swapped for the stand-in.
func newFakeDriver(t *testing.T, hook Hook, kernel *fakeKernel) *Driver {
	t.Helper()
	return newFakeScopedDriver(t, hook, Prefilter{}, kernel)
}

func newFakeScopedDriver(t *testing.T, hook Hook, scope Prefilter, kernel *fakeKernel) *Driver {
	t.Helper()
	d, err := New(Config{Hook: hook, Prefilter: scope})
	if err != nil {
		t.Fatalf("New(%q): %v", hook, err)
	}
	d.open = kernel.dial
	return d
}

func dropFixture(prefixes ...string) firewall.BanRule {
	r := firewall.BanRule{Stance: firewall.StanceDrop}
	for _, p := range prefixes {
		r.Targets = append(r.Targets, netip.MustParsePrefix(p))
	}
	return r
}

func bandwidthFixture(rate int64, prefixes ...string) firewall.BanRule {
	r := dropFixture(prefixes...)
	r.Stance, r.Rate = firewall.StanceLimitBandwidth, &rate
	return r
}

func mustPrefixes(prefixes ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, s := range prefixes {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func reqRateFixture(rate int64, prefixes ...string) firewall.BanRule {
	r := dropFixture(prefixes...)
	r.Stance, r.Rate = firewall.StanceLimitReqRate, &rate
	return r
}

func TestPlanDerivesTheEffectiveRules(t *testing.T) {
	kernel := newFakeKernel()

	t.Run("the stances place at their chains at the configured hook", func(t *testing.T) {
		rules := []firewall.BanRule{
			dropFixture("203.0.113.7/32"),
			{Targets: []netip.Prefix{netip.MustParsePrefix("198.51.100.7/32")}, Stance: firewall.StanceReject},
			{Targets: []netip.Prefix{netip.MustParsePrefix("192.0.2.7/32")}, Stance: firewall.StanceLimitPktRate, Rate: ratePtr(250)},
			bandwidthFixture(1000000, "203.0.113.9/32"),
		}
		want := []firewall.PlannedRule{
			{BanRule: rules[0], Placement: "ingress@input"},
			{BanRule: rules[1], Placement: "ingress@input"},
			{BanRule: rules[2], Placement: "ingress@input"},
			{BanRule: rules[3], Placement: "egress@output"},
		}
		plan, err := newFakeDriver(t, HookInput, kernel).Plan(rules)
		if err != nil {
			t.Fatalf("Plan: %v", err)
		}
		if !reflect.DeepEqual(plan.Rules, want) {
			t.Errorf("effective rules = %+v, want %+v", plan.Rules, want)
		}

		wantPrerouting := []firewall.PlannedRule{
			{BanRule: rules[0], Placement: "ingress@prerouting"},
			{BanRule: rules[1], Placement: "ingress@prerouting"},
			{BanRule: rules[2], Placement: "ingress@prerouting"},
			{BanRule: rules[3], Placement: "egress@forward"},
		}
		plan, err = newFakeDriver(t, HookPrerouting, kernel).Plan(rules)
		if err != nil {
			t.Fatalf("Plan(prerouting): %v", err)
		}
		if !reflect.DeepEqual(plan.Rules, wantPrerouting) {
			t.Errorf("effective rules at prerouting = %+v, want %+v", plan.Rules, wantPrerouting)
		}
	})

	t.Run("a limit-req-rate ban rule is declined with its rule and reason and is not effective", func(t *testing.T) {
		rules := []firewall.BanRule{
			dropFixture("203.0.113.7/32"),
			reqRateFixture(300, "198.51.100.9/32"),
		}
		plan, err := newFakeDriver(t, HookInput, kernel).Plan(rules)
		if err != nil {
			t.Fatalf("Plan: %v", err)
		}
		want := []firewall.PlannedRule{
			{BanRule: rules[0], Placement: "ingress@input"},
		}
		if !reflect.DeepEqual(plan.Rules, want) {
			t.Errorf("effective rules = %+v, want %+v", plan.Rules, want)
		}
		if len(plan.Declined) != 1 {
			t.Fatalf("declined = %+v, want exactly rule 1's limit-req-rate decline", plan.Declined)
		}
		if got := plan.Declined[0]; got.Rule != 1 || got.Feature != "limit-req-rate" || got.Reason == "" {
			t.Errorf("declined = %+v, want rule 1's limit-req-rate with a reason", got)
		}
	})

	t.Run("the configured enforcement scope narrows the targets to the families it can reach", func(t *testing.T) {
		rules := []firewall.BanRule{{
			Targets: []netip.Prefix{
				netip.MustParsePrefix("203.0.113.7/32"),
				netip.MustParsePrefix("2001:db8::7/128"),
			},
			Stance: firewall.StanceDrop,
		}}
		scope := Prefilter{DstAddrs: []netip.Prefix{netip.MustParsePrefix("2001:db8::5/128")}}
		plan, err := newFakeScopedDriver(t, HookInput, scope, kernel).Plan(rules)
		if err != nil {
			t.Fatalf("Plan: %v", err)
		}
		want := []firewall.PlannedRule{{
			BanRule: firewall.BanRule{
				Targets: []netip.Prefix{netip.MustParsePrefix("2001:db8::7/128")},
				Stance:  firewall.StanceDrop,
			},
			Placement: "ingress@input",
		}}
		if !reflect.DeepEqual(plan.Rules, want) {
			t.Errorf("effective rules = %+v, want only the reachable family's target: %+v", plan.Rules, want)
		}
	})

	t.Run("a ban rule no family can reach installs nothing and is not effective", func(t *testing.T) {
		rules := []firewall.BanRule{{
			Targets: []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32")},
			Stance:  firewall.StanceDrop,
		}}
		scope := Prefilter{DstAddrs: []netip.Prefix{netip.MustParsePrefix("2001:db8::5/128")}}
		plan, err := newFakeScopedDriver(t, HookInput, scope, kernel).Plan(rules)
		if err != nil {
			t.Fatalf("Plan: %v", err)
		}
		if len(plan.Rules) != 0 || len(plan.Declined) != 0 {
			t.Errorf("plan = %+v, want no effective rules and no declines for an unreachable ban rule", plan)
		}
	})
}

// The hash values are compared to each other only; the construction
// is never pinned.
func TestPlanFoldsTheEffectiveRules(t *testing.T) {
	kernel := newFakeKernel()
	hashOf := func(t *testing.T, d *Driver, rules []firewall.BanRule) uint32 {
		t.Helper()
		plan, err := d.Plan(rules)
		if err != nil {
			t.Fatalf("Plan: %v", err)
		}
		return plan.Hash
	}

	t.Run("the same effective rules hash identically across plans and runs", func(t *testing.T) {
		rules := []firewall.BanRule{dropFixture("203.0.113.7/32"), bandwidthFixture(1000000, "198.51.100.9/32")}
		first := hashOf(t, newFakeDriver(t, HookInput, kernel), rules)
		if second := hashOf(t, newFakeDriver(t, HookInput, kernel), rules); second != first {
			t.Errorf("hashes %x and %x disagree across drivers for identical rules", first, second)
		}
	})

	t.Run("a changed effective rule changes the hash", func(t *testing.T) {
		before := hashOf(t, newFakeDriver(t, HookInput, kernel), []firewall.BanRule{dropFixture("203.0.113.7/32")})
		after := hashOf(t, newFakeDriver(t, HookInput, kernel), []firewall.BanRule{dropFixture("198.51.100.7/32")})
		if before == after {
			t.Errorf("changed targets hash identically (%x): the fold is blind to the change", before)
		}
	})

	t.Run("changing a declined ban rule keeps the hash", func(t *testing.T) {
		base := []firewall.BanRule{dropFixture("203.0.113.7/32")}
		before := hashOf(t, newFakeDriver(t, HookInput, kernel), append(base, reqRateFixture(300, "198.51.100.9/32")))
		after := hashOf(t, newFakeDriver(t, HookInput, kernel), append(base, reqRateFixture(500, "203.0.113.9/32")))
		if before != after {
			t.Errorf("declined rules changed the hash (%x vs %x): the fold must drop what declines", before, after)
		}
	})

	t.Run("changing a ban rule the scope cannot reach keeps the hash", func(t *testing.T) {
		reach := Prefilter{DstAddrs: []netip.Prefix{netip.MustParsePrefix("2001:db8::5/128")}}
		before := hashOf(t, newFakeScopedDriver(t, HookInput, reach, kernel), []firewall.BanRule{dropFixture("203.0.113.7/32")})
		after := hashOf(t, newFakeScopedDriver(t, HookInput, reach, kernel), []firewall.BanRule{dropFixture("198.51.100.7/32")})
		if before != after {
			t.Errorf("dropped rules changed the hash (%x vs %x): the fold must drop what installs nothing", before, after)
		}
	})

	t.Run("changing the driver configuration changes the hash", func(t *testing.T) {
		rules := []firewall.BanRule{dropFixture("203.0.113.7/32"), bandwidthFixture(1000000, "198.51.100.9/32")}
		input := hashOf(t, newFakeDriver(t, HookInput, kernel), rules)
		prerouting := hashOf(t, newFakeDriver(t, HookPrerouting, kernel), rules)
		if input == prerouting {
			t.Errorf("input and prerouting hash identically (%x): configuration must shape the identity", input)
		}
	})

	t.Run("changing the enforcement scope changes the hash", func(t *testing.T) {
		rules := []firewall.BanRule{dropFixture("203.0.113.7/32")}
		all := hashOf(t, newFakeScopedDriver(t, HookInput, Prefilter{}, kernel), rules)
		ports := hashOf(t, newFakeScopedDriver(t, HookInput, Prefilter{DstPorts: []uint16{443}}, kernel), rules)
		addrs := hashOf(t, newFakeScopedDriver(t, HookInput, Prefilter{DstAddrs: mustPrefixes("203.0.113.5/32")}, kernel), rules)
		if all == ports || all == addrs || ports == addrs {
			t.Errorf("scopes hash all=%x ports=%x addrs=%x: the scope folds into the identity", all, ports, addrs)
		}
	})
}

func TestApplySkipsWhenUnchanged(t *testing.T) {
	rules := []firewall.BanRule{dropFixture("203.0.113.7/32"), bandwidthFixture(1000000, "198.51.100.9/32")}

	t.Run("an identical ruleset installs once and then skips", func(t *testing.T) {
		kernel := newFakeKernel()
		d := newFakeDriver(t, HookInput, kernel)
		first, err := d.Apply(rules)
		if err != nil {
			t.Fatalf("first Apply: %v", err)
		}
		if first.Skipped {
			t.Fatal("first Apply skipped: nothing was applied before it")
		}
		second, err := d.Apply(rules)
		if err != nil {
			t.Fatalf("second Apply: %v", err)
		}
		if !second.Skipped {
			t.Error("second Apply installed: an identical ruleset must skip")
		}
		if second.Hash != first.Hash {
			t.Errorf("skipped cycle reports hash %x, want %x", second.Hash, first.Hash)
		}
		if n := kernel.flushCount(); n != 1 {
			t.Errorf("flushed %d batches, want 1 (the skip installs nothing)", n)
		}
	})

	t.Run("a changed ruleset reinstalls", func(t *testing.T) {
		kernel := newFakeKernel()
		d := newFakeDriver(t, HookInput, kernel)
		if _, err := d.Apply(rules); err != nil {
			t.Fatalf("first Apply: %v", err)
		}
		changed := []firewall.BanRule{dropFixture("198.51.100.7/32")}
		out, err := d.Apply(changed)
		if err != nil {
			t.Fatalf("second Apply: %v", err)
		}
		if out.Skipped {
			t.Error("a changed ruleset skipped: it must re-enforce")
		}
		if n := kernel.flushCount(); n != 2 {
			t.Errorf("flushed %d batches, want 2", n)
		}
	})

	t.Run("a vanished ruleset reinstalls even when unchanged", func(t *testing.T) {
		kernel := newFakeKernel()
		d := newFakeDriver(t, HookInput, kernel)
		if _, err := d.Apply(rules); err != nil {
			t.Fatalf("first Apply: %v", err)
		}
		kernel.vanish()
		out, err := d.Apply(rules)
		if err != nil {
			t.Fatalf("second Apply: %v", err)
		}
		if out.Skipped {
			t.Error("an unchanged ruleset hid behind a vanished enforcement point")
		}
		if n := kernel.flushCount(); n != 2 {
			t.Errorf("flushed %d batches, want 2", n)
		}
	})

	t.Run("the existence probe runs every apply", func(t *testing.T) {
		kernel := newFakeKernel()
		d := newFakeDriver(t, HookInput, kernel)
		for range 3 {
			if _, err := d.Apply(rules); err != nil {
				t.Fatalf("Apply: %v", err)
			}
		}
		if n := kernel.probeCount(); n != 3 {
			t.Errorf("probed %d times, want 3 (freshly probed every apply, never cached)", n)
		}
	})

	t.Run("the skip state follows each driver instance", func(t *testing.T) {
		kernelA, kernelB := newFakeKernel(), newFakeKernel()
		a := newFakeDriver(t, HookInput, kernelA)
		b := newFakeDriver(t, HookInput, kernelB)
		if _, err := a.Apply(rules); err != nil {
			t.Fatalf("Apply(a): %v", err)
		}
		if out, err := b.Apply(rules); err != nil {
			t.Fatalf("Apply(b): %v", err)
		} else if out.Skipped {
			t.Error("a fresh driver instance skipped: skip state follows the instance that installed")
		}
	})
}

func TestApplyReadsTheCountersOfWhatItReplaced(t *testing.T) {
	t.Run("the replaced rules' nonzero counters come back as hits", func(t *testing.T) {
		kernel := newFakeKernel()
		kernel.seed(map[string][]*nftables.Rule{
			ingressName: {
				counterRule("v4_0", 5, 100),
				counterRule("v6_1", 0, 0), // no traffic: not a hit worth reporting
			},
			egressName: {
				counterRule("v4_2", 3, 50),
				counterRule("v6_2", 4, 60), // the same ban rule's other family
			},
		})
		d := newFakeDriver(t, HookInput, kernel)
		out, err := d.Apply([]firewall.BanRule{
			dropFixture("203.0.113.7/32"),
			dropFixture("2001:db8::7/128"),
			bandwidthFixture(1000000, "198.51.100.9/32", "2001:db8::9/128"),
		})
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		want := []firewall.Hit{
			{Rule: 0, Packets: 5, Bytes: 100},
			{Rule: 2, Packets: 7, Bytes: 110},
		}
		if !reflect.DeepEqual(out.Hits, want) {
			t.Errorf("hits = %+v, want %+v (nonzero only, aggregated by ban rule)", out.Hits, want)
		}
	})

	t.Run("a first install reports no hits", func(t *testing.T) {
		kernel := newFakeKernel()
		out, err := newFakeDriver(t, HookInput, kernel).Apply([]firewall.BanRule{dropFixture("203.0.113.7/32")})
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if len(out.Hits) != 0 {
			t.Errorf("hits = %+v, want none (nothing was installed to count)", out.Hits)
		}
	})

	t.Run("a skipped cycle reports no hits", func(t *testing.T) {
		kernel := newFakeKernel()
		kernel.seed(map[string][]*nftables.Rule{
			ingressName: {counterRule("v4_0", 9, 900)},
		})
		d := newFakeDriver(t, HookInput, kernel)
		rules := []firewall.BanRule{dropFixture("203.0.113.7/32")}
		if _, err := d.Apply(rules); err != nil {
			t.Fatalf("first Apply: %v", err)
		}
		out, err := d.Apply(rules)
		if err != nil {
			t.Fatalf("second Apply: %v", err)
		}
		if !out.Skipped || len(out.Hits) != 0 {
			t.Errorf("skipped outcome = %+v, want a skip with no hits", out)
		}
	})
}

func TestApplyReportsDeclines(t *testing.T) {
	kernel := newFakeKernel()
	d := newFakeDriver(t, HookInput, kernel)
	out, err := d.Apply([]firewall.BanRule{
		dropFixture("203.0.113.7/32"),
		reqRateFixture(300, "198.51.100.9/32"),
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(out.Declined) != 1 {
		t.Fatalf("declined = %+v, want exactly rule 1's limit-req-rate decline", out.Declined)
	}
	if got := out.Declined[0]; got.Rule != 1 || got.Feature != "limit-req-rate" || got.Reason == "" {
		t.Errorf("declined = %+v, want rule 1's limit-req-rate with a reason", got)
	}
	if n := kernel.rulesIn(ingressName); n != 1 {
		t.Errorf("ingress chain carries %d kernel rules, want 1 (the declined rule installs nothing)", n)
	}
	if n := kernel.rulesIn(egressName); n != 0 {
		t.Errorf("egress chain carries %d kernel rules, want 0", n)
	}
}

func TestApplyBuildsOneAtomicBatch(t *testing.T) {
	rules := []firewall.BanRule{
		dropFixture("203.0.113.7/32"),
		bandwidthFixture(1000000, "198.51.100.9/32"),
	}

	t.Run("the delete and the rebuild share one flushed batch", func(t *testing.T) {
		kernel := newFakeKernel()
		kernel.seed(nil)
		d := newFakeDriver(t, HookInput, kernel)
		if _, err := d.Apply(rules); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if n := kernel.flushCount(); n != 1 {
			t.Fatalf("flushed %d batches, want 1 — there must be no delete-then-rebuild window", n)
		}
		flush := kernel.lastFlush()
		var kinds []string
		for _, op := range flush {
			kinds = append(kinds, op.kind)
		}
		want := []string{"del-table", "add-table", "add-chain", "add-chain", "add-set", "add-rule", "add-set", "add-rule"}
		if !reflect.DeepEqual(kinds, want) {
			t.Errorf("batch = %v, want %v", kinds, want)
		}
		if got := kernel.rulesIn(ingressName); got != 1 {
			t.Errorf("ingress chain carries %d kernel rules, want 1", got)
		}
		if got := kernel.rulesIn(egressName); got != 1 {
			t.Errorf("egress chain carries %d kernel rules, want 1", got)
		}
	})

	t.Run("an absent ruleset rebuilds without the delete", func(t *testing.T) {
		kernel := newFakeKernel()
		d := newFakeDriver(t, HookInput, kernel)
		if _, err := d.Apply(rules); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		for _, op := range kernel.lastFlush() {
			if op.kind == "del-table" {
				t.Errorf("batch = %+v, want no delete of an absent ruleset", kernel.lastFlush())
				break
			}
		}
		if kernel.probeCount() != 1 {
			t.Errorf("probed %d times, want 1 (the pre-delete existence probe)", kernel.probeCount())
		}
	})

	t.Run("the configured scope's sets join the batch ahead of the rule's matches", func(t *testing.T) {
		kernel := newFakeKernel()
		scope := Prefilter{DstPorts: []uint16{443}, DstAddrs: []netip.Prefix{netip.MustParsePrefix("203.0.113.5/32")}}
		d := newFakeScopedDriver(t, HookInput, scope, kernel)
		if _, err := d.Apply([]firewall.BanRule{dropFixture("203.0.113.7/32")}); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		var kinds []string
		for _, op := range kernel.lastFlush() {
			kinds = append(kinds, op.kind)
		}
		want := []string{"add-table", "add-chain", "add-chain", "add-set", "add-set", "add-set", "add-set", "add-rule"}
		if !reflect.DeepEqual(kinds, want) {
			t.Errorf("batch = %v, want %v", kinds, want)
		}
	})
}

func TestResetToleratesAnAbsentRuleset(t *testing.T) {
	rules := []firewall.BanRule{dropFixture("203.0.113.7/32")}

	t.Run("reset removes the owned ruleset", func(t *testing.T) {
		kernel := newFakeKernel()
		d := newFakeDriver(t, HookInput, kernel)
		if _, err := d.Apply(rules); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if err := d.Reset(); err != nil {
			t.Fatalf("Reset: %v", err)
		}
		if n := kernel.rulesIn(ingressName); n != 0 {
			t.Errorf("ingress chain still carries %d kernel rules after Reset", n)
		}
	})

	t.Run("reset tolerates an absent ruleset", func(t *testing.T) {
		kernel := newFakeKernel()
		d := newFakeDriver(t, HookInput, kernel)
		if err := d.Reset(); err != nil {
			t.Errorf("Reset on an absent ruleset = %v, want nil", err)
		}
	})

	t.Run("after a reset the same ruleset installs again", func(t *testing.T) {
		kernel := newFakeKernel()
		d := newFakeDriver(t, HookInput, kernel)
		if _, err := d.Apply(rules); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if err := d.Reset(); err != nil {
			t.Fatalf("Reset: %v", err)
		}
		out, err := d.Apply(rules)
		if err != nil {
			t.Fatalf("Apply after Reset: %v", err)
		}
		if out.Skipped {
			t.Error("the re-install after Reset skipped: the reset ends the skip state")
		}
	})
}

func TestPlanRefusesWhatItCannotPlan(t *testing.T) {
	kernel := newFakeKernel()
	tests := []struct {
		name    string
		rule    firewall.BanRule
		wantErr string
	}{
		{
			name:    "an unknown stance is refused loudly",
			rule:    firewall.BanRule{Stance: "throttle", Targets: []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32")}},
			wantErr: `stance "throttle": not supported`,
		},
		{
			name:    "a limit stance without its rate is refused loudly",
			rule:    firewall.BanRule{Stance: firewall.StanceLimitPktRate, Targets: []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32")}},
			wantErr: `stance "limit-pkt-rate": rate required`,
		},
		{
			name:    "a limit stance below rate one is refused loudly",
			rule:    firewall.BanRule{Stance: firewall.StanceLimitBandwidth, Rate: ratePtr(0), Targets: []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32")}},
			wantErr: "rate must be at least 1",
		},
		{
			name: "a supported stance plans",
			rule: dropFixture("203.0.113.7/32"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newFakeDriver(t, HookInput, kernel)
			_, err := d.Plan([]firewall.BanRule{tt.rule})
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Plan: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Plan succeeded, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Plan error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestPerPointEnforcement(t *testing.T) {
	rules := []firewall.BanRule{dropFixture("203.0.113.7/32")}

	t.Run("an unreachable enforcement point is reported while another still enforces", func(t *testing.T) {
		gone := newFakeDriver(t, HookInput, newFakeKernel())
		gone.open = func() (kernelConn, io.Closer, error) {
			return nil, nil, fmt.Errorf("%w: open /gone: no such file or directory", firewall.ErrUnreachable)
		}
		kernel := newFakeKernel()
		alive := newFakeDriver(t, HookInput, kernel)

		if _, err := gone.Apply(rules); !errors.Is(err, firewall.ErrUnreachable) {
			t.Errorf("Apply at a vanished point = %v, want a firewall.ErrUnreachable", err)
		}
		if out, err := alive.Apply(rules); err != nil || out.Skipped {
			t.Errorf("Apply at the live point = (%+v, %v), want a plain install", out, err)
		}
		if n := kernel.rulesIn(ingressName); n != 1 {
			t.Errorf("ingress chain carries %d kernel rules, want 1 (the live point still enforces)", n)
		}
	})

	t.Run("one point's unchanged skip never silences another's install", func(t *testing.T) {
		kernelA, kernelB := newFakeKernel(), newFakeKernel()
		a := newFakeDriver(t, HookInput, kernelA)
		b := newFakeDriver(t, HookInput, kernelB)
		if _, err := a.Apply(rules); err != nil {
			t.Fatalf("Apply(a): %v", err)
		}
		if _, err := b.Apply(rules); err != nil {
			t.Fatalf("Apply(b): %v", err)
		}
		out, err := a.Apply(rules)
		if err != nil {
			t.Fatalf("second Apply(a): %v", err)
		}
		if !out.Skipped {
			t.Error("an identical ruleset at one point must skip")
		}
		changed := []firewall.BanRule{dropFixture("198.51.100.7/32")}
		out, err = b.Apply(changed)
		if err != nil {
			t.Fatalf("Apply(b, changed): %v", err)
		}
		if out.Skipped {
			t.Error("a changed ruleset at one point must re-enforce")
		}
		if n := kernelA.flushCount(); n != 1 {
			t.Errorf("point a flushed %d batches, want 1 (its skip state is its own)", n)
		}
		if n := kernelB.flushCount(); n != 2 {
			t.Errorf("point b flushed %d batches, want 2", n)
		}
	})
}
