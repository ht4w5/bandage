package nft

import (
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

// The driver's identity suite: the nftables driver's planning and
// apply logic against a fake kernel — the highest point at which
// driver-owned identity is observable without privileges. The fake is
// a private in-memory kernel stand-in that records what would be
// flushed; it replaces the real netlink path in these tests, never
// layers over it. Assertions stay external: which ban rules would be
// installed, when, and what outcomes are reported — the netlink
// encoding itself is verified by the root-gated kernel test only.

// fakeKernel is the in-memory kernel stand-in: it stands in for
// nftables in one namespace, records every batch handed to Flush and
// applies it to its own table state, and serves the read-backs the
// driver performs (existence probes, chain listing, rule counters).
type fakeKernel struct {
	mu           sync.Mutex
	table        *nftables.Table             // the owned table while present
	chains       map[string][]*nftables.Rule // flushed kernel rules per chain name
	probes       int                         // existence probes served
	flushes      [][]kernelOp                // one entry per flushed batch
	batch        []kernelOp                  // the batch being buffered
	pendingRules []*nftables.Rule            // the batch's rules, flushed together
}

// kernelOp is one recorded batch operation — the shape of what would
// be flushed, never its encoding.
type kernelOp struct {
	kind  string // del-table, add-table, add-chain, add-set or add-rule
	chain string // the chain name of add-chain and add-rule
}

// newFakeKernel stands up an empty fake kernel — nothing installed.
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
// records it — exactly the atomicity the real flush has: the batch
// lands all at once or not at all.
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

// flushCount is the number of batches flushed — the atomic batches,
// never individual operations.
func (k *fakeKernel) flushCount() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.flushes)
}

// lastFlush is the batch of the most recent flush, as recorded ops.
func (k *fakeKernel) lastFlush() []kernelOp {
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.flushes) == 0 {
		return nil
	}
	return k.flushes[len(k.flushes)-1]
}

// rulesIn counts the kernel rules recorded in one chain.
func (k *fakeKernel) rulesIn(chain string) int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.chains[chain])
}

// probeCount is the number of existence probes served — the cheap
// probe every apply performs before deciding anything.
func (k *fakeKernel) probeCount() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.probes
}

// counterRule builds the kernel-rule fixture one ban rule's counter
// read-back maps: the lookup of the ban rule's set (its index baked
// into the name) and the counter reading beside it — the shape every
// ban rule's kernel rule carries.
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
	d, err := New(hook)
	if err != nil {
		t.Fatalf("New(%q): %v", hook, err)
	}
	d.open = kernel.dial
	return d
}

// The ban rule fixtures the identity tests plan and apply.
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

func reqRateFixture(rate int64, prefixes ...string) firewall.BanRule {
	r := dropFixture(prefixes...)
	r.Stance, r.Rate = firewall.StanceLimitReqRate, &rate
	return r
}

// TestPlanDerivesTheEffectiveRules: the planning step is pure and
// derives exactly what would be installed — the ban rules this driver
// can honour, narrowed to the targets that reach their address
// families, placed at their chains by their stances, and the declines
// with reasons.
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

	t.Run("the service prefilter narrows the targets to the families it can reach", func(t *testing.T) {
		rules := []firewall.BanRule{{
			Targets: []netip.Prefix{
				netip.MustParsePrefix("203.0.113.7/32"),
				netip.MustParsePrefix("2001:db8::7/128"),
			},
			Prefilter: firewall.Prefilter{DstAddrs: []netip.Prefix{netip.MustParsePrefix("2001:db8::5/128")}},
			Stance:    firewall.StanceDrop,
		}}
		plan, err := newFakeDriver(t, HookInput, kernel).Plan(rules)
		if err != nil {
			t.Fatalf("Plan: %v", err)
		}
		want := []firewall.PlannedRule{{
			BanRule: firewall.BanRule{
				Targets:   []netip.Prefix{netip.MustParsePrefix("2001:db8::7/128")},
				Prefilter: rules[0].Prefilter,
				Stance:    firewall.StanceDrop,
			},
			Placement: "ingress@input",
		}}
		if !reflect.DeepEqual(plan.Rules, want) {
			t.Errorf("effective rules = %+v, want only the reachable family's target: %+v", plan.Rules, want)
		}
	})

	t.Run("a ban rule no family can reach installs nothing and is not effective", func(t *testing.T) {
		rules := []firewall.BanRule{{
			Targets:   []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32")},
			Prefilter: firewall.Prefilter{DstAddrs: []netip.Prefix{netip.MustParsePrefix("2001:db8::5/128")}},
			Stance:    firewall.StanceDrop,
		}}
		plan, err := newFakeDriver(t, HookInput, kernel).Plan(rules)
		if err != nil {
			t.Fatalf("Plan: %v", err)
		}
		if len(plan.Rules) != 0 || len(plan.Declined) != 0 {
			t.Errorf("plan = %+v, want no effective rules and no declines for an unreachable ban rule", plan)
		}
	})
}

// TestPlanFoldsTheEffectiveRules: the ruleset hash folds the effective
// rules — after the declines, after the drops — so the identity is
// what would be installed, and changing driver configuration changes
// it. The hash values are compared to each other only; the
// construction is never pinned.
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

	t.Run("changing a ban rule the prefilter cannot reach keeps the hash", func(t *testing.T) {
		reach := firewall.Prefilter{DstAddrs: []netip.Prefix{netip.MustParsePrefix("2001:db8::5/128")}}
		unreachable := func(target string) firewall.BanRule {
			r := dropFixture(target)
			r.Prefilter = reach
			return r
		}
		before := hashOf(t, newFakeDriver(t, HookInput, kernel), []firewall.BanRule{unreachable("203.0.113.7/32")})
		after := hashOf(t, newFakeDriver(t, HookInput, kernel), []firewall.BanRule{unreachable("198.51.100.7/32")})
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
}

// TestApplySkipsWhenUnchanged: the skip-if-unchanged decision is the
// driver's own — the install is skipped when the plan's hash matches
// the last applied hash and the owned ruleset still exists (probed
// fresh every apply), and re-enforces otherwise. Skip state follows
// each driver instance.
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
		// The table is gone behind our back — an external reset, a
		// recreated container — while the ruleset is unchanged.
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

// TestApplyReadsTheCountersOfWhatItReplaced: the hits covering the
// period since the last change are the nonzero counters of the rules
// the install replaces — read before the rebuild, mapped onto the ban
// rules they count, aggregated across families.
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

// TestApplyReportsDeclines: what the plan declines, apply reports —
// per rule (by index) and per feature, with a reason — and the
// declined ban rule installs nothing at the packet layer, never faked
// as a packet or byte meter.
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
	// The declined ban rule installs nothing: the drop's one kernel
	// rule on the ingress chain, no meter anywhere.
	if n := kernel.rulesIn(ingressName); n != 1 {
		t.Errorf("ingress chain carries %d kernel rules, want 1 (the declined rule installs nothing)", n)
	}
	if n := kernel.rulesIn(egressName); n != 0 {
		t.Errorf("egress chain carries %d kernel rules, want 0", n)
	}
}

// TestApplyBuildsOneAtomicBatch: the rebuild is one atomic batch —
// the delete and the rebuild share one flush, so the table is never
// absent while the new one applies — and the delete joins the batch
// only where the pre-delete existence probe found the table.
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
		// The delete joins the batch and comes before every add; the
		// table, both chains and one kernel rule per ban rule and
		// family are rebuilt inside the same batch.
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
}

// TestResetToleratesAnAbsentRuleset: reset removes the owned ruleset
// and tolerates it being already absent, and a reset driver re-enforces
// from scratch.
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

// TestPlanRefusesWhatItCannotPlan: the planning step is loud about a
// ban rule it could neither honour nor decline — an unknown stance or
// a limit without a usable rate is a broken seam input, never silently
// dropped. Failing and passing case per validation.
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
