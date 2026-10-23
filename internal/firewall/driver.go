package firewall

import "errors"

// ErrUnreachable marks a driver failure caused by the target
// enforcement point being unreachable: its nsfs handle cannot be
// opened. The update cycle warns and skips such an enforcement point
// for the cycle (the others still enforce) and tolerates it on reset,
// so one dead container cannot halt enforcement everywhere or spoil a
// clean shutdown. A failure past the open — netlink privileges, a
// rejected batch — is a real error and stays loud.
var ErrUnreachable = errors.New("namespace unreachable")

// Hit is one ban rule's nonzero counter reading at the install that
// replaces it: Rule is the ban rule's index in the ruleset handed to
// the driver (its --dry-run JSON order), Packets and Bytes the
// counter's reading over the period since the last change.
type Hit struct {
	Rule    int
	Packets uint64
	Bytes   uint64
}

// Decline is one ban-rule feature a firewall driver declines: Rule is
// the ban rule's index in the ruleset handed to the driver, Feature the
// Penalty action it cannot honour (e.g. "limit-req-rate"), and Reason
// why its enforcement surface cannot apply it. A decline is a
// first-class outcome — the engine logs and counts every one, so lost
// enforcement is never silent.
type Decline struct {
	Rule    int
	Feature string
	Reason  string
}

// PlannedRule is one effective rule: one ban rule as this driver would
// actually enforce it — after the declines and the drops of its
// planning step, carrying only the targets that reach its enforcement
// surface — and Placement, the opaque placement label naming where the
// driver puts it (e.g. one of the nftables driver's chains at its
// hook). The engine prints placement labels in logs and --dry-run and
// never parses them.
type PlannedRule struct {
	BanRule
	Placement string
}

// Plan is the pure planning step's answer — no I/O, no privileges: the
// effective rules the driver would install (with their placement
// labels), the ruleset hash identifying them (each driver folds its
// own effective rules with the shared rolling-hash helpers — see
// Hasher), and the ban-rule features it declines with reasons.
// --dry-run prints exactly this.
type Plan struct {
	Rules    []PlannedRule
	Hash     uint32
	Declined []Decline
}

// Outcome is what one Apply reports back: Skipped marks an
// unchanged-skip (the plan's hash matched the last applied hash and
// the owned ruleset still exists — nothing was installed); otherwise
// the install happened and Hash identifies it, Hits holds the nonzero
// counters of the rules the install replaced (the period since the
// last change), and Declined the ban-rule features this ruleset cannot
// honour. Declines are reported on every outcome — skipped cycles
// included — so lost enforcement is never silent.
type Outcome struct {
	Skipped  bool
	Hash     uint32
	Hits     []Hit
	Declined []Decline
}

// Driver is the firewall-driver port: plan, apply, reset. Plan is the
// pure planning step; Apply replaces the wholly-owned ruleset —
// skipping the install when the plan's hash matches the hash of the
// ruleset it last applied there and the owned ruleset still exists
// (a cheap existence probe, fresh every apply) — and reports what
// happened; Reset removes the ruleset, tolerating its absence. The
// rolling hash, the skip-if-unchanged decision and the counter
// read-back are the driver's own: only the driver knows which ban
// rules are actually effective and which it drops, so skip state
// follows each driver instance and changing driver configuration
// re-enforces (the effective rules changed). The port is the update
// cycle's seam: the recording stub (firewalltest) and the nftables
// driver (firewall/nft) implement it. A driver per target namespace
// may wrap ErrUnreachable when that namespace cannot be reached.
type Driver interface {
	Plan(rules []BanRule) (Plan, error)
	Apply(rules []BanRule) (Outcome, error)
	Reset() error
}
