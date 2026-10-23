package firewall

import "errors"

// ErrUnreachable marks a driver failure caused by the target
// enforcement point being unreachable — its handle cannot be opened.
// The update cycle warns and skips that point for the cycle and
// tolerates it on reset; failures past the open stay loud.
var ErrUnreachable = errors.New("enforcement point unreachable")

// Point is one enforcement point — where one driver instance enforces.
// Label names the point in the engine's logs and --dry-run output; the
// engine never parses it.
type Point struct {
	Label  string
	Driver Driver
}

// Hit is one ban rule's nonzero counter reading at the install that
// replaces it: Rule is the ban rule's index in the ruleset the driver
// replaced (the previous apply's input rules, in --dry-run JSON order),
// Packets and Bytes the reading since the last change.
type Hit struct {
	Rule    int
	Packets uint64
	Bytes   uint64
}

// Decline is one ban-rule feature a firewall driver declines: Rule is
// the ban rule's index in the ruleset handed to the driver, Feature
// names the declined feature (a string: a decline is per rule and per
// feature), and Reason why its enforcement surface cannot apply it.
type Decline struct {
	Rule    int
	Feature string
	Reason  string
}

// PlannedRule is one effective rule: one ban rule as this driver would
// enforce it — after the planning step's declines and drops, carrying
// only the targets that reach its enforcement surface. Placement names
// where the driver puts it; the engine prints it and never parses it.
type PlannedRule struct {
	BanRule
	Placement string
}

// Plan is the pure planning step's answer — no I/O, no privileges: the
// effective rules the driver would install (with their placement
// labels), the ruleset hash identifying them (see Hasher), and the
// ban-rule features it declines with reasons. --dry-run prints exactly
// this.
type Plan struct {
	Rules    []PlannedRule
	Hash     uint32
	Declined []Decline
}

// Outcome is what one Apply reports back: Skipped marks an
// unchanged-skip (the plan's hash matched the last applied hash and
// the owned ruleset still exists); otherwise the install happened,
// Hash identifies it, and Hits holds the nonzero counters of the rules
// it replaced, over the period since the last change. Declines are
// reported on every outcome, skipped cycles included.
type Outcome struct {
	Skipped  bool
	Hash     uint32
	Hits     []Hit
	Declined []Decline
}

// Driver is the firewall-driver port: plan, apply, reset. Plan is the
// pure planning step. Apply replaces the wholly-owned ruleset,
// skipping the install when the plan's hash matches the hash of the
// ruleset it last applied there and the owned ruleset still exists;
// Reset removes the ruleset, tolerating its absence. Skip state
// follows each driver instance (only it knows which ban rules are
// effective), so changed driver configuration re-enforces. A driver
// may wrap ErrUnreachable for an unreachable enforcement point.
type Driver interface {
	Plan(rules []BanRule) (Plan, error)
	Apply(rules []BanRule) (Outcome, error)
	Reset() error
}
