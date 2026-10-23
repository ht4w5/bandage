package firewall

import "errors"

// ErrUnreachable marks a driver failure caused by the target namespace
// being unreachable: its nsfs handle cannot be opened. The update
// cycle warns and skips such a namespace for the cycle (the others
// still install) and tolerates it on reset, so one dead container
// cannot halt enforcement everywhere or spoil a clean shutdown. A
// failure past the open — netlink privileges, a rejected batch — is a
// real error and stays loud.
var ErrUnreachable = errors.New("namespace unreachable")

// Hit is one ban rule's nonzero counter reading at the install that
// replaces it: Rule is the ban rule's index in the ruleset being
// replaced (its --dry-run JSON order), Packets and Bytes the counter's
// reading over the period since the last change.
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

// Outcome is what an install reports back to the engine: the nonzero
// counter readings of the rules it replaced and the ban-rule features
// it declined. Declines are first-class outcomes — reported per rule
// (by index) and per feature — so the engine can log and count every
// piece of enforcement a driver could not honour.
type Outcome struct {
	Hits     []Hit
	Declined []Decline
}

// Driver is the firewall-driver port: Install replaces the
// wholly-owned ruleset with rules and reports the nonzero packet/byte
// counters of the rules it replaced together with the ban-rule features
// it declined, Reset removes it, and TableExists probes whether that
// ruleset is still in place — the cheap existence probe of the
// skip-if-unchanged check (the probe is existence, not rule bodies:
// rule-body tampering under a surviving ruleset is undetected). The
// port is the update cycle's seam: the recording stub (firewalltest)
// and the nftables driver (firewall/nft) implement it. A driver per
// target namespace may wrap ErrUnreachable when that namespace cannot
// be reached.
type Driver interface {
	Install(rules []BanRule) (Outcome, error)
	Reset() error
	TableExists() (bool, error)
}
