package splint

import (
	"errors"
	"slices"
	"sync"
)

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

// Driver is the firewall-driver port: Install replaces the
// wholly-owned ruleset with rules and reports the nonzero packet/byte
// counters of the rules it replaced, Reset removes it, and
// TableExists probes whether that ruleset is still in place — the
// cheap existence probe of the skip-if-unchanged check (the probe is
// existence, not rule bodies: rule-body tampering under a surviving
// table is undetected). The port is the update cycle's seam: Stub
// below and the nftables driver (internal/splint/nft) implement it. A
// driver per target namespace may wrap ErrUnreachable when that
// namespace cannot be reached.
type Driver interface {
	Install(rules []BanRule) ([]Hit, error)
	Reset() error
	TableExists() (bool, error)
}

// Stub is a recording Driver: the test double the update-cycle seam
// observes. It never touches netlink, so lifecycle behavior is
// testable without privileges.
type Stub struct {
	// InstallErr, when set before use, makes Install fail.
	InstallErr error

	// ResetErr, when set before use, makes Reset fail.
	ResetErr error

	// TableGone, when set before use, makes TableExists report the
	// wholly-owned ruleset missing — an external reset or a recreated
	// container hiding behind an unchanged hash.
	TableGone bool

	// InstallHits, when set before use, are the nonzero counter
	// readings every Install reports — the hits the update cycle
	// logs.
	InstallHits []Hit

	mu       sync.Mutex
	installs [][]BanRule
	resets   int
	probes   int
}

// Install records rules and returns InstallHits, or InstallErr.
func (s *Stub) Install(rules []BanRule) ([]Hit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.InstallErr != nil {
		return nil, s.InstallErr
	}
	s.installs = append(s.installs, slices.Clone(rules))
	return slices.Clone(s.InstallHits), nil
}

// Reset records the call and returns ResetErr.
func (s *Stub) Reset() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resets++
	return s.ResetErr
}

// TableExists counts the probe and reports the ruleset present unless
// TableGone is set.
func (s *Stub) TableExists() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.probes++
	return !s.TableGone, nil
}

// InstallCalls returns the rulesets passed to Install, in order.
func (s *Stub) InstallCalls() [][]BanRule {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.installs)
}

// ResetCalls returns how many times Reset ran.
func (s *Stub) ResetCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resets
}

// TableProbes returns how many times TableExists ran.
func (s *Stub) TableProbes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.probes
}
