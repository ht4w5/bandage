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

// Driver is the firewall-driver port: Install replaces the
// wholly-owned ruleset with rules, Reset removes it. The port is the
// update cycle's seam: Stub below and the nftables driver
// (internal/splint/nft) implement it. A driver per target namespace
// may wrap ErrUnreachable when that namespace cannot be reached.
type Driver interface {
	Install(rules []BanRule) error
	Reset() error
}

// Stub is a recording Driver: the test double the update-cycle seam
// observes. It never touches netlink, so lifecycle behavior is
// testable without privileges.
type Stub struct {
	// InstallErr, when set before use, makes Install fail.
	InstallErr error

	// ResetErr, when set before use, makes Reset fail.
	ResetErr error

	mu       sync.Mutex
	installs [][]BanRule
	resets   int
}

// Install records rules and returns InstallErr.
func (s *Stub) Install(rules []BanRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.InstallErr != nil {
		return s.InstallErr
	}
	s.installs = append(s.installs, slices.Clone(rules))
	return nil
}

// Reset records the call and returns ResetErr.
func (s *Stub) Reset() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resets++
	return s.ResetErr
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
