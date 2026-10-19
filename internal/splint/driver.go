package splint

import (
	"slices"
	"sync"
)

// Driver is the firewall-driver port: Install replaces the
// wholly-owned ruleset with rules, Reset removes it. The port is the
// update cycle's seam: Stub below and ticket 02's nftables driver
// implement it.
type Driver interface {
	Install(rules []BanRule) error
	Reset() error
}

// Stub is a recording Driver: the walking skeleton's placeholder
// installer until ticket 02's nftables driver lands, and the test
// double the update-cycle seam observes. It never touches netlink.
type Stub struct {
	// InstallErr, when set before use, makes Install fail.
	InstallErr error

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

// Reset records the call.
func (s *Stub) Reset() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resets++
	return nil
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
