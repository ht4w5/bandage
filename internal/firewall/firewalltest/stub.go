// Package firewalltest holds the recording adapters the update-cycle
// seam observes: test doubles on the firewall-driver port that never
// touch an enforcement surface, so lifecycle behaviour stays testable
// without privileges.
package firewalltest

import (
	"slices"
	"sync"

	"github.com/HT4w5/bandage/internal/firewall"
)

// Stub is a recording firewall.Driver: the test double the
// update-cycle seam observes. It never touches netlink, so lifecycle
// behavior is testable without privileges.
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
	InstallHits []firewall.Hit

	// InstallDeclines, when set before use, are the ban-rule features
	// every Install reports declined — the declines the update cycle
	// logs and counts.
	InstallDeclines []firewall.Decline

	mu       sync.Mutex
	installs [][]firewall.BanRule
	resets   int
	probes   int
}

// Install records rules and returns InstallHits and InstallDeclines,
// or InstallErr.
func (s *Stub) Install(rules []firewall.BanRule) (firewall.Outcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.InstallErr != nil {
		return firewall.Outcome{}, s.InstallErr
	}
	s.installs = append(s.installs, slices.Clone(rules))
	return firewall.Outcome{Hits: slices.Clone(s.InstallHits), Declined: slices.Clone(s.InstallDeclines)}, nil
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
func (s *Stub) InstallCalls() [][]firewall.BanRule {
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
