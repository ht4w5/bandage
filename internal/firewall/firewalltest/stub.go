// Package firewalltest holds the recording test doubles the
// update-cycle seam observes: doubles on the firewall-driver port
// that never touch an enforcement surface, so lifecycle behaviour
// stays testable without privileges.
package firewalltest

import (
	"slices"
	"sync"

	"github.com/HT4w5/bandage/internal/firewall"
)

// Stub is a recording firewall.Driver: the test double the
// update-cycle seam observes. It never touches an enforcement surface,
// so lifecycle behavior is testable without privileges. Its plan puts
// every input ban rule it does not decline in effect under the
// Placement label it is configured with, and hashes those effective
// rules with the seam's shared helper — so the ruleset hash the engine
// logs is deterministic across runs. What it applies, skips and
// reports is scripted per test.
type Stub struct {
	// ApplyErr, when set before use, makes Apply fail.
	ApplyErr error

	// ResetErr, when set before use, makes Reset fail.
	ResetErr error

	// Skip, when set before use, makes every Apply report the cycle as
	// skipped — the unchanged ruleset the driver leaves alone — with
	// no hits.
	Skip bool

	// ApplyHits, when set before use, are the nonzero counter readings
	// every installing Apply reports — the hits the update cycle
	// logs.
	ApplyHits []firewall.Hit

	// ApplyDeclined, when set before use, are the ban-rule features
	// Plan and Apply report declined — the declines the update cycle
	// logs and counts. A declined ban rule is not effective.
	ApplyDeclined []firewall.Decline

	// Placement is the placement label every planned rule carries.
	Placement string

	mu      sync.Mutex
	applies [][]firewall.BanRule
	resets  int
}

// Plan reports every input ban rule in effect — the declined ones
// dropped — under the configured placement label, with the ruleset
// hash folding those effective rules.
func (s *Stub) Plan(rules []firewall.BanRule) (firewall.Plan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.planOf(rules), nil
}

// planOf derives the scripted plan over rules.
func (s *Stub) planOf(rules []firewall.BanRule) firewall.Plan {
	plan := firewall.Plan{Declined: slices.Clone(s.ApplyDeclined)}
	declined := map[int]bool{}
	for _, d := range plan.Declined {
		declined[d.Rule] = true
	}
	for i, r := range rules {
		if declined[i] {
			continue
		}
		plan.Rules = append(plan.Rules, firewall.PlannedRule{BanRule: r, Placement: s.Placement})
	}
	plan.Hash = firewall.Hash(plan.Rules)
	return plan
}

// Apply records the ruleset and reports the scripted outcome: ApplyErr
// fails the call; otherwise Skip reports the cycle as skipped with no
// hits, and an installing cycle carries ApplyHits and the plan's
// declines.
func (s *Stub) Apply(rules []firewall.BanRule) (firewall.Outcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ApplyErr != nil {
		return firewall.Outcome{}, s.ApplyErr
	}
	s.applies = append(s.applies, slices.Clone(rules))
	plan := s.planOf(rules)
	if s.Skip {
		return firewall.Outcome{Skipped: true, Hash: plan.Hash, Declined: plan.Declined}, nil
	}
	return firewall.Outcome{Hash: plan.Hash, Hits: slices.Clone(s.ApplyHits), Declined: plan.Declined}, nil
}

// Reset records the call and returns ResetErr.
func (s *Stub) Reset() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resets++
	return s.ResetErr
}

// ApplyCalls returns the rulesets passed to Apply, in order.
func (s *Stub) ApplyCalls() [][]firewall.BanRule {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.applies)
}

// ResetCalls returns how many times Reset ran.
func (s *Stub) ResetCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resets
}
