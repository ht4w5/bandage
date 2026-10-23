// Package firewalltest holds the recording test doubles the
// update-cycle seam observes: firewall drivers that never touch an
// enforcement surface, so lifecycle behavior is testable without
// privileges.
package firewalltest

import (
	"slices"
	"sync"

	"github.com/HT4w5/webmedkit/splint/internal/firewall"
)

// Stub is a recording firewall.Driver. It never touches an enforcement
// surface. Its plan puts every non-declined input ban rule in effect
// under the configured Placement, hashed with the seam's shared
// helper; what it applies, skips and reports is scripted per test.
type Stub struct {
	// ApplyErr, when set before use, makes Apply fail.
	ApplyErr error

	// ResetErr, when set before use, makes Reset fail.
	ResetErr error

	// Skip, when set before use, makes every Apply report the cycle as
	// skipped, with no hits.
	Skip bool

	// ApplyHits, when set before use, are the counter readings every
	// installing Apply reports.
	ApplyHits []firewall.Hit

	// ApplyDeclined, when set before use, are the ban-rule features
	// Plan and Apply report declined. A declined ban rule is not
	// effective.
	ApplyDeclined []firewall.Decline

	// Placement is the placement label every planned rule carries.
	Placement string

	mu      sync.Mutex
	applies [][]firewall.BanRule
	resets  int
}

// Plan reports every non-declined input ban rule in effect under the
// configured placement label.
func (s *Stub) Plan(rules []firewall.BanRule) (firewall.Plan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scriptedPlan(rules), nil
}

func (s *Stub) scriptedPlan(rules []firewall.BanRule) firewall.Plan {
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

// Apply records the ruleset and reports the scripted outcome.
func (s *Stub) Apply(rules []firewall.BanRule) (firewall.Outcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ApplyErr != nil {
		return firewall.Outcome{}, s.ApplyErr
	}
	s.applies = append(s.applies, slices.Clone(rules))
	plan := s.scriptedPlan(rules)
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

func (s *Stub) ResetCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resets
}
