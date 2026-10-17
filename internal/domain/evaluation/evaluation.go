// Package evaluation runs the rule model over events: prefilter, tracker
// update, match (filter ∧ overflow) and action dispatch.
package evaluation

import (
	"context"
	"fmt"
	"time"

	bandage "github.com/HT4w5/bandage/internal/domain"
	"github.com/HT4w5/bandage/internal/domain/report"
	"github.com/HT4w5/bandage/internal/domain/track"
)

// Service evaluates events against the loaded chains.
//
// A rule matches when its filter accepts the event and its tracker (if
// any) overflows; a match runs the rule's actions in order. Tracker decay
// uses event time; report timestamps use the injected wall clock.
type Service struct {
	chains  []bandage.Chain
	cache   track.TrackerCache
	reports *report.Service
	now     func() time.Time
}

func NewService(chains []bandage.Chain, cache track.TrackerCache, reports *report.Service, now func() time.Time) *Service {
	return &Service{chains: chains, cache: cache, reports: reports, now: now}
}

// Evaluate runs every chain's rules over the event. Control flow between
// chains (goto/jump/stop) lands with the chains/actions ticket; until
// then all rules are evaluated in order.
func (s *Service) Evaluate(ctx context.Context, event *bandage.Event) error {
	for ci := range s.chains {
		chain := &s.chains[ci]
		for ri := range chain.Rules {
			rule := &chain.Rules[ri]
			if !rule.Filter.Match(event) {
				continue
			}
			reading, matched, err := s.updateTracker(ctx, rule, event)
			if err != nil {
				return err
			}
			if !matched {
				continue
			}
			for _, action := range rule.Actions {
				if action.Report == nil {
					continue
				}
				if err := s.trigger(ctx, chain, rule, action.Report, reading, event); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// updateTracker feeds the rule's tracker (when it has one) and reports
// the trigger-time reading plus whether the rule matched.
func (s *Service) updateTracker(ctx context.Context, rule *bandage.Rule, event *bandage.Event) (bandage.TrackerReading, bool, error) {
	if rule.Tracker == nil {
		// Tracker-less rules match on filter alone.
		return bandage.TrackerReading{}, true, nil
	}
	cfg := rule.Tracker
	increment := 1.0
	if cfg.Kind == bandage.TrackBandwidth {
		increment = float64(event.SentBytes)
	}
	// The key is the Target: the source address aggregated to the
	// tracker's prefix, so sources in one prefix share tracker state.
	key := cfg.Target(event.RemoteAddr).String()
	rec, err := s.cache.Update(ctx, rule.ID, key, cfg.TTL, func(r *track.Record) {
		r.Accumulate(increment, cfg.Leak, event.Time.Unix())
	})
	if err != nil {
		return bandage.TrackerReading{}, false, fmt.Errorf("evaluate rule %q: %w", rule.ID, err)
	}
	reading := bandage.TrackerReading{
		Track:  string(cfg.Kind),
		Value:  rec.Value,
		Leak:   cfg.Leak,
		Volume: cfg.Volume,
	}
	return reading, rec.Overflow(cfg.Volume), nil
}

func (s *Service) trigger(ctx context.Context, chain *bandage.Chain, rule *bandage.Rule, action *bandage.ReportAction, reading bandage.TrackerReading, event *bandage.Event) error {
	now := s.now()
	rec := bandage.Report{
		Rule:      rule.ID,
		Chain:     chain.Name,
		Reason:    action.Reason,
		Target:    rule.Tracker.Target(event.RemoteAddr).String(),
		CreatedAt: now,
		UpdatedAt: now,
		ExpiresAt: now.Add(action.TTL),
		Tracker:   reading,
		Sample: bandage.Sample{
			Time:   event.Time,
			Path:   event.Path,
			Agent:  event.Agent,
			Status: event.Status,
			Sent:   event.SentBytes,
			Size:   event.SizeBytes,
		},
	}
	return s.reports.Trigger(ctx, rec)
}
