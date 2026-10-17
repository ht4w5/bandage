// Package evaluation runs the rule model over events: prefilter, tracker
// update, match (filter ∧ overflow) and action dispatch.
package evaluation

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"time"

	bandage "github.com/HT4w5/bandage/internal/domain"
)

// TrackerCache is the tracker-state port beside its consumer: records
// keyed by (ns, key) with sliding TTL and atomic per-key update
// callbacks. fn runs under the store's per-key lock, so it must not
// perform I/O or use ctx; ttl is the sliding expiry, zero means no
// expiry (the reserved filesize namespace). The in-memory store
// satisfies this structurally.
type TrackerCache interface {
	Update(ctx context.Context, ns, key string, ttl time.Duration, fn func(*bandage.Record)) (bandage.Record, error)
}

// ReportSink is the report write path beside its consumer: a Trigger
// upserts one report per (rule, target). report.Service satisfies this
// structurally.
type ReportSink interface {
	Trigger(ctx context.Context, rec bandage.Report) error
}

// Service evaluates events against the loaded chains.
//
// A rule matches when its filter accepts the event and its tracker (if
// any) overflows; a match runs the rule's full action list in order.
// Terminality is per-rule: a rule containing report, goto or stop then
// ends traversal of its chain, while other chains are still evaluated
// for the event. Tracker decay uses event time; report timestamps use
// the injected wall clock.
type Service struct {
	chains  []bandage.Chain
	byName  map[string]int
	cache   TrackerCache
	reports ReportSink
	now     func() time.Time
	logger  *slog.Logger
}

func NewService(chains []bandage.Chain, cache TrackerCache, reports ReportSink, now func() time.Time, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	byName := make(map[string]int, len(chains))
	for i, chain := range chains {
		byName[chain.Name] = i
	}
	return &Service{chains: chains, byName: byName, cache: cache, reports: reports, now: now, logger: logger}
}

// Evaluate runs every chain over the event: chains in file order, rules
// within a chain in order.
func (s *Service) Evaluate(ctx context.Context, event *bandage.Event) error {
	for i := range s.chains {
		if err := s.runChain(ctx, i, event); err != nil {
			return err
		}
	}
	return nil
}

// runChain traverses one chain's rules in order. It is also entered by
// name from goto/jump actions.
func (s *Service) runChain(ctx context.Context, ci int, event *bandage.Event) error {
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
		if err := s.runActions(ctx, chain, rule, reading, event); err != nil {
			return err
		}
		if rule.Terminal() {
			break
		}
	}
	return nil
}

// runActions runs a matching rule's full action list in order: the
// actions always all run, and terminality applies only after the list.
func (s *Service) runActions(ctx context.Context, chain *bandage.Chain, rule *bandage.Rule, reading bandage.TrackerReading, event *bandage.Event) error {
	for _, action := range rule.Actions {
		switch {
		case action.Report != nil:
			if err := s.trigger(ctx, chain, rule, action.Report, reading, event); err != nil {
				return err
			}
		case action.Log != nil:
			// flux's log statement: the level and message name the
			// record; the event and the rule's tracker reading are
			// logged with it (PLAN §1).
			s.logger.Log(ctx, action.Log.Level, action.Log.Message,
				"rule", rule.ID,
				"event", event,
				"tracker", reading,
			)
		case action.Goto != "":
			if err := s.runNamedChain(ctx, rule, action.Goto, event); err != nil {
				return err
			}
		case action.Jump != "":
			if err := s.runNamedChain(ctx, rule, action.Jump, event); err != nil {
				return err
			}
		}
	}
	return nil
}

// runNamedChain runs a goto/jump target chain by name. The loader has
// validated that the target exists (validateChainGraph).
func (s *Service) runNamedChain(ctx context.Context, rule *bandage.Rule, name string, event *bandage.Event) error {
	ci, ok := s.byName[name]
	if !ok {
		return fmt.Errorf("evaluate rule %q: target chain %q not found", rule.ID, name)
	}
	return s.runChain(ctx, ci, event)
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
	volume := cfg.Volume
	ttl := cfg.TTL
	// The key is the Target: the source address aggregated to the
	// tracker's prefix, so sources in one prefix share tracker state
	// (the domain's key convention).
	target := cfg.Target(event.RemoteAddr).String()
	key := bandage.TrackerKey(target)
	switch cfg.Kind {
	case bandage.TrackBandwidth:
		increment = float64(event.SentBytes)
	case bandage.TrackReplay:
		if event.SizeBytes == bandage.FilesizeUnknown {
			// Warm-up blindness (DECISIONS §8): skip the event entirely —
			// no increment, no decay, no cache touch. No Match is possible
			// until the path's Filesize estimate is warm.
			return bandage.TrackerReading{}, false, nil
		}
		// Increment by the transferred fraction of the estimated size,
		// capped at 1 per event (DECISIONS §8; no flux byte-domain hack).
		size := float64(event.SizeBytes)
		increment = math.Min(float64(event.SentBytes)/size, 1)
		// Volume is the volume method's output for this event's estimate
		// ("tolerated download equivalents") and the cache-entry TTL is
		// re-derived from it per event.
		volume = cfg.VolumeFor(size)
		ttl = bandage.TTL(cfg.Leak, volume)
		// Replay state is keyed per (Target, path): the domain's key
		// convention joins the target prefix string and the path with
		// KeySep (DECISIONS §9).
		key = bandage.ReplayTrackerKey(target, event.Path)
	}
	rec, err := s.cache.Update(ctx, rule.ID, key, ttl, func(r *bandage.Record) {
		r.Accumulate(increment, cfg.Leak, event.Time.Unix())
	})
	if err != nil {
		return bandage.TrackerReading{}, false, fmt.Errorf("evaluate rule %q: %w", rule.ID, err)
	}
	reading := bandage.TrackerReading{
		Track:  string(cfg.Kind),
		Value:  rec.Value,
		Leak:   cfg.Leak,
		Volume: volume,
	}
	return reading, rec.Overflow(volume), nil
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
