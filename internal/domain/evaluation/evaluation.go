// Package evaluation runs the rule model over events: prefilter, tracker
// update, match (filter and overflow) and action dispatch.
package evaluation

import (
	"context"
	"fmt"
	"math"
	"time"

	bandage "github.com/HT4w5/bandage/internal/domain"
)

// TrackerCache is the tracker-state port: records keyed by (ns, key) with sliding TTL and atomic per-key updates.
type TrackerCache interface {
	// Update applies fn to the record for (ns, key) under the store's per-key lock; fn must not do I/O or use ctx. ttl 0 means no expiry.
	Update(ctx context.Context, ns, key string, ttl time.Duration, fn func(*bandage.Record)) (bandage.Record, error)
	// Clear empties the record for (ns, key) - the Trigger reset: the bucket re-arms (ADR 0008).
	Clear(ctx context.Context, ns, key string) error
}

// ReportSink is the report write path: a Trigger upserts one report per (rule, target).
type ReportSink interface {
	Trigger(ctx context.Context, rec bandage.Report) error
}

// Logger is the log action's logging port (ADR 0005); it carries only the domain's four levels, so a rule can never exit the process.
type Logger interface {
	Log(level bandage.Level, msg string, fields map[string]any)
}

// nopLogger discards every record (the Service default).
type nopLogger struct{}

func (nopLogger) Log(bandage.Level, string, map[string]any) {}

// Service evaluates events against the loaded chains.
type Service struct {
	chains  []bandage.Chain
	byName  map[string]int
	cache   TrackerCache
	reports ReportSink
	now     func() time.Time
	logger  Logger
}

func NewService(chains []bandage.Chain, cache TrackerCache, reports ReportSink, now func() time.Time, logger Logger) *Service {
	if logger == nil {
		logger = nopLogger{}
	}
	byName := make(map[string]int, len(chains))
	for i, chain := range chains {
		byName[chain.Name] = i
	}
	return &Service{chains: chains, byName: byName, cache: cache, reports: reports, now: now, logger: logger}
}

// Evaluate runs every chain over the event: chains in file order, rules within a chain in order.
func (s *Service) Evaluate(ctx context.Context, event *bandage.Event) error {
	for i := range s.chains {
		if err := s.runChain(ctx, i, event); err != nil {
			return err
		}
	}
	return nil
}

// matchContext is one rule match in progress: rule, chain, trigger-time tracker reading and event.
type matchContext struct {
	chain   *bandage.Chain
	rule    *bandage.Rule
	reading bandage.TrackerReading
	event   *bandage.Event
}

// target is the report Target and tracker key base: the event's source aggregated to the rule tracker's prefix.
func (m matchContext) target() string {
	return m.rule.Tracker.TargetString(m.event.RemoteAddr)
}

// runChain traverses one chain's rules in order; also entered by name from goto/jump actions.
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
		if err := s.runActions(ctx, matchContext{chain: chain, rule: rule, reading: reading, event: event}); err != nil {
			return err
		}
		if rule.Terminal() {
			break
		}
	}
	return nil
}

// runActions runs a matching rule's full action list in order; terminality applies only after the list.
func (s *Service) runActions(ctx context.Context, m matchContext) error {
	dispatch := actionDispatch{svc: s, ctx: ctx, m: m}
	for _, action := range m.rule.Actions {
		if err := action.Accept(&dispatch); err != nil {
			return err
		}
	}
	return nil
}

// actionDispatch is the evaluation side of Action.Accept: it executes one action variant for a match.
type actionDispatch struct {
	svc *Service
	ctx context.Context
	m   matchContext
}

func (d *actionDispatch) VisitReport(a *bandage.ReportAction) error {
	return d.svc.trigger(d.ctx, d.m, a)
}

func (d *actionDispatch) VisitLog(a *bandage.LogAction) error {
	// The record carries the rule, its Target, the event and the reading.
	d.svc.logger.Log(a.Level, a.Message, map[string]any{
		"rule":    d.m.rule.ID,
		"target":  d.m.target(),
		"event":   d.m.event,
		"tracker": d.m.reading,
	})
	return nil
}

func (d *actionDispatch) VisitGoto(target string) error {
	return d.svc.runNamedChain(d.ctx, d.m.rule, target, d.m.event)
}

func (d *actionDispatch) VisitJump(target string) error {
	return d.svc.runNamedChain(d.ctx, d.m.rule, target, d.m.event)
}

func (d *actionDispatch) VisitStop() error { return nil }

// runNamedChain runs a goto/jump target chain by name (the loader has validated that the target exists).
func (s *Service) runNamedChain(ctx context.Context, rule *bandage.Rule, name string, event *bandage.Event) error {
	ci, ok := s.byName[name]
	if !ok {
		return fmt.Errorf("evaluate rule %q: target chain %q not found", rule.ID, name)
	}
	return s.runChain(ctx, ci, event)
}

// updateTracker feeds the rule's tracker (when it has one) and reports the trigger-time reading plus whether the rule matched.
func (s *Service) updateTracker(ctx context.Context, rule *bandage.Rule, event *bandage.Event) (bandage.TrackerReading, bool, error) {
	if rule.Tracker == nil {
		// Tracker-less rules match on filter alone.
		return bandage.TrackerReading{}, true, nil
	}
	cfg := rule.Tracker
	increment := 1.0
	volume := cfg.Volume
	ttl := cfg.TTL
	key := matchKey(cfg, event)
	switch cfg.Kind {
	case bandage.TrackBandwidth:
		increment = float64(event.SentBytes)
	case bandage.TrackReplay:
		if event.SizeBytes == bandage.FilesizeUnknown {
			// Warm-up blindness: skip unknown sizes entirely - no increment,
			// no decay, no cache touch.
			return bandage.TrackerReading{}, false, nil
		}
		// Increment is the transferred fraction of the estimated size, capped
		// at 1 per event.
		size := float64(event.SizeBytes)
		increment = math.Min(float64(event.SentBytes)/size, 1)
		// Volume is the volume method's output for this event's estimate;
		// the cache-entry TTL is re-derived from it per event.
		volume = cfg.VolumeFor(size)
		ttl = bandage.TTL(cfg.Leak, volume)
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

// matchKey derives the tracker cache key: the Target, or for replay the Target and path joined with KeySep; the key a Trigger empties.
func matchKey(cfg *bandage.TrackerConfig, event *bandage.Event) string {
	target := cfg.TargetString(event.RemoteAddr)
	if cfg.Kind == bandage.TrackReplay {
		return bandage.ReplayTrackerKey(target, event.Path)
	}
	return bandage.TrackerKey(target)
}

// trigger runs the rule's report action and, on success, empties the matched rule's tracker record; a failed write is not a Trigger outcome (ADR 0008).
func (s *Service) trigger(ctx context.Context, m matchContext, action *bandage.ReportAction) error {
	now := s.now()
	rec := bandage.Report{
		Rule:      m.rule.ID,
		Chain:     m.chain.Name,
		Reason:    action.Reason,
		Target:    m.target(),
		CreatedAt: now,
		UpdatedAt: now,
		ExpiresAt: now.Add(action.TTL),
		Tracker:   m.reading,
		Sample: bandage.Sample{
			Time:   m.event.Time,
			Path:   m.event.Path,
			Agent:  m.event.Agent,
			Status: m.event.Status,
			Sent:   m.event.SentBytes,
			Size:   m.event.SizeBytes,
		},
	}
	if err := s.reports.Trigger(ctx, rec); err != nil {
		return err
	}
	if m.rule.Tracker == nil {
		// Tracker-less rules have nothing to empty.
		return nil
	}
	if err := s.cache.Clear(ctx, m.rule.ID, matchKey(m.rule.Tracker, m.event)); err != nil {
		return fmt.Errorf("evaluate rule %q: %w", m.rule.ID, err)
	}
	return nil
}
