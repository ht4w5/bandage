package splint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/rs/zerolog"

	"github.com/HT4w5/bandage/internal/firewall"
)

// DefaultInterval is the update interval unless the operator says
// otherwise: bans and un-bans track report expiry within minutes.
const DefaultInterval = 5 * time.Minute

// MinInterval is the update interval's floor; a shorter interval churns
// the timer without tightening ban staleness much.
const MinInterval = time.Minute

// ClampInterval resolves the configured update interval: values below
// the one-minute floor are clamped, and clamped reports whether that
// happened.
func ClampInterval(d time.Duration) (time.Duration, bool) {
	if d < MinInterval {
		return MinInterval, true
	}
	return d, false
}

// Updater runs the fetch-compile-apply update cycle at every
// enforcement point — fluxc's lifecycle: one startup test install
// before the loop, the last installed rules kept on a failed cycle,
// and a reset on clean exit. One fetch-compile serves every point.
// The engine carries no hash, probe, skip or counter logic: each
// driver owns its identity and the engine just logs what the driver
// reports — applied, or unchanged-skip with the hash, the nonzero hits
// since the last change, and declines. The engine knows no targeting
// and no enforcement scope: where and what to enforce is each driver's
// configuration (ADR 0012); the points name themselves only through
// their opaque labels.
type Updater struct {
	fetcher  *Fetcher
	points   []firewall.Point
	policy   Policy
	log      zerolog.Logger
	interval time.Duration

	// ticks feeds the update loop in tests; nil means a real ticker.
	ticks <-chan time.Time
}

// New assembles an Updater enforcing at every given enforcement point
// — one fetch-compile cycle serves them all. The point list must be
// non-empty (a driver factory opens at least one). The update interval
// is clamped to MinInterval, warning the operator when it is.
func New(f *Fetcher, points []firewall.Point, p Policy, interval time.Duration, log zerolog.Logger) (*Updater, error) {
	if len(points) == 0 {
		return nil, errors.New("enforcement points: at least one required")
	}
	interval, clamped := ClampInterval(interval)
	if clamped {
		log.Warn().Dur("interval", interval).Msg("update interval clamped to the one-minute floor")
	}
	return &Updater{fetcher: f, points: points, policy: p, log: log, interval: interval}, nil
}

// Update runs one update cycle: fetch the report document, compile its
// live reports into ban rules and hand them to every enforcement
// point's driver — one fetch-compile serves them all. Each point is
// reached and failed independently; on error the last installed rules
// stay and nothing more installs, and the returned skips are the
// report records left out of the compilation.
func (u *Updater) Update(ctx context.Context) ([]Skip, error) {
	rules, skips, err := u.load(ctx)
	if err != nil {
		return nil, err
	}
	if err := u.applyAll(rules); err != nil {
		return skips, fmt.Errorf("install: %w", err)
	}
	return skips, nil
}

// applyAll hands the compiled ruleset to every enforcement point's
// driver and logs what each reports. Every point is independent: an
// unreachable one is warned and skipped for the cycle while the
// others still install — one dead container cannot halt enforcement
// everywhere — and a real failure is loud after every point has been
// tried, so missing netlink privileges surface at the startup
// install. Whether an unchanged ruleset skips is each driver's own
// decision; the engine only reports it.
func (u *Updater) applyAll(rules []firewall.BanRule) error {
	var failed []error
	for _, point := range u.points {
		name := point.Label
		out, err := point.Driver.Apply(rules)
		switch {
		case u.skipUnreachable(err, name, "enforcement point unreachable; skipping for the cycle"):
			continue
		case err != nil:
			failed = append(failed, fmt.Errorf("point %s: %w", name, err))
			continue
		}
		hash := fmt.Sprintf("%x", out.Hash)
		if out.Skipped {
			// A skipped cycle logs the skip and no hits.
			u.log.Info().Str("point", name).Str("hash", hash).Msg("ban rules unchanged; skipping install")
		} else {
			// The nonzero counters of the rules just replaced — the
			// replaced ruleset's indices (the previous apply's input
			// rules), covering what the enforcement did since the last
			// change.
			for _, h := range out.Hits {
				u.log.Info().
					Str("point", name).
					Int("rule", h.Rule).
					Uint64("packets", h.Packets).
					Uint64("bytes", h.Bytes).
					Msg("ban rule hit in the replaced ruleset")
			}
			u.log.Info().Str("point", name).Int("rules", len(rules)).Int("declined", len(out.Declined)).Str("hash", hash).Msg("installed ban rules")
		}
		// Declined features are lost enforcement — logged and counted
		// per rule and feature, never silently dropped.
		for _, d := range out.Declined {
			u.log.Warn().
				Str("point", name).
				Int("rule", d.Rule).
				Str("feature", d.Feature).
				Str("reason", d.Reason).
				Msg("declined ban rule feature")
		}
	}
	return errors.Join(failed...)
}

// skipUnreachable classifies one enforcement point's failure: an
// unreachable one (firewall.ErrUnreachable — its handle cannot be
// opened) is warned with msg and swallowed, so the point is skipped
// for the cycle or tolerated at reset and one dead container cannot
// halt enforcement everywhere or spoil a clean shutdown. Any other
// failure is left to the caller's loud path. It reports whether the
// failure was swallowed.
func (u *Updater) skipUnreachable(err error, name, msg string) bool {
	if !errors.Is(err, firewall.ErrUnreachable) {
		return false
	}
	u.log.Warn().Err(err).Str("point", name).Msg(msg)
	return true
}

// resetAll removes the installed ruleset from every enforcement point,
// tolerating points that vanished meanwhile: an unreachable one is
// warned and skipped at exit too, so a dead container cannot spoil a
// clean shutdown. Any other reset failure is loud after every point
// has been tried.
func (u *Updater) resetAll() error {
	var failed []error
	for _, point := range u.points {
		err := point.Driver.Reset()
		if err == nil {
			continue
		}
		if u.skipUnreachable(err, point.Label, "enforcement point unreachable at reset; tolerating") {
			continue
		}
		failed = append(failed, fmt.Errorf("point %s: %w", point.Label, err))
	}
	return errors.Join(failed...)
}

// DryRun runs one fetch-compile cycle and writes the engine's compiled
// ban rules to w as indented JSON, then the selected driver's plan —
// one line per effective rule with its placement and rate, the
// declines with reasons, and the ruleset hash line — instead of
// installing them: the plan comes from the pure planning step only, no
// enforcement surface is touched and no privileges are needed.
// Skipped records are logged like any cycle.
func (u *Updater) DryRun(ctx context.Context, w io.Writer) error {
	rules, _, err := u.load(ctx)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rules); err != nil {
		return err
	}
	for _, point := range u.points {
		plan, err := point.Driver.Plan(rules)
		if err != nil {
			return fmt.Errorf("plan: %w", err)
		}
		if len(u.points) > 1 {
			// One plan per enforcement point; with a single point the
			// plan stands bare.
			if _, err := fmt.Fprintf(w, "point=%s\n", point.Label); err != nil {
				return err
			}
		}
		if err := writePlan(w, plan); err != nil {
			return err
		}
	}
	return nil
}

// writePlan renders one driver's plan: one line per effective rule —
// its stance, rate and placement — then the declines with reasons,
// then the ruleset hash line.
func writePlan(w io.Writer, plan firewall.Plan) error {
	for _, pr := range plan.Rules {
		rate := "-"
		if pr.Rate != nil {
			rate = strconv.FormatInt(*pr.Rate, 10)
		}
		placement := pr.Placement
		if placement == "" {
			placement = "-"
		}
		if _, err := fmt.Fprintf(w, "stance=%s rate=%s placement=%s\n", pr.Stance, rate, placement); err != nil {
			return err
		}
	}
	for _, d := range plan.Declined {
		if _, err := fmt.Fprintf(w, "declined rule=%d feature=%s reason=%s\n", d.Rule, d.Feature, d.Reason); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "hash=%x\n", plan.Hash)
	return err
}

// load fetches and compiles one report document, logging every skipped
// report record and the cycle's counts, and returning the compiled
// ruleset. The ruleset hash is the driver's own — each driver folds its
// effective rules — so the engine computes none.
func (u *Updater) load(ctx context.Context) ([]firewall.BanRule, []Skip, error) {
	data, err := u.fetcher.Fetch(ctx)
	if err != nil {
		return nil, nil, err
	}
	doc, err := ParseDocument(data)
	if err != nil {
		return nil, nil, err
	}
	rules, skips := Compile(doc, u.policy)
	for _, s := range skips {
		u.log.Warn().
			Str("rule", s.Rule).
			Str("target", s.Target).
			Str("reason", s.Reason).
			Msg("skipped report record")
	}
	u.log.Info().
		Int("reports", len(doc.Reports)).
		Int("rules", len(rules)).
		Int("skipped", len(skips)).
		Msg("compiled ban rules")
	return rules, skips, nil
}

// Run performs the startup test install and then one update per tick
// until ctx is done (SIGINT/SIGTERM for the binary), resetting the
// driver before it returns. A startup failure is returned to the
// caller, which exits non-zero; later failures only log loudly and the
// last installed rules stay.
func (u *Updater) Run(ctx context.Context) error {
	if _, err := u.Update(ctx); err != nil {
		// fluxc: clear any half-installed ruleset before exiting non-zero.
		if rerr := u.resetAll(); rerr != nil {
			u.log.Error().Err(rerr).Msg("reset after failed startup test install failed")
		}
		return fmt.Errorf("startup test install: %w", err)
	}
	u.log.Info().Msg("startup test install ok")

	ticks := u.ticks
	if ticks == nil {
		ticker := time.NewTicker(u.interval)
		defer ticker.Stop()
		ticks = ticker.C
	}
	for {
		select {
		case <-ctx.Done():
			if err := u.resetAll(); err != nil {
				return fmt.Errorf("reset: %w", err)
			}
			u.log.Info().Msg("reset and exit")
			return nil
		case <-ticks:
			if _, err := u.Update(ctx); err != nil {
				u.log.Error().Err(err).Msg("update failed; keeping last installed rules")
			}
		}
	}
}
