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

// Updater runs the fetch-compile-apply update cycle against one
// firewall driver per target namespace — fluxc's lifecycle: one
// startup test install before the loop, the last installed rules kept
// on a failed cycle, and a reset on clean exit. One fetch-compile
// serves every namespace. The engine carries no hash, probe, skip or
// counter logic: each driver owns its identity and the engine just
// logs what the driver reports — applied, or unchanged-skip with the
// hash, the nonzero hits since the last change, and declines.
type Updater struct {
	fetcher  *Fetcher
	targets  []Namespace
	policy   Policy
	log      zerolog.Logger
	interval time.Duration

	// ticks feeds the update loop in tests; nil means a real ticker.
	ticks <-chan time.Time
}

// Namespace is one network namespace to enforce in: the nsfs handle
// path whose netlink the driver installs through, plus the driver
// itself. The empty path is the current namespace — the default
// target. The handle path is re-opened on every driver call (a
// recreated container is picked up through its stable handle), never
// held across cycles.
type Namespace struct {
	Path   string
	Driver firewall.Driver
}

// name is the operator-facing namespace name in logs and warnings.
func (n Namespace) name() string {
	if n.Path == "" {
		return "current"
	}
	return n.Path
}

// New assembles an Updater over a single driver — the default shape,
// enforcing in one namespace. The update interval is clamped to
// MinInterval, warning the operator when it is.
func New(f *Fetcher, d firewall.Driver, p Policy, interval time.Duration, log zerolog.Logger) *Updater {
	return newUpdater(f, []Namespace{{Driver: d}}, p, interval, log)
}

// NewForNamespaces assembles an Updater installing into one target
// namespace per entry: one fetch-compile cycle serves them all. The
// namespace list must be non-empty.
func NewForNamespaces(f *Fetcher, namespaces []Namespace, p Policy, interval time.Duration, log zerolog.Logger) (*Updater, error) {
	if len(namespaces) == 0 {
		return nil, errors.New("namespaces: at least one required")
	}
	return newUpdater(f, namespaces, p, interval, log), nil
}

// newUpdater assembles an Updater over the resolved namespace list.
// The update interval is clamped to MinInterval, warning the operator
// when it is.
func newUpdater(f *Fetcher, namespaces []Namespace, p Policy, interval time.Duration, log zerolog.Logger) *Updater {
	interval, clamped := ClampInterval(interval)
	if clamped {
		log.Warn().Dur("interval", interval).Msg("update interval clamped to the one-minute floor")
	}
	return &Updater{fetcher: f, targets: namespaces, policy: p, log: log, interval: interval}
}

// Update runs one update cycle: fetch the report document, compile its
// live reports into ban rules and hand them to every target's driver —
// one fetch-compile serves them all. Each namespace is reached and
// failed independently; on error the last installed rules stay and
// nothing more installs, and the returned skips are the report records
// left out of the compilation.
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

// applyAll hands the compiled ruleset to every target's driver and
// logs what each reports. Every namespace is independent: an
// unreachable one is warned and skipped for the cycle while the others
// still install — one dead container cannot halt enforcement
// everywhere — and a real failure is loud after every namespace has
// been tried, so missing netlink privileges surface at the startup
// install. Whether an unchanged ruleset skips is each driver's own
// decision; the engine only reports it.
func (u *Updater) applyAll(rules []firewall.BanRule) error {
	var failed []error
	for _, target := range u.targets {
		name := target.name()
		out, err := target.Driver.Apply(rules)
		switch {
		case errors.Is(err, firewall.ErrUnreachable):
			u.log.Warn().Err(err).Str("netns", name).Msg("namespace unreachable; skipping for the cycle")
			continue
		case err != nil:
			failed = append(failed, fmt.Errorf("netns %s: %w", name, err))
			continue
		}
		hash := fmt.Sprintf("%x", out.Hash)
		if out.Skipped {
			// A skipped cycle logs the skip and no hits.
			u.log.Info().Str("netns", name).Str("hash", hash).Msg("ban rules unchanged; skipping install")
		} else {
			// The nonzero counters of the rules just replaced — what the
			// enforcement did since the last change.
			for _, h := range out.Hits {
				u.log.Info().
					Str("netns", name).
					Int("rule", h.Rule).
					Uint64("packets", h.Packets).
					Uint64("bytes", h.Bytes).
					Msg("ban rule hit")
			}
			u.log.Info().Str("netns", name).Int("rules", len(rules)).Int("declined", len(out.Declined)).Str("hash", hash).Msg("installed ban rules")
		}
		// Declined features are lost enforcement — logged and counted
		// per rule and feature, never silently dropped.
		for _, d := range out.Declined {
			u.log.Warn().
				Str("netns", name).
				Int("rule", d.Rule).
				Str("feature", d.Feature).
				Str("reason", d.Reason).
				Msg("declined ban rule feature")
		}
	}
	return errors.Join(failed...)
}

// resetAll removes the installed ruleset from every target namespace,
// tolerating namespaces that vanished meanwhile: an unreachable one
// is warned and skipped at exit too, so a dead container cannot spoil
// a clean shutdown. Any other reset failure is loud after every
// namespace has been tried.
func (u *Updater) resetAll() error {
	var failed []error
	for _, target := range u.targets {
		err := target.Driver.Reset()
		if err == nil {
			continue
		}
		if errors.Is(err, firewall.ErrUnreachable) {
			u.log.Warn().Err(err).Str("netns", target.name()).Msg("namespace unreachable at reset; tolerating")
			continue
		}
		failed = append(failed, fmt.Errorf("netns %s: %w", target.name(), err))
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
	for _, target := range u.targets {
		plan, err := target.Driver.Plan(rules)
		if err != nil {
			return fmt.Errorf("plan: %w", err)
		}
		if len(u.targets) > 1 {
			// One plan per target driver; with a single target the
			// plan stands bare.
			if _, err := fmt.Fprintf(w, "netns=%s\n", target.name()); err != nil {
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
