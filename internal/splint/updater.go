package splint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/rs/zerolog"
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

// Updater runs the fetch-compile-install update cycle against a
// firewall driver — fluxc's lifecycle: one startup test install before
// the loop, the last installed rules kept on a failed cycle, and a
// reset on clean exit.
type Updater struct {
	fetcher  *Fetcher
	driver   Driver
	policy   Policy
	log      zerolog.Logger
	interval time.Duration

	// ticks feeds the update loop in tests; nil means a real ticker.
	ticks <-chan time.Time
}

// New assembles an Updater. The update interval is clamped to
// MinInterval, warning the operator when it is.
func New(f *Fetcher, d Driver, p Policy, interval time.Duration, log zerolog.Logger) *Updater {
	interval, clamped := ClampInterval(interval)
	if clamped {
		log.Warn().Dur("interval", interval).Msg("update interval clamped to the one-minute floor")
	}
	return &Updater{fetcher: f, driver: d, policy: p, log: log, interval: interval}
}

// Update runs one update cycle: fetch the report document, compile its
// live reports into ban rules and install them through the driver. On
// error the last installed rules stay and nothing installs; the
// returned skips are the report records left out of the compilation.
func (u *Updater) Update(ctx context.Context) ([]Skip, error) {
	rules, skips, err := u.load(ctx)
	if err != nil {
		return nil, err
	}
	if err := u.driver.Install(rules); err != nil {
		return skips, fmt.Errorf("install: %w", err)
	}
	u.log.Info().Int("rules", len(rules)).Msg("installed ban rules")
	return skips, nil
}

// DryRun runs one fetch-compile cycle and writes the compiled ban rules
// to w as indented JSON instead of installing them: no firewall driver,
// no netlink, no privileges. Skipped records are logged like any cycle.
func (u *Updater) DryRun(ctx context.Context, w io.Writer) error {
	rules, _, err := u.load(ctx)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rules)
}

// load fetches and compiles one report document, logging every skipped
// report record and the cycle's counts.
func (u *Updater) load(ctx context.Context) ([]BanRule, []Skip, error) {
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
		if rerr := u.driver.Reset(); rerr != nil {
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
			if err := u.driver.Reset(); err != nil {
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
