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

// Updater runs the fetch-compile-install update cycle against one
// firewall driver per target namespace — fluxc's lifecycle: one
// startup test install before the loop, the last installed rules kept
// on a failed cycle, and a reset on clean exit. One fetch-compile
// serves every namespace.
type Updater struct {
	fetcher  *Fetcher
	targets  []*nsState
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
	Driver Driver
}

// name is the operator-facing namespace name in logs and warnings.
func (n Namespace) name() string {
	if n.Path == "" {
		return "current"
	}
	return n.Path
}

// nsState is one namespace's cycle state: where to install, plus the
// identity of the ruleset last installed there — the compiled
// ruleset's rolling hash. The skip compares that hash per namespace
// and still probes that the table exists (freshly, every cycle), so a
// recreated container or an external reset cannot hide behind an
// unchanged hash.
type nsState struct {
	Namespace

	// hash is the rolling hash of the ruleset last installed here;
	// installed marks that an install has succeeded (the zero hash is
	// a legal hash, so presence is its own flag).
	hash      uint32
	installed bool
}

// unchanged reports whether hash is the rolling hash of the ruleset
// last installed for this namespace — the skip-if-unchanged
// comparison. (The ruleset-equality stand-in is gone: the rolling hash
// is the compiled ruleset's identity.)
func (s *nsState) unchanged(hash uint32) bool {
	return s.installed && s.hash == hash
}

// setInstalled records hash as this namespace's last installed
// ruleset identity.
func (s *nsState) setInstalled(hash uint32) {
	s.hash, s.installed = hash, true
}

// New assembles an Updater over a single driver — the default shape,
// enforcing in one namespace. The update interval is clamped to
// MinInterval, warning the operator when it is.
func New(f *Fetcher, d Driver, p Policy, interval time.Duration, log zerolog.Logger) *Updater {
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
	targets := make([]*nsState, 0, len(namespaces))
	for _, ns := range namespaces {
		targets = append(targets, &nsState{Namespace: ns})
	}
	return &Updater{fetcher: f, targets: targets, policy: p, log: log, interval: interval}
}

// Update runs one update cycle: fetch the report document, compile its
// live reports into ban rules and install them into every target
// namespace — one fetch-compile serves them all. Each namespace is
// reached and failed independently; on error the last installed rules
// stay and nothing more installs, and the returned skips are the
// report records left out of the compilation.
func (u *Updater) Update(ctx context.Context) ([]Skip, error) {
	rules, skips, hash, err := u.load(ctx)
	if err != nil {
		return nil, err
	}
	if err := u.installAll(rules, hash); err != nil {
		return skips, fmt.Errorf("install: %w", err)
	}
	return skips, nil
}

// installAll installs one compiled ruleset into every target
// namespace. Every namespace is independent: an unreachable one is
// warned and skipped for the cycle while the others still install —
// one dead container cannot halt enforcement everywhere — and a real
// install failure is loud after every namespace has been tried, so
// missing netlink privileges surface at the startup install.
// Unchanged rules skip the reinstall per namespace, provided the
// namespace's table still exists (probed fresh every cycle).
func (u *Updater) installAll(rules []BanRule, hash uint32) error {
	var failed []error
	for _, target := range u.targets {
		name := target.name()
		if target.unchanged(hash) {
			exists, err := target.Driver.TableExists()
			switch {
			case errors.Is(err, ErrUnreachable):
				u.log.Warn().Err(err).Str("netns", name).Msg("namespace unreachable; skipping for the cycle")
				continue
			case err == nil && exists:
				// Known limit: the probe is existence, not rule bodies
				// — tampering with the rules under a surviving table is
				// undetected.
				u.log.Info().Str("netns", name).Str("hash", fmt.Sprintf("%x", hash)).Msg("ban rules unchanged; skipping install")
				continue
			}
			// A probe that could not decide is answered by installing:
			// only a table known to exist may skip.
		}
		hits, err := target.Driver.Install(rules)
		if err == nil {
			target.setInstalled(hash)
			// The nonzero counters of the rules just replaced — what the
			// enforcement did since the last change.
			for _, h := range hits {
				u.log.Info().
					Str("netns", name).
					Int("rule", h.Rule).
					Uint64("packets", h.Packets).
					Uint64("bytes", h.Bytes).
					Msg("ban rule hit")
			}
			u.log.Info().Str("netns", name).Int("rules", len(rules)).Msg("installed ban rules")
			continue
		}
		if errors.Is(err, ErrUnreachable) {
			u.log.Warn().Err(err).Str("netns", name).Msg("namespace unreachable; skipping for the cycle")
			continue
		}
		failed = append(failed, fmt.Errorf("netns %s: %w", name, err))
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
		if errors.Is(err, ErrUnreachable) {
			u.log.Warn().Err(err).Str("netns", target.name()).Msg("namespace unreachable at reset; tolerating")
			continue
		}
		failed = append(failed, fmt.Errorf("netns %s: %w", target.name(), err))
	}
	return errors.Join(failed...)
}

// DryRun runs one fetch-compile cycle and writes the compiled ban rules
// to w as indented JSON, then one mapping line per ban rule — stance,
// rate and chain (the contract's penalty → nftables mapping) — and the
// ruleset hash line, instead of installing them: no firewall driver, no
// netlink, no privileges. Skipped records are logged like any cycle.
func (u *Updater) DryRun(ctx context.Context, w io.Writer) error {
	rules, _, hash, err := u.load(ctx)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rules); err != nil {
		return err
	}
	for _, r := range rules {
		rate := "-"
		if r.Rate != nil {
			rate = strconv.FormatInt(*r.Rate, 10)
		}
		if _, err := fmt.Fprintf(w, "stance=%s rate=%s chain=%s\n", r.Stance, rate, r.Stance.Chain()); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(w, "hash=%x\n", hash)
	return err
}

// load fetches and compiles one report document, logging the ruleset
// hash (every cycle), every skipped report record and the cycle's
// counts, and returning the compiled ruleset with its rolling hash.
func (u *Updater) load(ctx context.Context) ([]BanRule, []Skip, uint32, error) {
	data, err := u.fetcher.Fetch(ctx)
	if err != nil {
		return nil, nil, 0, err
	}
	doc, err := ParseDocument(data)
	if err != nil {
		return nil, nil, 0, err
	}
	rules, skips := Compile(doc, u.policy)
	for _, s := range skips {
		u.log.Warn().
			Str("rule", s.Rule).
			Str("target", s.Target).
			Str("reason", s.Reason).
			Msg("skipped report record")
	}
	hash := Hash(rules)
	u.log.Info().
		Int("reports", len(doc.Reports)).
		Int("rules", len(rules)).
		Int("skipped", len(skips)).
		Str("hash", fmt.Sprintf("%x", hash)).
		Msg("compiled ban rules")
	return rules, skips, hash, nil
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
