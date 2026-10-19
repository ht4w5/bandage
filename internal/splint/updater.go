package splint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
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
// per-namespace installed state that follows each namespace.
type nsState struct {
	Namespace

	// installed is the ruleset last installed here — the
	// per-namespace installed-state slot. Ticket 06 fills it with the
	// compiled ruleset's rolling hash (and the table-existence probe
	// that keeps a recreated container from hiding behind it); until
	// then the slot holds the ruleset itself and unchanged compares
	// that, so quiet cycles skip the reinstall per namespace.
	installed []BanRule
}

// unchanged reports whether rules match the last installed ruleset
// for this namespace.
func (t *nsState) unchanged(rules []BanRule) bool {
	return t.installed != nil && rulesEqual(t.installed, rules)
}

// setInstalled records rules as this namespace's last installed
// ruleset (ticket 06 records its hash instead).
func (t *nsState) setInstalled(rules []BanRule) {
	t.installed = slices.Clone(rules)
}

// rulesEqual reports whether two compiled rulesets are identical —
// the minimal stand-in for ticket 06's rolling-hash comparison.
func rulesEqual(a, b []BanRule) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Stance != b[i].Stance || !slices.Equal(a[i].Targets, b[i].Targets) {
			return false
		}
	}
	return true
}

// New assembles an Updater over a single driver — the default shape,
// enforcing in one namespace. The update interval is clamped to
// MinInterval, warning the operator when it is.
func New(f *Fetcher, d Driver, interval time.Duration, log zerolog.Logger) *Updater {
	return newUpdater(f, []Namespace{{Driver: d}}, interval, log)
}

// NewForNamespaces assembles an Updater installing into one target
// namespace per entry: one fetch-compile cycle serves them all. The
// namespace list must be non-empty.
func NewForNamespaces(f *Fetcher, namespaces []Namespace, interval time.Duration, log zerolog.Logger) (*Updater, error) {
	if len(namespaces) == 0 {
		return nil, errors.New("namespaces: at least one required")
	}
	return newUpdater(f, namespaces, interval, log), nil
}

// newUpdater assembles an Updater over the resolved namespace list.
// The update interval is clamped to MinInterval, warning the operator
// when it is.
func newUpdater(f *Fetcher, namespaces []Namespace, interval time.Duration, log zerolog.Logger) *Updater {
	interval, clamped := ClampInterval(interval)
	if clamped {
		log.Warn().Dur("interval", interval).Msg("update interval clamped to the one-minute floor")
	}
	targets := make([]*nsState, 0, len(namespaces))
	for _, ns := range namespaces {
		targets = append(targets, &nsState{Namespace: ns})
	}
	return &Updater{fetcher: f, targets: targets, log: log, interval: interval}
}

// Update runs one update cycle: fetch the report document, compile its
// live reports into ban rules and install them into every target
// namespace — one fetch-compile serves them all. Each namespace is
// reached and failed independently; on error the last installed rules
// stay and nothing more installs, and the returned skips are the
// report records left out of the compilation.
func (u *Updater) Update(ctx context.Context) ([]Skip, error) {
	rules, skips, err := u.load(ctx)
	if err != nil {
		return nil, err
	}
	if err := u.installAll(rules); err != nil {
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
// Unchanged rules skip the reinstall per namespace.
func (u *Updater) installAll(rules []BanRule) error {
	var failed []error
	for _, t := range u.targets {
		name := t.name()
		if t.unchanged(rules) {
			u.log.Info().Str("netns", name).Msg("ban rules unchanged; skipping install")
			continue
		}
		err := t.Driver.Install(rules)
		if err == nil {
			t.setInstalled(rules)
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
	for _, t := range u.targets {
		err := t.Driver.Reset()
		if err == nil {
			continue
		}
		if errors.Is(err, ErrUnreachable) {
			u.log.Warn().Err(err).Str("netns", t.name()).Msg("namespace unreachable at reset; tolerating")
			continue
		}
		failed = append(failed, fmt.Errorf("netns %s: %w", t.name(), err))
	}
	return errors.Join(failed...)
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
	rules, skips := Compile(doc)
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
