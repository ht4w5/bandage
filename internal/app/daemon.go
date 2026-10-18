package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"

	bandage "github.com/HT4w5/bandage/internal/domain"
	"github.com/HT4w5/bandage/internal/domain/enrichment"
	"github.com/HT4w5/bandage/internal/domain/evaluation"
	"github.com/HT4w5/bandage/internal/domain/report"
	"github.com/HT4w5/bandage/internal/identity"
	"github.com/HT4w5/bandage/internal/infra/cache/memory"
	"github.com/HT4w5/bandage/internal/infra/httpapi"
	"github.com/HT4w5/bandage/internal/infra/ingest/syslog"
	nginxparser "github.com/HT4w5/bandage/internal/infra/parse/nginx"
	"github.com/HT4w5/bandage/internal/infra/persistence/sqlite"
)

// sweepInterval is the internal cadence of the tracker cache expiry
// sweep, the expired-report sweeper and the periodic statistics log.
const sweepInterval = time.Minute

// File-size enrichment parameters (DECISIONS §3): the EWMA smoothing
// window (alpha = 1/period) and the warm-up sample gate. Internal
// constants — the spec's config surface has no enrichment knobs.
const (
	filesizePeriod     = 5
	filesizeMinSamples = 5
)

// EventParser is the parser port beside its consumer: one raw log line in,
// one domain Event out (or an error, which drops and counts the line).
type EventParser interface {
	Parse(line []byte) (bandage.Event, error)
}

// counters is the drop accounting behind the pipeline block: logged
// periodically and served in /stats (DECISIONS §6, ADR 0006). It and
// its accessor are unexported: the only readers are the Daemon's Stats
// snapshot and in-package tests — no exported API exists solely for
// tests.
type counters struct {
	Received int64 // raw lines received from the wire
	Parsed   int64 // lines parsed into events
	Dropped  int64 // malformed or invalid lines dropped
}

type options struct {
	now    func() time.Time
	logger zerolog.Logger
	store  reportStore
}

// Option configures the daemon wiring.
type Option func(*options)

// WithClock injects the wall clock (report timestamps and cache expiry).
func WithClock(now func() time.Time) Option {
	return func(o *options) { o.now = now }
}

// WithLogger injects the program-wide logger: the command passes the
// one logger built from config (ADR 0005), and tests capture records
// through the same injection point (spec: Log capture) — the daemon's
// logging is the contract for evictions and log actions.
func WithLogger(l zerolog.Logger) Option {
	return func(o *options) { o.logger = l }
}

// reportStore is the daemon's report persistence: the domain report
// port plus Close. The sqlite adapter satisfies it. The raw store sits
// behind the report service: every report mutation goes through the
// service, and the daemon holds the store itself for Close (and for the
// direct reads in tests and benchmarks).
type reportStore interface {
	report.Repository
	Close() error
}

// withStore substitutes the report store. It is unexported like every
// test-only seam: the binary always wires sqlite; tests substitute a
// store to keep a write in flight and observe shutdown with the store
// wedged.
func withStore(s reportStore) Option {
	return func(o *options) { o.store = s }
}

// Daemon is the assembled analyzer: syslog ingest → nginx JSON parser →
// file-size enrichment → evaluation → report service → sqlite, served
// over HTTP.
type Daemon struct {
	cfg     Config
	chains  []bandage.Chain
	now     func() time.Time
	logger  zerolog.Logger
	parser  EventParser
	enrich  *enrichment.FilesizeEnricher
	workers int

	// repo is the raw report store, kept for Close; report mutations go
	// through reports (the report service).
	repo    reportStore
	reports *report.Service
	cache   *memory.Store
	eval    *evaluation.Service
	src     *syslog.Source
	apiSrv  *http.Server
	apiLn   net.Listener

	// ctx/cancel is the daemon-lifetime context threaded through the
	// pipeline and sweeper; cancel is the bounded-shutdown backstop.
	ctx    context.Context
	cancel context.CancelFunc

	lines     chan string
	processed *progress
	startedAt time.Time
	received  atomic.Int64
	parsed    atomic.Int64
	dropped   atomic.Int64

	stopSweep chan struct{}
	wg        sync.WaitGroup
	once      sync.Once
	shutdown  error
}

// New assembles the daemon. Config must already be validated (strictly
// decoded before any socket opens); the worker count must be at least
// 1 (spec story 16).
func New(cfg Config, chains []bandage.Chain, opts ...Option) (*Daemon, error) {
	if cfg.Pipeline.Workers < 1 {
		return nil, fmt.Errorf("app: pipeline.workers must be at least 1 (got %d)", cfg.Pipeline.Workers)
	}
	var o options
	WithClock(time.Now)(&o)
	// The default logger is built from config like the program-wide one
	// (ADR 0005); the command passes its flag-adjusted instance and
	// tests pass their capture.
	o.logger = NewLogger(os.Stderr, cfg.Log.Level)
	for _, opt := range opts {
		opt(&o)
	}

	var repo reportStore = o.store
	if repo == nil {
		r, err := sqlite.Open(cfg.DB.SQLite.Path)
		if err != nil {
			return nil, err
		}
		repo = r
	}
	cache := memory.New(cfg.Cache.MaxEntries, o.now, o.logger)
	reports := report.NewService(repo)
	enricher, err := enrichment.NewFilesizeEnricher(memory.NewFilesize(cache), filesizePeriod, filesizeMinSamples)
	if err != nil {
		return nil, err
	}

	d := &Daemon{
		cfg:       cfg,
		chains:    chains,
		now:       o.now,
		logger:    o.logger,
		parser:    nginxparser.New(),
		enrich:    enricher,
		workers:   cfg.Pipeline.Workers,
		repo:      repo,
		reports:   reports,
		cache:     cache,
		eval:      evaluation.NewService(chains, cache, reports, o.now, domainLogger{o.logger}),
		lines:     make(chan string),
		processed: newProgress(),
		stopSweep: make(chan struct{}),
	}
	d.apiSrv = &http.Server{Handler: httpapi.New(reports, d, o.now)}
	return d, nil
}

// Start opens the ingest and API listeners and starts the pipeline:
// one pipeline goroutine per configured worker reading the ingest line
// channel, plus the sweeper (flux-engine style). lifetime spans the
// daemon's run — the pipeline and sweeper thread it through every call
// in place of ad-hoc background contexts. Its cancellation is the
// daemon's bounded-shutdown backstop, so the work context is detached
// from the caller's: a SIGINT/SIGTERM starts the graceful drain in
// Shutdown, never an abort of in-flight work (spec: Daemon context).
func (d *Daemon) Start(lifetime context.Context) error {
	d.ctx, d.cancel = context.WithCancel(context.WithoutCancel(lifetime))
	d.startedAt = d.now()
	// Suppression state is re-derived from the report table at startup
	// (spec story 13, ADR 0008): alive reports suppress the next
	// Trigger's write, deleted or expired ones do not.
	if err := d.reports.Rebuild(d.ctx, d.now()); err != nil {
		return fmt.Errorf("reports: rebuild live-report set: %w", err)
	}
	// The startup record names the running build: the log stream itself
	// identifies what is deployed (spec story 14).
	d.logger.Info().
		Str("name", identity.Name).
		Str("version", identity.Version()).
		Str("commit", identity.Commit()).
		Str("build_date", identity.BuildDate()).
		Msg("starting")
	d.src = syslog.New(d.cfg.Ingest.Syslog.Network, d.cfg.Ingest.Syslog.Listen, d.lines, d.logger)
	if err := d.src.Start(); err != nil {
		return err
	}

	ln, err := net.Listen("tcp", d.cfg.API.Listen)
	if err != nil {
		d.src.Shutdown()
		return fmt.Errorf("api: listen %s: %w", d.cfg.API.Listen, err)
	}
	d.apiLn = ln

	d.wg.Add(d.workers + 1)
	for range d.workers {
		go d.runPipeline()
	}
	go d.sweep()
	go func() {
		if err := d.apiSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			d.logger.Error().Err(err).Msg("api server stopped")
		}
	}()
	d.logger.Info().Str("addr", ln.Addr().String()).Msg("api started")
	return nil
}

// runPipeline parses, enriches and evaluates raw lines; one goroutine
// per worker runs it. Bad lines are dropped and counted.
func (d *Daemon) runPipeline() {
	defer d.wg.Done()
	for line := range d.lines {
		d.received.Add(1)
		ev, err := d.parser.Parse([]byte(line))
		if err != nil {
			d.dropped.Add(1)
			d.logger.Warn().Err(err).Msg("dropping bad log line")
			d.processed.bump()
			continue
		}
		d.parsed.Add(1)
		if err := d.enrich.Enrich(d.ctx, &ev); err != nil {
			d.logger.Error().Err(err).Msg("enrich event")
		}
		if err := d.eval.Evaluate(d.ctx, &ev); err != nil {
			d.logger.Error().Err(err).Msg("evaluate event")
		}
		d.processed.bump()
	}
}

// sweep periodically expires tracker cache entries, logs the periodic
// statistics line (drop accounting and cache stats, DECISIONS §6) and
// deletes expired reports.
func (d *Daemon) sweep() {
	defer d.wg.Done()
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-d.stopSweep:
			return
		case <-t.C:
			d.cache.SweepExpired()
			d.logStatistics()
			n, err := d.sweepOnce(d.ctx)
			if err != nil {
				d.logger.Error().Err(err).Msg("sweep expired reports")
				continue
			}
			if n > 0 {
				d.logger.Info().Int("count", n).Msg("swept expired reports")
			}
		}
	}
}

// logStatistics emits the periodic statistics record (DECISIONS §6):
// drop accounting and cache statistics under their long-standing field
// names. It renders from the same Stats snapshot /stats serves, so the
// two always agree; the sweep ticker calls it at the internal cadence
// and tests drive it directly (like sweepOnce), never by sleeping.
func (d *Daemon) logStatistics() {
	s := d.Stats()
	d.logger.Info().
		Int64("received", s.Pipeline.Received).Int64("parsed", s.Pipeline.Parsed).Int64("dropped", s.Pipeline.Dropped).
		Int64("cache_gets", s.TrackerCache.Gets).Int64("cache_sets", s.TrackerCache.Sets).Int64("cache_misses", s.TrackerCache.Misses).
		Int64("cache_evictions", s.TrackerCache.Evictions).Int64("cache_size", s.TrackerCache.Size).
		Msg("statistics")
}

// sweepOnce runs one sweeper pass: it deletes expired reports through
// the report service at the injected wall clock and returns the number
// of deleted rows. The periodic sweeper calls it once per tick; tests
// drive a pass directly, so expiry behavior needs no sleeping.
func (d *Daemon) sweepOnce(ctx context.Context) (int, error) {
	return d.reports.DeleteExpired(ctx, d.now())
}

// Shutdown drains the pipeline and closes every resource, in that
// order: the ingest stops, the line channel closes and the workers
// finish the events already in flight — their report upserts complete
// — before the resources close. Shutdown is bounded by the caller's
// deadline even if a store call never returns: only when ctx expires
// does the daemon cancel the lifetime context to abort stragglers and
// return without waiting for them (spec: Daemon context). The lifetime
// context is cancelled either way before Shutdown returns, so none
// leaks. Idempotent.
func (d *Daemon) Shutdown(ctx context.Context) error {
	d.once.Do(func() {
		// Context hygiene: the lifetime context is cancelled before
		// Shutdown returns — after the drain on the clean path, as the
		// bounded backstop on the deadline path — so no live context
		// outlives the daemon.
		defer d.cancel()
		done := make(chan error, 1)
		go func() {
			var err error
			if serr := d.src.Shutdown(); serr != nil {
				err = errors.Join(err, serr)
			}
			close(d.stopSweep)
			close(d.lines)
			d.wg.Wait()
			if serr := d.apiSrv.Shutdown(ctx); serr != nil {
				err = errors.Join(err, serr)
			}
			if cerr := d.repo.Close(); cerr != nil {
				err = errors.Join(err, cerr)
			}
			done <- err
		}()
		select {
		case err := <-done:
			d.shutdown = err
		case <-ctx.Done():
			// Bounded backstop: the deadline expired with stragglers
			// still in flight (e.g. a store call that never returns).
			// Cancel the lifetime context to abort them and return
			// without waiting; the drain goroutine finishes them off.
			d.cancel()
			d.shutdown = ctx.Err()
		}
	})
	return d.shutdown
}

// apiAddr is the bound API listen address (host:port), read by
// in-package tests through the HTTP API.
func (d *Daemon) apiAddr() string {
	if d.apiLn == nil {
		return ""
	}
	return d.apiLn.Addr().String()
}

// waitProcessed blocks until n raw lines have been fully processed
// (parsed and evaluated, or dropped) or ctx is done. It is the in-package
// test driver for the pipeline; the binary never waits on it.
func (d *Daemon) waitProcessed(ctx context.Context, n int64) error {
	return d.processed.wait(ctx, n)
}

// counters returns the drop accounting counters — the internal
// accessor, distinct from the exported Stats snapshot it feeds.
func (d *Daemon) counters() counters {
	return counters{
		Received: d.received.Load(),
		Parsed:   d.parsed.Load(),
		Dropped:  d.dropped.Load(),
	}
}

// Stats assembles the /stats snapshot (httpapi.StatsSource, satisfied
// structurally): the build identity module, the cumulative pipeline
// counters and the tracker cache statistics, all since start. The
// periodic statistics log line renders from the same snapshot, so its
// counters always agree with /stats.
func (d *Daemon) Stats() httpapi.Stats {
	c := d.counters()
	cs := d.cache.Statistics()
	return httpapi.Stats{
		StartedAt: d.startedAt,
		Build: httpapi.Build{
			Name:      identity.Name,
			Version:   identity.Version(),
			Commit:    identity.Commit(),
			BuildDate: identity.BuildDate(),
			Dirty:     identity.Dirty(),
			GoVersion: identity.GoVersion(),
			Platform:  identity.Platform(),
		},
		Pipeline: httpapi.Pipeline{
			Workers:  d.workers,
			Received: c.Received,
			Parsed:   c.Parsed,
			Dropped:  c.Dropped,
		},
		TrackerCache: httpapi.TrackerCache{
			Gets:      cs.Gets,
			Sets:      cs.Sets,
			Misses:    cs.Misses,
			Evictions: cs.Evictions,
			Size:      cs.Size,
			EntryCap:  cs.EntryCap,
		},
	}
}

// progress counts processed lines and wakes waiters (no polling, no
// sleeps).
type progress struct {
	mu sync.Mutex
	n  int64
	ch chan struct{}
}

func newProgress() *progress {
	return &progress{ch: make(chan struct{})}
}

func (p *progress) bump() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.n++
	close(p.ch)
	p.ch = make(chan struct{})
}

func (p *progress) wait(ctx context.Context, n int64) error {
	for {
		p.mu.Lock()
		if p.n >= n {
			p.mu.Unlock()
			return nil
		}
		ch := p.ch
		p.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
