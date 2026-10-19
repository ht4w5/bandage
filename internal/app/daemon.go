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

// sweepInterval is the shared cadence of the cache and report expiry
// sweeps and the periodic statistics log.
const sweepInterval = time.Minute

// File-size enrichment parameters (DECISIONS section 3): EWMA window
// and warm-up sample gate. Not configurable by design.
const (
	filesizePeriod     = 5
	filesizeMinSamples = 5
)

// EventParser turns one raw log line into a domain Event; an error
// drops and counts the line.
type EventParser interface {
	Parse(line []byte) (bandage.Event, error)
}

// counters is the drop accounting behind the statistics log and
// /stats (DECISIONS section 6, ADR 0006).
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

// WithLogger injects the program-wide logger (ADR 0005).
func WithLogger(l zerolog.Logger) Option {
	return func(o *options) { o.logger = l }
}

// reportStore is the report repository plus Close. Report mutations go
// through the report service; the store itself is kept only for Close.
type reportStore interface {
	report.Repository
	Close() error
}

// withStore substitutes the report store (test-only seam).
func withStore(s reportStore) Option {
	return func(o *options) { o.store = s }
}

// Daemon is the assembled analyzer: syslog ingest -> parse -> enrich ->
// evaluate -> report -> sqlite, served over HTTP.
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

// New assembles the daemon from validated config; Pipeline.Workers must
// be at least 1.
func New(cfg Config, chains []bandage.Chain, opts ...Option) (*Daemon, error) {
	if cfg.Pipeline.Workers < 1 {
		return nil, fmt.Errorf("app: pipeline.workers must be at least 1 (got %d)", cfg.Pipeline.Workers)
	}
	var o options
	WithClock(time.Now)(&o)
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

// Start opens the listeners and starts the pipeline and sweeper.
// lifetime is detached from the caller's context; only Shutdown cancels it.
func (d *Daemon) Start(lifetime context.Context) error {
	d.ctx, d.cancel = context.WithCancel(context.WithoutCancel(lifetime))
	d.startedAt = d.now()
	// Rebuild must run before the workers start: suppression state
	// (ADR 0008) has to be complete before the first event evaluates.
	if err := d.reports.Rebuild(d.ctx, d.now()); err != nil {
		return fmt.Errorf("reports: rebuild live-report set: %w", err)
	}
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

// runPipeline parses, enriches and evaluates raw lines; bad lines are
// dropped and counted.
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

// sweep periodically expires cache entries, logs the statistics line
// and deletes expired reports.
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

// logStatistics emits the periodic statistics record (DECISIONS
// section 6) from the same Stats snapshot /stats serves.
func (d *Daemon) logStatistics() {
	s := d.Stats()
	d.logger.Info().
		Int64("received", s.Pipeline.Received).Int64("parsed", s.Pipeline.Parsed).Int64("dropped", s.Pipeline.Dropped).
		Int64("cache_gets", s.TrackerCache.Gets).Int64("cache_sets", s.TrackerCache.Sets).Int64("cache_misses", s.TrackerCache.Misses).
		Int64("cache_evictions", s.TrackerCache.Evictions).Int64("cache_size", s.TrackerCache.Size).
		Msg("statistics")
}

// sweepOnce deletes expired reports at the injected wall clock and
// returns the number deleted.
func (d *Daemon) sweepOnce(ctx context.Context) (int, error) {
	return d.reports.DeleteExpired(ctx, d.now())
}

// Shutdown drains in-flight work and closes every resource, bounded by
// ctx; the lifetime context never outlives it. Idempotent.
func (d *Daemon) Shutdown(ctx context.Context) error {
	d.once.Do(func() {
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
			// Deadline expired with stragglers in flight: abort them
			// via the lifetime context and return without waiting.
			d.cancel()
			d.shutdown = ctx.Err()
		}
	})
	return d.shutdown
}

// apiAddr is the bound API listen address (host:port).
func (d *Daemon) apiAddr() string {
	if d.apiLn == nil {
		return ""
	}
	return d.apiLn.Addr().String()
}

// waitProcessed blocks until n lines are processed (or dropped) or ctx
// is done. Test-only.
func (d *Daemon) waitProcessed(ctx context.Context, n int64) error {
	return d.processed.wait(ctx, n)
}

// counters returns the drop accounting snapshot that feeds Stats.
func (d *Daemon) counters() counters {
	return counters{
		Received: d.received.Load(),
		Parsed:   d.parsed.Load(),
		Dropped:  d.dropped.Load(),
	}
}

// Stats assembles the /stats snapshot (httpapi.StatsSource): build
// identity, pipeline counters and cache statistics since start.
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

// progress counts processed lines and wakes waiters without polling.
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
