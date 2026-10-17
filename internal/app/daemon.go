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

	"github.com/HT4w5/bandage/internal/infra/cache/memory"
	"github.com/HT4w5/bandage/internal/infra/httpapi"
	"github.com/HT4w5/bandage/internal/infra/ingest/syslog"
	nginxparser "github.com/HT4w5/bandage/internal/infra/parse/nginx"
	"github.com/HT4w5/bandage/internal/infra/persistence/sqlite"
	bandage "github.com/HT4w5/bandage/internal/domain"
	"github.com/HT4w5/bandage/internal/domain/enrichment"
	"github.com/HT4w5/bandage/internal/domain/evaluation"
	"github.com/HT4w5/bandage/internal/domain/report"
	"github.com/HT4w5/bandage/internal/identity"
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

// counters is the drop accounting logged periodically (DECISIONS §6).
// It and its accessor are unexported: the only readers are the periodic
// statistics log and in-package tests — no exported API exists solely
// for tests.
type counters struct {
	Received int64 // raw lines received from the wire
	Parsed   int64 // lines parsed into events
	Dropped  int64 // malformed or invalid lines dropped
}

type options struct {
	now    func() time.Time
	logger zerolog.Logger
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

// Daemon is the assembled analyzer: syslog ingest → nginx JSON parser →
// file-size enrichment → evaluation → report service → sqlite, served
// over HTTP.
type Daemon struct {
	cfg    Config
	chains []bandage.Chain
	now    func() time.Time
	logger zerolog.Logger
	parser EventParser
	enrich *enrichment.FilesizeEnricher

	repo   *sqlite.ReportRepository
	cache  *memory.Store
	eval   *evaluation.Service
	src    *syslog.Source
	apiSrv *http.Server
	apiLn  net.Listener

	lines     chan string
	processed *progress
	received  atomic.Int64
	parsed    atomic.Int64
	dropped   atomic.Int64

	stopSweep chan struct{}
	wg        sync.WaitGroup
	once      sync.Once
	shutdown  error
}

// New assembles the daemon. Config must already be validated (strictly
// decoded before any socket opens).
func New(cfg Config, chains []bandage.Chain, opts ...Option) (*Daemon, error) {
	var o options
	WithClock(time.Now)(&o)
	// The default logger is built from config like the program-wide one
	// (ADR 0005); the command passes its flag-adjusted instance and
	// tests pass their capture.
	o.logger = NewLogger(os.Stderr, cfg.Log.Level)
	for _, opt := range opts {
		opt(&o)
	}

	repo, err := sqlite.Open(cfg.DB.SQLite.Path)
	if err != nil {
		return nil, err
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
		repo:      repo,
		cache:     cache,
		eval:      evaluation.NewService(chains, cache, reports, o.now, domainLogger{o.logger}),
		lines:     make(chan string),
		processed: newProgress(),
		stopSweep: make(chan struct{}),
	}
	d.apiSrv = &http.Server{Handler: httpapi.New(repo, o.now)}
	return d, nil
}

// Start opens the ingest and API listeners and starts the pipeline. The
// single pipeline goroutine is the worker seam (flux-engine style).
func (d *Daemon) Start() error {
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

	d.wg.Add(2)
	go d.runPipeline()
	go d.sweep()
	go func() {
		if err := d.apiSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			d.logger.Error().Err(err).Msg("api server stopped")
		}
	}()
	d.logger.Info().Str("addr", ln.Addr().String()).Msg("api started")
	return nil
}

// runPipeline parses, enriches and evaluates raw lines in order. Bad
// lines are dropped and counted.
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
		if err := d.enrich.Enrich(context.Background(), &ev); err != nil {
			d.logger.Error().Err(err).Msg("enrich event")
		}
		if err := d.eval.Evaluate(context.Background(), &ev); err != nil {
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
			cs := d.cache.Statistics()
			s := d.stats()
			d.logger.Info().
				Int64("received", s.Received).Int64("parsed", s.Parsed).Int64("dropped", s.Dropped).
				Int64("cache_gets", cs.Gets).Int64("cache_sets", cs.Sets).Int64("cache_misses", cs.Misses).
				Int64("cache_evictions", cs.Evictions).Int64("cache_size", cs.Size).
				Msg("statistics")
			n, err := d.sweepOnce(context.Background())
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

// sweepOnce runs one sweeper pass: it deletes expired reports at the
// injected wall clock and returns the number of deleted rows. The
// periodic sweeper calls it once per tick; tests drive a pass directly,
// so expiry behavior needs no sleeping.
func (d *Daemon) sweepOnce(ctx context.Context) (int, error) {
	return d.repo.DeleteExpired(ctx, d.now())
}

// Shutdown drains the pipeline and closes every resource. Idempotent.
func (d *Daemon) Shutdown(ctx context.Context) error {
	d.once.Do(func() {
		err := d.src.Shutdown()
		close(d.stopSweep)
		close(d.lines)
		d.wg.Wait()
		if serr := d.apiSrv.Shutdown(ctx); serr != nil {
			err = errors.Join(err, serr)
		}
		if cerr := d.repo.Close(); cerr != nil {
			err = errors.Join(err, cerr)
		}
		d.shutdown = err
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

// stats returns the drop accounting counters.
func (d *Daemon) stats() counters {
	return counters{
		Received: d.received.Load(),
		Parsed:   d.parsed.Load(),
		Dropped:  d.dropped.Load(),
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
