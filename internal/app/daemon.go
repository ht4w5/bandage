package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HT4w5/bandage/internal/adapters/cache/memory"
	"github.com/HT4w5/bandage/internal/adapters/httpapi"
	"github.com/HT4w5/bandage/internal/adapters/ingest/syslog"
	nginxparser "github.com/HT4w5/bandage/internal/adapters/parse/nginx"
	"github.com/HT4w5/bandage/internal/adapters/persistence/sqlite"
	bandage "github.com/HT4w5/bandage/internal/domain"
	"github.com/HT4w5/bandage/internal/domain/evaluation"
	"github.com/HT4w5/bandage/internal/domain/report"
)

// sweepInterval is the internal cadence of the tracker cache expiry
// sweep, the expired-report sweeper and the periodic statistics log.
const sweepInterval = time.Minute

// EventParser is the parser port beside its consumer: one raw log line in,
// one domain Event out (or an error, which drops and counts the line).
type EventParser interface {
	Parse(line []byte) (bandage.Event, error)
}

// Stats is the drop accounting surfaced by the daemon and logged
// periodically (DECISIONS §6).
type Stats struct {
	Received int64 // raw lines received from the wire
	Parsed   int64 // lines parsed into events
	Dropped  int64 // malformed or invalid lines dropped
}

type options struct {
	now    func() time.Time
	logger *slog.Logger
}

// Option configures the daemon wiring.
type Option func(*options)

// WithClock injects the wall clock (report timestamps and cache expiry).
func WithClock(now func() time.Time) Option {
	return func(o *options) { o.now = now }
}

// WithLogger sets the daemon logger.
func WithLogger(l *slog.Logger) Option {
	return func(o *options) { o.logger = l }
}

// Daemon is the assembled analyzer: syslog ingest → nginx JSON parser →
// evaluation → report service → sqlite, served over HTTP.
type Daemon struct {
	cfg    Config
	chains []bandage.Chain
	now    func() time.Time
	logger *slog.Logger
	parser EventParser

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
	WithLogger(slog.Default())(&o)
	for _, opt := range opts {
		opt(&o)
	}

	repo, err := sqlite.Open(cfg.DB.SQLite.Path)
	if err != nil {
		return nil, err
	}
	cache := memory.New(cfg.Cache.MaxEntries, o.now, o.logger)
	reports := report.NewService(repo)

	d := &Daemon{
		cfg:       cfg,
		chains:    chains,
		now:       o.now,
		logger:    o.logger,
		parser:    nginxparser.New(),
		repo:      repo,
		cache:     cache,
		eval:      evaluation.NewService(chains, cache, reports, o.now),
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
			d.logger.Error("api server stopped", "error", err)
		}
	}()
	d.logger.Info("api started", "addr", ln.Addr().String())
	return nil
}

// runPipeline parses and evaluates raw lines in order. Bad lines are
// dropped and counted.
func (d *Daemon) runPipeline() {
	defer d.wg.Done()
	for line := range d.lines {
		d.received.Add(1)
		ev, err := d.parser.Parse([]byte(line))
		if err != nil {
			d.dropped.Add(1)
			d.logger.Warn("dropping bad log line", "error", err)
			d.processed.bump()
			continue
		}
		d.parsed.Add(1)
		if err := d.eval.Evaluate(context.Background(), &ev); err != nil {
			d.logger.Error("evaluate event", "error", err)
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
			s := d.Stats()
			cs := d.cache.Statistics()
			d.logger.Info("statistics",
				"received", s.Received, "parsed", s.Parsed, "dropped", s.Dropped,
				"cache_gets", cs.Gets, "cache_sets", cs.Sets, "cache_misses", cs.Misses,
				"cache_evictions", cs.Evictions, "cache_size", cs.Size)
			n, err := d.repo.DeleteExpired(context.Background(), d.now())
			if err != nil {
				d.logger.Error("sweep expired reports", "error", err)
				continue
			}
			if n > 0 {
				d.logger.Info("swept expired reports", "count", n)
			}
		}
	}
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

// APIAddr is the bound API listen address (host:port).
func (d *Daemon) APIAddr() string {
	if d.apiLn == nil {
		return ""
	}
	return d.apiLn.Addr().String()
}

// WaitProcessed blocks until n raw lines have been fully processed
// (parsed and evaluated, or dropped) or ctx is done.
func (d *Daemon) WaitProcessed(ctx context.Context, n int64) error {
	return d.processed.wait(ctx, n)
}

// Stats returns the drop accounting counters.
func (d *Daemon) Stats() Stats {
	return Stats{
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
