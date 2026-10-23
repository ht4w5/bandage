// Command splint installs ban rules derived from bandage reports: it
// fetches the report document on a timer and installs the compiled ban
// rules through a firewall driver. SIGINT/SIGTERM reset the installed
// ruleset before the clean exit.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	flag "github.com/spf13/pflag"

	"github.com/HT4w5/bandage/internal/firewall"
	"github.com/HT4w5/bandage/internal/firewall/nft"
	"github.com/HT4w5/bandage/internal/identity"
	"github.com/HT4w5/bandage/internal/splint"
)

// Exit codes: 0 clean, 1 load or run error, 2 bad command line (the
// error plus usage on stderr).
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

// progName keys the shared linker-injected build identity.
const progName = "splint"

// options is the resolved engine command line; the driver's own flags
// live in its factory's flag group.
type options struct {
	url            string
	caFile         string
	certFile       string
	keyFile        string
	fetchTimeout   time.Duration
	interval       time.Duration
	excludePrefix  []string
	excludePrivate bool
	dryRun         bool
	logLevel       string
}

func main() {
	code, _ := run(os.Args[1:], os.Stdout, os.Stderr)
	os.Exit(code)
}

// run runs the whole command: operator output to stdout, errors and
// usage to stderr; it returns the exit code and the resolved options.
func run(args []string, stdout, stderr io.Writer) (int, options) {
	fs := flag.NewFlagSet(progName, flag.ContinueOnError)
	fs.SetOutput(stdout)
	// The registry owns --firewall's selection semantics: the known
	// driver names, one driver per run, and the refusal of a set flag
	// that belongs to an unselected driver.
	nftFactory := nft.NewFactory()
	reg := firewall.NewRegistry(nftFactory)
	fs.Usage = func() { writeUsage(fs, fs.Output(), reg) }
	firewallName := fs.String("firewall", nftFactory.Name(), "firewall driver: "+strings.Join(reg.Names(), ", "))
	url := fs.StringP("url", "u", "", "URL of the bandage report document")
	// Each factory binds its own flag group; driver targeting and
	// enforcement scope never pass through the engine's flags.
	reg.Bind(fs)
	// The certificate flags match bandaid's one for one, so the
	// operator's PKI runbook applies unchanged.
	caFile := fs.String("cacert", "", "CA certificate file")
	certFile := fs.String("cert", "", "client certificate file")
	keyFile := fs.String("key", "", "client key file")
	fetchTimeout := fs.DurationP("fetch-timeout", "t", splint.DefaultFetchTimeout, "set fetch HTTP timeout")
	interval := fs.DurationP("update-interval", "i", splint.DefaultInterval, "report document update interval (clamped to a 1m floor)")
	// One repeatable flag subsumes bandaid's whitelist and fluxc's
	// exclude-prefix surfaces.
	excludePrefix := fs.StringSliceP("exclude-prefix", "x", nil, "prefix subtracted from every ban rule's Target set (repeatable)")
	excludePrivate := fs.BoolP("exclude-private", "p", true, "exclude RFC1918 and ULA targets")
	dryRun := fs.BoolP("dry-run", "d", false, "fetch and print the compiled ban rules once without installing")
	logLevel := fs.StringP("log-level", "l", "info", "log level: debug, info, warn or error")
	showVersion := fs.BoolP("version", "v", false, "print version and exit")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK, options{}
		}
		fmt.Fprintln(stderr, err)
		writeUsage(fs, stderr, reg)
		return exitUsage, options{}
	}
	if *showVersion {
		fmt.Fprintln(stdout, identity.For(progName).String())
		return exitOK, options{}
	}
	opts := options{
		url:            *url,
		caFile:         *caFile,
		certFile:       *certFile,
		keyFile:        *keyFile,
		fetchTimeout:   *fetchTimeout,
		interval:       *interval,
		excludePrefix:  *excludePrefix,
		excludePrivate: *excludePrivate,
		dryRun:         *dryRun,
		logLevel:       *logLevel,
	}
	factory, err := reg.Select(*firewallName, fs)
	if err != nil {
		fmt.Fprintln(stderr, err)
		writeUsage(fs, stderr, reg)
		return exitUsage, opts
	}
	if err := factory.Validate(); err != nil {
		return fail(stderr, err), opts
	}
	logger, err := newLogger(stderr, opts.logLevel)
	if err != nil {
		return fail(stderr, err), opts
	}
	exclude, err := parsePrefixes(opts.excludePrefix)
	if err != nil {
		return fail(stderr, err), opts
	}
	// Exclusions are subtracted compiler-side; the driver installs
	// Targets verbatim.
	policy := splint.NewPolicy(exclude, opts.excludePrivate)
	fetcher, err := splint.NewFetcher(opts.url,
		splint.WithTLS(opts.caFile, opts.certFile, opts.keyFile),
		splint.WithFetchTimeout(opts.fetchTimeout),
	)
	if err != nil {
		return fail(stderr, err), opts
	}
	points, err := factory.Open()
	if err != nil {
		return fail(stderr, err), opts
	}
	u, err := splint.New(fetcher, points, policy, opts.interval, logger)
	if err != nil {
		return fail(stderr, err), opts
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if opts.dryRun {
		// --dry-run only plans: no netlink, no privileges.
		if err := u.DryRun(ctx, stdout); err != nil {
			return fail(stderr, err), opts
		}
		return exitOK, opts
	}
	if err := u.Run(ctx); err != nil {
		return fail(stderr, err), opts
	}
	return exitOK, opts
}

func parsePrefixes(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, v := range values {
		p, err := firewall.ParsePrefixOrAddr(v)
		if err != nil {
			return nil, fmt.Errorf("exclude prefix: %w", err)
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}

// newLogger is splint's own logger constructor; the daemon's NewLogger
// is daemon assembly, which splint does not import.
func newLogger(w io.Writer, level string) (zerolog.Logger, error) {
	lvl, err := parseLevel(level)
	if err != nil {
		return zerolog.Logger{}, err
	}
	return zerolog.New(zerolog.ConsoleWriter{
		Out:        w,
		NoColor:    true,
		TimeFormat: time.RFC3339,
	}).Level(lvl).With().Timestamp().Logger(), nil
}

func parseLevel(level string) (zerolog.Level, error) {
	switch level {
	case "debug":
		return zerolog.DebugLevel, nil
	case "info":
		return zerolog.InfoLevel, nil
	case "warn":
		return zerolog.WarnLevel, nil
	case "error":
		return zerolog.ErrorLevel, nil
	default:
		return 0, fmt.Errorf("log level: must be debug, info, warn or error (got %q)", level)
	}
}

// writeUsage groups the usage text by owner: the engine's options
// first, then one group per registered driver.
func writeUsage(fs *flag.FlagSet, w io.Writer, reg *firewall.Registry) {
	fmt.Fprintf(w, "Usage of %s:\n", fs.Name())
	owned := make(map[string]bool)
	for _, g := range reg.Groups() {
		for _, name := range g.Flags {
			owned[name] = true
		}
	}
	engine := flag.NewFlagSet("engine options", flag.ContinueOnError)
	fs.VisitAll(func(f *flag.Flag) {
		if !owned[f.Name] {
			engine.AddFlag(f)
		}
	})
	fmt.Fprintf(w, "\nengine options:\n%s", engine.FlagUsages())
	for _, g := range reg.Groups() {
		group := flag.NewFlagSet(g.Owner+" driver options", flag.ContinueOnError)
		for _, name := range g.Flags {
			if f := fs.Lookup(name); f != nil {
				group.AddFlag(f)
			}
		}
		fmt.Fprintf(w, "\n%s driver options:\n%s", g.Owner, group.FlagUsages())
	}
}

func fail(w io.Writer, err error) int {
	fmt.Fprintln(w, err)
	return exitError
}
