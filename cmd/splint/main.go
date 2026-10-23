// Command splint installs ban rules derived from bandage reports.
//
// splint fetches the report document from a bandage API on a timer,
// compiles the document's live reports into ban rules and installs them
// through a firewall-driver port; --dry-run prints the compiled ban
// rules and the driver's plan once and exits without installing
// anything. SIGINT/SIGTERM reset the installed ruleset before the clean
// exit.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	flag "github.com/spf13/pflag"

	"github.com/HT4w5/bandage/internal/firewall"
	"github.com/HT4w5/bandage/internal/firewall/nft"
	"github.com/HT4w5/bandage/internal/identity"
	"github.com/HT4w5/bandage/internal/splint"
)

// Exit codes: 0 for a clean run, 1 for a load or run error, 2 for a bad
// command line (the error plus usage on stderr).
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

// progName is the program name in the build identity; the version,
// commit and build date are the shared linker-injected stamp.
const progName = "splint"

// options is the resolved command line.
type options struct {
	url            string
	hook           string
	netns          []string
	caFile         string
	certFile       string
	keyFile        string
	fetchTimeout   time.Duration
	interval       time.Duration
	excludePrefix  []string
	excludePrivate bool
	servicePort    []uint16
	serviceAddress []string
	dryRun         bool
	logLevel       string
}

func main() {
	code, _ := run(os.Args[1:], os.Stdout, os.Stderr)
	os.Exit(code)
}

// run holds the whole command: operator output goes to stdout, errors
// and usage to stderr; it returns the exit code and the resolved
// options. The run seam is deliberately untested — command behaviour
// is not frozen by tests; each validation is verified at the module
// that owns it.
func run(args []string, stdout, stderr io.Writer) (int, options) {
	fs := flag.NewFlagSet(progName, flag.ContinueOnError)
	// pflag renders the usage itself; only the streams and exit codes
	// are decided here. Help goes to stdout, errors to stderr below.
	fs.SetOutput(stdout)
	url := fs.StringP("url", "u", "", "URL of the bandage report document")
	hookFlag := fs.String("hook", "input", "enforcement hook: input or prerouting")
	// --netns is repeatable so one instance can enforce the same ban
	// rules across several containers (and the host, addressed by its
	// own nsfs path); the default target is the current namespace.
	// Values are literal nsfs paths, never comma lists — hence
	// StringArray, which unlike StringSlice keeps an empty value
	// visible to the validation below.
	netnsFlag := fs.StringArray("netns", nil, "target network namespace nsfs path (repeatable; default: the current namespace)")
	// The certificate surface is bandaid's flag for flag, so the
	// operator's PKI runbook applies unchanged.
	caFile := fs.String("cacert", "", "CA certificate file")
	certFile := fs.String("cert", "", "client certificate file")
	keyFile := fs.String("key", "", "client key file")
	fetchTimeout := fs.DurationP("fetch-timeout", "t", splint.DefaultFetchTimeout, "set fetch HTTP timeout")
	interval := fs.DurationP("update-interval", "i", splint.DefaultInterval, "report document update interval (clamped to a 1m floor)")
	// The exclusion surface is one repeatable flag: it subsumes
	// bandaid's whitelist and fluxc's exclude-prefix surfaces.
	excludePrefix := fs.StringSliceP("exclude-prefix", "x", nil, "prefix excluded from every ban set (repeatable)")
	excludePrivate := fs.BoolP("exclude-private", "p", true, "exclude RFC1918 and ULA targets")
	// The service prefilter: the protected destinations every ban rule
	// matches first. Empty sets mean all.
	servicePort := fs.UintSlice("service-port", nil, "service destination port the ban prefilter matches (repeatable)")
	serviceAddress := fs.StringSlice("service-address", nil, "service destination address or prefix the ban prefilter matches (repeatable)")
	dryRun := fs.BoolP("dry-run", "d", false, "fetch and print the compiled ban rules once without installing")
	logLevel := fs.StringP("log-level", "l", "info", "log level: debug, info, warn or error")
	showVersion := fs.BoolP("version", "v", false, "print version and exit")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK, options{}
		}
		fmt.Fprintln(stderr, err)
		printUsage(fs, stderr)
		return exitUsage, options{}
	}
	if *showVersion {
		fmt.Fprintln(stdout, identity.For(progName).String())
		return exitOK, options{}
	}
	opts := options{
		url:            *url,
		hook:           *hookFlag,
		netns:          *netnsFlag,
		caFile:         *caFile,
		certFile:       *certFile,
		keyFile:        *keyFile,
		fetchTimeout:   *fetchTimeout,
		interval:       *interval,
		excludePrefix:  *excludePrefix,
		excludePrivate: *excludePrivate,
		serviceAddress: *serviceAddress,
		dryRun:         *dryRun,
		logLevel:       *logLevel,
	}
	for i, path := range opts.netns {
		if path == "" {
			return fail(stderr, fmt.Errorf("netns: namespace path must not be empty (value %d)", i+1)), opts
		}
		if slices.Contains(opts.netns[:i], path) {
			return fail(stderr, fmt.Errorf("netns: duplicate namespace path %q", path)), opts
		}
	}
	logger, err := newLogger(stderr, opts.logLevel)
	if err != nil {
		return fail(stderr, err), opts
	}
	exclude, err := parsePrefixes("exclude prefix", opts.excludePrefix)
	if err != nil {
		return fail(stderr, err), opts
	}
	ports, err := parsePorts(*servicePort)
	if err != nil {
		return fail(stderr, err), opts
	}
	opts.servicePort = ports
	dstAddrs, err := parsePrefixes("service address", opts.serviceAddress)
	if err != nil {
		return fail(stderr, err), opts
	}
	// Exclusions are subtracted compiler-side: the driver installs
	// Targets verbatim. Every ban rule leads with the service prefilter.
	policy := splint.NewPolicy(exclude, opts.excludePrivate, firewall.Prefilter{
		DstPorts: opts.servicePort,
		DstAddrs: dstAddrs,
	})
	fetcher, err := splint.NewFetcher(opts.url,
		splint.WithTLS(opts.caFile, opts.certFile, opts.keyFile),
		splint.WithFetchTimeout(opts.fetchTimeout),
	)
	if err != nil {
		return fail(stderr, err), opts
	}
	hook, err := nft.ParseHook(opts.hook)
	if err != nil {
		return fail(stderr, err), opts
	}
	// One driver per target namespace; without --netns the single
	// target is the current namespace.
	paths := opts.netns
	if len(paths) == 0 {
		paths = []string{""}
	}
	namespaces := make([]splint.Namespace, 0, len(paths))
	for _, path := range paths {
		driver, err := nft.NewNetNS(hook, path)
		if err != nil {
			return fail(stderr, err), opts
		}
		namespaces = append(namespaces, splint.Namespace{Path: path, Driver: driver})
	}
	u, err := splint.NewForNamespaces(fetcher, namespaces, policy, opts.interval, logger)
	if err != nil {
		return fail(stderr, err), opts
	}

	// SIGINT/SIGTERM end the update loop, which resets the installed
	// ruleset before returning.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if opts.dryRun {
		// --dry-run only plans: the pure planning step, no netlink, no
		// privileges.
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

// parsePorts validates the --service-port values: ports live in
// 1-65535, and out-of-range values are refused at startup.
func parsePorts(values []uint) ([]uint16, error) {
	ports := make([]uint16, 0, len(values))
	for _, v := range values {
		if v < 1 || v > 65535 {
			return nil, fmt.Errorf("service port: must be between 1 and 65535 (got %d)", v)
		}
		ports = append(ports, uint16(v))
	}
	return ports, nil
}

// parsePrefixes parses one flag's prefix values (--exclude-prefix,
// --service-address), labeling parse failures with the flag's surface.
func parsePrefixes(what string, values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, v := range values {
		p, err := splint.ParsePrefixOrAddr(v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", what, err)
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}

// newLogger builds the program logger: fixed console-style text on w
// with timestamps, filtered at one of the four level words. (The
// daemon's NewLogger is daemon assembly; splint is a strict consumer
// and keeps its own small constructor.)
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

// parseLevel maps the four level words onto zerolog levels.
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

// printUsage prints pflag's own usage text to w. pflag renders it only
// on its built-in help path, so replay that path against the wanted
// stream and ignore the resulting ErrHelp.
func printUsage(fs *flag.FlagSet, w io.Writer) {
	fs.SetOutput(w)
	_ = fs.Parse([]string{"--help"})
}

// fail reports err on the error stream and returns the exit code.
func fail(w io.Writer, err error) int {
	fmt.Fprintln(w, err)
	return exitError
}
