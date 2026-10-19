// Command splint-nft installs ban rules derived from bandage reports.
//
// splint-nft fetches the report document from a bandage API on a timer,
// compiles the document's live reports into ban rules and installs them
// through a firewall-driver port; --dry-run prints the compiled ban
// rules once and exits without installing anything. SIGINT/SIGTERM
// reset the installed ruleset before the clean exit.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	flag "github.com/spf13/pflag"

	"github.com/HT4w5/bandage/internal/identity"
	"github.com/HT4w5/bandage/internal/splint"
	"github.com/HT4w5/bandage/internal/splint/nft"
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
const progName = "splint-nft"

// options is the resolved command line.
type options struct {
	url          string
	hook         string
	caFile       string
	certFile     string
	keyFile      string
	fetchTimeout time.Duration
	interval     time.Duration
	dryRun       bool
	logLevel     string
}

func main() {
	code, _ := run(os.Args[1:], os.Stdout, os.Stderr)
	os.Exit(code)
}

// run is the command's testable seam: operator output goes to stdout,
// errors and usage to stderr; it returns the exit code and the resolved
// options.
func run(args []string, stdout, stderr io.Writer) (int, options) {
	fs := flag.NewFlagSet(progName, flag.ContinueOnError)
	// pflag renders the usage itself; only the streams and exit codes
	// are decided here. Help goes to stdout, errors to stderr below.
	fs.SetOutput(stdout)
	url := fs.StringP("url", "u", "", "URL of the bandage report document")
	hookFlag := fs.String("hook", "input", "enforcement hook: input or prerouting")
	// The certificate surface is bandaid's flag for flag, so the
	// operator's PKI runbook applies unchanged.
	caFile := fs.String("cacert", "", "CA certificate file")
	certFile := fs.String("cert", "", "client certificate file")
	keyFile := fs.String("key", "", "client key file")
	fetchTimeout := fs.DurationP("fetch-timeout", "t", splint.DefaultFetchTimeout, "set fetch HTTP timeout")
	interval := fs.DurationP("update-interval", "i", splint.DefaultInterval, "report document update interval (clamped to a 1m floor)")
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
		fmt.Fprintln(stdout, identity.Summary(progName))
		return exitOK, options{}
	}
	opts := options{
		url:          *url,
		hook:         *hookFlag,
		caFile:       *caFile,
		certFile:     *certFile,
		keyFile:      *keyFile,
		fetchTimeout: *fetchTimeout,
		interval:     *interval,
		dryRun:       *dryRun,
		logLevel:     *logLevel,
	}
	logger, err := newLogger(stderr, opts.logLevel)
	if err != nil {
		return fail(stderr, err), opts
	}
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
	driver, err := nft.New(hook)
	if err != nil {
		return fail(stderr, err), opts
	}
	u := splint.New(fetcher, driver, opts.interval, logger)

	// SIGINT/SIGTERM end the update loop, which resets the installed
	// ruleset before returning.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if opts.dryRun {
		// --dry-run never reaches the driver: no netlink, no privileges.
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
