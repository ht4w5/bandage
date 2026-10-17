// Command bandage is the realtime web log analyzer daemon.
//
// Usage:
//
//	bandage [-c bandage.yml] [-r rules.yml] [-l level] [-w workers]
//	bandage -t [-c bandage.yml] [-r rules.yml]
//
// -t/--test validates config and rules, prints the validated plan with
// the build identity header and exits without ingesting anything.
// Config and rules changes take effect on restart only.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	flag "github.com/spf13/pflag"

	"github.com/HT4w5/bandage/internal/app"
	bandage "github.com/HT4w5/bandage/internal/domain"
	"github.com/HT4w5/bandage/internal/identity"
)

// Exit codes: a clean run (-v, -h, --test, the daemon) exits 0, a load
// or run error exits 1, and a bad command line (unknown flag) exits 2
// with the usage.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

// shutdownTimeout bounds the graceful drain on the way down: shutdown
// completes within it even if a store call hangs (spec story 31).
const shutdownTimeout = 10 * time.Second

// options is the resolved command line: paths and mode plus the values
// an operator can override per run, resolved with flag > config >
// default precedence.
type options struct {
	configPath string
	rulesPath  string
	test       bool
	logLevel   string
	workers    int
}

func main() {
	code, _ := run(os.Args[1:], os.Stdout, os.Stderr)
	os.Exit(code)
}

// run is the command's testable seam: flag parsing, shorthands, exit
// behavior and flag > config > default precedence (spec Testing
// Decisions — nothing else is tested through it). It writes operator
// output to stdout, errors and usage to the given writers, and returns
// the process exit code plus the resolved options.
func run(args []string, stdout, stderr io.Writer) (int, options) {
	fs := flag.NewFlagSet("bandage", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.StringP("config", "c", "bandage.yml", "path to the config file")
	rulesPath := fs.StringP("rules", "r", "rules.yml", "path to the rules file")
	testMode := fs.BoolP("test", "t", false, "validate config and rules, print the plan and exit")
	logLevel := fs.StringP("log-level", "l", "", "log level: debug, info, warn or error (overrides config)")
	workers := fs.IntP("workers", "w", 0, "pipeline worker count (overrides config)")
	showVersion := fs.BoolP("version", "v", false, "print version and exit")
	showHelp := fs.BoolP("help", "h", false, "show this help and exit")

	if err := fs.Parse(args); err != nil {
		// A bad command line fails loudly: the error plus usage, exit 2.
		fmt.Fprintln(stderr, err)
		usage(stderr, fs)
		return exitUsage, options{}
	}
	if *showHelp {
		usage(stdout, fs)
		return exitOK, options{}
	}
	if *showVersion {
		fmt.Fprintln(stdout, identity.String())
		return exitOK, options{}
	}

	cfg, err := app.LoadConfig(*configPath)
	if err != nil {
		return fail(stderr, err), options{}
	}
	opts := options{
		configPath: *configPath,
		rulesPath:  *rulesPath,
		test:       *testMode,
		// Precedence: the explicit flag wins, then the config value,
		// then the built-in default — decided by whether the flag was
		// set. log.level and pipeline.workers both come from the config
		// here; the flags above override them when passed.
		logLevel: resolveLogLevel(*logLevel, fs.Changed("log-level"), string(cfg.Log.Level)),
		workers:  resolveWorkers(*workers, fs.Changed("workers"), cfg.Pipeline.Workers),
	}
	// The resolved worker count must be at least 1 (spec story 16):
	// config load rejects an invalid pipeline.workers, an explicit -w
	// value is validated here, and the daemon receives the resolved
	// count either way.
	if opts.workers < 1 {
		return fail(stderr, fmt.Errorf("pipeline.workers: must be positive (got %d)", opts.workers)), opts
	}
	cfg.Pipeline.Workers = opts.workers
	level, err := bandage.ParseLevel(opts.logLevel)
	if err != nil {
		return fail(stderr, err), opts
	}
	// The one program-wide logger (ADR 0005): built from the resolved
	// config here and passed to the daemon and its adapters.
	logger := app.NewLogger(stderr, level)

	if opts.test {
		plan, err := app.Test(opts.configPath, opts.rulesPath)
		if err != nil {
			return fail(stderr, err), opts
		}
		fmt.Fprint(stdout, plan)
		return exitOK, opts
	}

	chains, err := app.LoadRules(opts.rulesPath)
	if err != nil {
		return fail(stderr, err), opts
	}
	d, err := app.New(cfg, chains, app.WithLogger(logger))
	if err != nil {
		return fail(stderr, err), opts
	}
	// The daemon-lifetime context comes from SIGINT/SIGTERM: the signal
	// ends the daemon's lifetime and starts the graceful drain below.
	// The daemon detaches its work from the signal's cancellation —
	// in-flight report upserts complete during the drain — and cancels
	// its lifetime context only as the bounded-shutdown backstop
	// (spec: Daemon context).
	lifetime, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := d.Start(lifetime); err != nil {
		return fail(stderr, err), opts
	}
	<-lifetime.Done()
	logger.Info().Msg("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := d.Shutdown(shutdownCtx); err != nil {
		return fail(stderr, fmt.Errorf("shutdown: %w", err)), opts
	}
	return exitOK, opts
}

// usage prints the help text: the short identity header, the synopsis
// and the flag table.
func usage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprintf(w, "%s\n\nUsage:\n  bandage [flags]\n\nFlags:\n%s", identity.Header(), fs.FlagUsages())
}

// resolveLogLevel applies flag > config > default precedence to the log
// level: the flag wins when explicitly set, then the config value, then
// the built-in default.
func resolveLogLevel(flagValue string, flagSet bool, configValue string) string {
	switch {
	case flagSet:
		return flagValue
	case configValue != "":
		return configValue
	default:
		return "info"
	}
}

// resolveWorkers applies flag > config > default precedence to the
// worker count: the flag wins when explicitly set, then the config
// value, then the built-in default — the machine's CPU count (spec
// story 15, ADR 0007).
func resolveWorkers(flagValue int, flagSet bool, configValue int) int {
	switch {
	case flagSet:
		return flagValue
	case configValue != 0:
		return configValue
	default:
		return runtime.NumCPU()
	}
}

// fail reports err on the error stream and returns the exit code.
func fail(w io.Writer, err error) int {
	fmt.Fprintln(w, err)
	return exitError
}
