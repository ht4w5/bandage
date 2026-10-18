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
// an operator can override per run, resolved with flag > config
// precedence (the built-in defaults belong to config.go alone).
type options struct {
	configPath string
	rulesPath  string
	test       bool
	logLevel   bandage.Level
	workers    int
}

func main() {
	code, _ := run(os.Args[1:], os.Stdout, os.Stderr)
	os.Exit(code)
}

// run is the command's testable seam: flag parsing and shorthands,
// -v/-h exit behavior, --test failure exit codes and flag > config
// precedence (spec Testing Decisions — nothing else may be tested
// through it; the plan content is asserted at the app seam). It writes
// operator output to stdout, errors and usage to the given writers, and
// returns the process exit code plus the resolved options.
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
	level, err := resolveLogLevel(*logLevel, fs.Changed("log-level"), cfg.Log.Level)
	if err != nil {
		return fail(stderr, err), options{}
	}
	workerCount, err := resolveWorkers(*workers, fs.Changed("workers"), cfg.Pipeline.Workers)
	if err != nil {
		return fail(stderr, err), options{}
	}
	opts := options{
		configPath: *configPath,
		rulesPath:  *rulesPath,
		test:       *testMode,
		// Precedence for the two per-run overrides is flag over config,
		// decided by whether the flag was set (spec story 9). The
		// built-in defaults live with the config decoder alone —
		// validateConfig fills log.level (info) and pipeline.workers (the
		// machine's CPU count) before this point — so config.go is their
		// single owner and there is no third tier here.
		logLevel: level,
		workers:  workerCount,
	}
	// The resolved values ride the validated config to the daemon.
	// Each worker count is validated where it enters: config values at
	// load (validateConfig), the flag at resolution below, and app.New
	// guards the invariant (spec story 16).
	cfg.Log.Level = opts.logLevel
	cfg.Pipeline.Workers = opts.workers
	// The one program-wide logger (ADR 0005): built from the resolved
	// config here and passed to the daemon and the infra tree.
	logger := app.NewLogger(stderr, opts.logLevel)

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

// resolveLogLevel resolves the log level straight to a domain Level
// (nothing re-parses it downstream): the flag wins when explicitly set —
// it must then name one of the four level words — otherwise the config
// value stands (config.go owns the info default).
func resolveLogLevel(flagValue string, flagSet bool, configValue bandage.Level) (bandage.Level, error) {
	if flagSet {
		return bandage.ParseLevel(flagValue)
	}
	return configValue, nil
}

// resolveWorkers applies flag > config precedence to the worker count:
// the flag wins when explicitly set and must then be at least 1 — the
// resolved count is never below 1 (spec story 16) — otherwise the config
// value stands (config.go owns the CPU-count default, spec story 15 /
// ADR 0007).
func resolveWorkers(flagValue int, flagSet bool, configValue int) (int, error) {
	if flagSet {
		if flagValue < 1 {
			return 0, fmt.Errorf("workers: must be at least 1 (got %d)", flagValue)
		}
		return flagValue, nil
	}
	return configValue, nil
}

// fail reports err on the error stream and returns the exit code.
func fail(w io.Writer, err error) int {
	fmt.Fprintln(w, err)
	return exitError
}
