// Command bandage is the realtime web log analyzer daemon.
//
// bandage -t validates config and rules, prints the validated plan and
// exits; without -t it ingests logs until SIGINT/SIGTERM. Config and
// rules changes take effect on restart only.
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

	flag "github.com/spf13/pflag"

	"github.com/HT4w5/bandage/internal/app"
	bandage "github.com/HT4w5/bandage/internal/domain"
	"github.com/HT4w5/bandage/internal/identity"
)

// Exit codes: 0 for a clean run, 1 for a load or run error, 2 for a bad
// command line (the error plus usage on stderr).
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

// shutdownTimeout bounds the graceful drain, even if a store call hangs.
const shutdownTimeout = 10 * time.Second

// options is the resolved command line: paths, mode and the per-run
// overrides (flag over config; the defaults belong to config.go).
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

// run is the command's testable seam: operator output goes to stdout,
// errors and usage to stderr; it returns the exit code and the resolved
// options.
func run(args []string, stdout, stderr io.Writer) (int, options) {
	fs := flag.NewFlagSet("bandage", flag.ContinueOnError)
	// pflag renders the usage itself; only the streams and exit codes
	// are decided here. Help goes to stdout, errors to stderr below.
	fs.SetOutput(stdout)
	configPath := fs.StringP("config", "c", "bandage.yml", "path to the config file")
	rulesPath := fs.StringP("rules", "r", "rules.yml", "path to the rules file")
	testMode := fs.BoolP("test", "t", false, "validate config and rules, print the plan and exit")
	logLevel := fs.StringP("log-level", "l", "", "log level: debug, info, warn or error (overrides config)")
	workers := fs.IntP("workers", "w", 0, "pipeline worker count (overrides config)")
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
		logLevel:   level,
		workers:    workerCount,
	}
	// The resolved values ride the validated config to the daemon.
	cfg.Log.Level = opts.logLevel
	cfg.Pipeline.Workers = opts.workers
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
	// SIGINT/SIGTERM end the daemon's lifetime and start the graceful
	// drain; in-flight work completes before the shutdown timeout cuts
	// it off.
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

// printUsage prints pflag's own usage text to w. pflag renders it only
// on its built-in help path, so replay that path against the wanted
// stream and ignore the resulting ErrHelp.
func printUsage(fs *flag.FlagSet, w io.Writer) {
	fs.SetOutput(w)
	_ = fs.Parse([]string{"--help"})
}

// resolveLogLevel resolves the log level to a domain Level: the flag
// wins when set and must name one of the four level words.
func resolveLogLevel(flagValue string, flagSet bool, configValue bandage.Level) (bandage.Level, error) {
	if flagSet {
		return bandage.ParseLevel(flagValue)
	}
	return configValue, nil
}

// resolveWorkers applies flag over config: the flag wins when set and
// must be at least 1.
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
