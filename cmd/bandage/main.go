// Command bandage is the realtime web log analyzer daemon.
//
// Usage:
//
//	bandage [-config bandage.yml] [-rules rules.yml] [-log-level info]
//	bandage -check [-config bandage.yml] [-rules rules.yml]
//
// -check validates config and rules, prints the validated plan and exits
// without ingesting anything. Config and rules changes take effect on
// restart only.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/HT4w5/bandage/internal/app"
	bandage "github.com/HT4w5/bandage/internal/domain"
)

func main() {
	var (
		configPath = flag.String("config", "bandage.yml", "path to the config file")
		rulesPath  = flag.String("rules", "rules.yml", "path to the rules file")
		check      = flag.Bool("check", false, "validate config and rules, print the plan and exit")
		logLevel   = flag.String("log-level", "info", "log level: debug, info, warn or error")
	)
	flag.Parse()

	level, err := bandage.ParseLevel(*logLevel)
	if err != nil {
		fatal(err)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	if *check {
		plan, err := app.Check(*configPath, *rulesPath)
		if err != nil {
			fatal(err)
		}
		fmt.Print(plan)
		return
	}

	cfg, err := app.LoadConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	chains, err := app.LoadRules(*rulesPath)
	if err != nil {
		fatal(err)
	}

	d, err := app.New(cfg, chains)
	if err != nil {
		fatal(err)
	}
	if err := d.Start(); err != nil {
		fatal(err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	s := <-sig
	slog.Info("shutting down", "signal", s.String())

	ctx := context.Background()
	if err := d.Shutdown(ctx); err != nil {
		fatal(fmt.Errorf("shutdown: %w", err))
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
