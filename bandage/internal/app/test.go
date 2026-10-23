package app

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/HT4w5/webmedkit/bandage/internal/domain"
	"github.com/HT4w5/webmedkit/internal/identity"
)

// Test validates the config and rules files and returns the validated
// plan (bandage --test). It opens no sockets. The plan banner carries
// the passed build identity.
func Test(configPath, rulesPath string, build identity.Build) (string, error) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return "", err
	}
	chains, err := LoadRules(rulesPath)
	if err != nil {
		return "", err
	}
	return planText(cfg, chains, build), nil
}

func planText(cfg Config, chains []domain.Chain, build identity.Build) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", build.Header())
	fmt.Fprintf(&b, "config: ingest syslog/%s %s %s\n", cfg.Ingest.Parser, cfg.Ingest.Syslog.Network, cfg.Ingest.Syslog.Listen)
	fmt.Fprintf(&b, "config: db %s %s\n", cfg.DB.Driver, cfg.DB.SQLite.Path)
	fmt.Fprintf(&b, "config: api %s\n", cfg.API.Listen)
	fmt.Fprintf(&b, "config: cache max_entries %d\n", cfg.Cache.MaxEntries)
	for _, chain := range chains {
		fmt.Fprintf(&b, "chain %s\n", chain.Name)
		for _, rule := range chain.Rules {
			fmt.Fprintf(&b, "  rule %s\n", rule.ID)
			fmt.Fprintf(&b, "    filter: %s\n", rule.FilterSource)
			if rule.Tracker == nil {
				fmt.Fprintf(&b, "    tracker: none\n")
			} else {
				ttl := rule.Tracker.TTL.String()
				if rule.Tracker.Kind == domain.TrackReplay {
					ttl = "per-event"
				}
				fmt.Fprintf(&b, "    tracker: %s leak=%s volume=%s ttl=%s\n",
					rule.Tracker.Kind, fmtFloat(rule.Tracker.Leak), rule.Tracker.VolumeDesc(), ttl)
			}
			for _, action := range rule.Actions {
				// The describer cannot fail; Accept is shared with evaluation.
				_ = action.Accept(actionDescriber{b: &b})
			}
		}
	}
	return b.String()
}

// actionDescriber is the --test side of Action.Accept, appending one
// action line to the plan.
type actionDescriber struct {
	b *strings.Builder
}

func (d actionDescriber) VisitReport(a *domain.ReportAction) error {
	fmt.Fprintf(d.b, "    action report reason=%s ttl=%s penalty=%s", a.Reason, a.TTL, a.Penalty.Action)
	if a.Penalty.Rate != nil {
		fmt.Fprintf(d.b, " rate=%d", *a.Penalty.Rate)
	}
	fmt.Fprintln(d.b)
	return nil
}

func (d actionDescriber) VisitLog(a *domain.LogAction) error {
	fmt.Fprintf(d.b, "    action log level=%s message=%q\n", a.Level, a.Message)
	return nil
}

func (d actionDescriber) VisitGoto(target string) error {
	fmt.Fprintf(d.b, "    action goto target=%s\n", target)
	return nil
}

func (d actionDescriber) VisitJump(target string) error {
	fmt.Fprintf(d.b, "    action jump target=%s\n", target)
	return nil
}

func (d actionDescriber) VisitStop() error {
	fmt.Fprintf(d.b, "    action stop\n")
	return nil
}

func fmtFloat(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}
