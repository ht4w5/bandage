package app

import (
	"fmt"
	"strconv"
	"strings"

	bandage "github.com/HT4w5/bandage/internal/domain"
	"github.com/HT4w5/bandage/internal/identity"
)

// Test validates the config and rules files and returns the validated
// plan (bandage --test): chains → rules with filter, tracker config and
// actions. It opens no sockets and ingests nothing.
func Test(configPath, rulesPath string) (string, error) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return "", err
	}
	chains, err := LoadRules(rulesPath)
	if err != nil {
		return "", err
	}
	return planText(cfg, chains), nil
}

func planText(cfg Config, chains []bandage.Chain) string {
	var b strings.Builder
	// The plan opens with the build identity header (spec story 6).
	fmt.Fprintf(&b, "%s\n", identity.Header())
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
				// Replay derives its cache TTL per event from the volume
				// method output (DECISIONS §8).
				ttl := rule.Tracker.TTL.String()
				if rule.Tracker.Kind == bandage.TrackReplay {
					ttl = "per-event"
				}
				fmt.Fprintf(&b, "    tracker: %s leak=%s volume=%s ttl=%s\n",
					rule.Tracker.Kind, fmtFloat(rule.Tracker.Leak), rule.Tracker.VolumeDesc(), ttl)
			}
			for _, action := range rule.Actions {
				// The describer cannot fail; Accept is the single action
				// dispatch point shared with evaluation.
				_ = action.Accept(actionDescriber{b: &b})
			}
		}
	}
	return b.String()
}

// actionDescriber is the --test side of Action.Accept: it appends one
// action line to the validated plan.
type actionDescriber struct {
	b *strings.Builder
}

func (d actionDescriber) VisitReport(a *bandage.ReportAction) error {
	fmt.Fprintf(d.b, "    action report reason=%s ttl=%s\n", a.Reason, a.TTL)
	return nil
}

func (d actionDescriber) VisitLog(a *bandage.LogAction) error {
	fmt.Fprintf(d.b, "    action log level=%s message=%q\n", strings.ToLower(a.Level.String()), a.Message)
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
