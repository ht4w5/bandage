package app

import (
	"fmt"
	"strconv"
	"strings"

	bandage "github.com/HT4w5/bandage/internal/domain"
)

// Check validates the config and rules files and returns the validated
// plan (bandage -check): chains → rules with filter, tracker config and
// actions. It opens no sockets and ingests nothing.
func Check(configPath, rulesPath string) (string, error) {
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
	fmt.Fprintf(&b, "config: ingest syslog/%s %s %s\n", cfg.Ingest.Parser, cfg.Ingest.Syslog.Network, cfg.Ingest.Syslog.Listen)
	fmt.Fprintf(&b, "config: db %s %s\n", cfg.DB.Driver, cfg.DB.SQLite.Path)
	fmt.Fprintf(&b, "config: api %s\n", cfg.API.Listen)
	fmt.Fprintf(&b, "config: cache max_entries %d\n", cfg.Cache.MaxEntries)
	for _, chain := range chains {
		fmt.Fprintf(&b, "chain %s\n", chain.Name)
		for _, rule := range chain.Rules {
			fmt.Fprintf(&b, "  rule %s\n", rule.ID)
			// Format version 0 has exactly one filter ("any").
			fmt.Fprintf(&b, "    filter: any\n")
			if rule.Tracker == nil {
				fmt.Fprintf(&b, "    tracker: none\n")
			} else {
				fmt.Fprintf(&b, "    tracker: %s leak=%s volume=%s ttl=%s\n",
					rule.Tracker.Kind, fmtFloat(rule.Tracker.Leak), fmtFloat(rule.Tracker.Volume), rule.Tracker.TTL)
			}
			for _, action := range rule.Actions {
				switch {
				case action.Report != nil:
					fmt.Fprintf(&b, "    action report reason=%s ttl=%s\n", action.Report.Reason, action.Report.TTL)
				case action.Log != nil:
					fmt.Fprintf(&b, "    action log level=%s message=%q\n", strings.ToLower(action.Log.Level.String()), action.Log.Message)
				case action.Goto != "":
					fmt.Fprintf(&b, "    action goto target=%s\n", action.Goto)
				case action.Jump != "":
					fmt.Fprintf(&b, "    action jump target=%s\n", action.Jump)
				case action.Stop:
					fmt.Fprintf(&b, "    action stop\n")
				}
			}
		}
	}
	return b.String()
}

func fmtFloat(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}
