package app

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	bandage "github.com/HT4w5/bandage/internal/domain"
	"github.com/HT4w5/bandage/internal/domain/filter"
	"github.com/HT4w5/bandage/internal/domain/track"
)

// reasonRe is the machine-readable reason slug pattern (spec: Reports).
var reasonRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// raw rules wire types (strict decode).

type rawRules struct {
	Version *int       `yaml:"version"`
	Chains  []rawChain `yaml:"chains"`
}

type rawChain struct {
	Name  string    `yaml:"name"`
	Rules []rawRule `yaml:"rules"`
}

type rawRule struct {
	ID      string      `yaml:"id"`
	Filter  string      `yaml:"filter"`
	Tracker *rawTracker `yaml:"tracker"`
	Actions []yaml.Node `yaml:"actions"`
}

// rawTracker keeps leak and volume as nodes: presence is validated ("explicit
// leak and volume") and the volume-method block shape stays open for the
// replay ticket. A missing node has Kind zero.
type rawTracker struct {
	Track        string          `yaml:"track"`
	Leak         yaml.Node       `yaml:"leak"`
	Volume       yaml.Node       `yaml:"volume"`
	TargetPrefix rawTargetPrefix `yaml:"target_prefix"`
}

// rawTargetPrefix is accepted and defaulted ({32, 64}); aggregation is the
// target-aggregation ticket's job.
type rawTargetPrefix struct {
	IPv4 *int `yaml:"ipv4"`
	IPv6 *int `yaml:"ipv6"`
}

type rawReportAction struct {
	Reason string `yaml:"reason"`
	TTL    string `yaml:"ttl"`
}

// LoadRules reads and validates the rules file at path.
func LoadRules(path string) ([]bandage.Chain, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("rules: read %s: %w", path, err)
	}
	chains, err := ParseRules(data)
	if err != nil {
		return nil, fmt.Errorf("rules %s: %w", path, err)
	}
	return chains, nil
}

// ParseRules strictly decodes and validates a format-version-0 rules
// document into chains. Unknown keys and invalid values are errors; every
// error names the rule it belongs to where possible.
func ParseRules(data []byte) ([]bandage.Chain, error) {
	var raw rawRules
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("rules: empty document")
		}
		return nil, fmt.Errorf("rules: decode: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return nil, errors.New("rules: multiple YAML documents")
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("rules: decode: %w", err)
	}

	if raw.Version == nil {
		return nil, errors.New("rules: version: required (want 0)")
	}
	if *raw.Version != 0 {
		return nil, fmt.Errorf("rules: version: unsupported format version %d (want 0)", *raw.Version)
	}
	if len(raw.Chains) == 0 {
		return nil, errors.New("rules: chains: at least one chain required")
	}

	seen := make(map[string]bool)
	chains := make([]bandage.Chain, 0, len(raw.Chains))
	for i := range raw.Chains {
		chain, err := buildChain(&raw.Chains[i], seen)
		if err != nil {
			return nil, err
		}
		chains = append(chains, chain)
	}
	if err := validateChainGraph(chains); err != nil {
		return nil, err
	}
	return chains, nil
}

func buildChain(raw *rawChain, seen map[string]bool) (bandage.Chain, error) {
	if raw.Name == "" {
		return bandage.Chain{}, errors.New("rules: chain: name: required")
	}
	if len(raw.Rules) == 0 {
		return bandage.Chain{}, fmt.Errorf("rules: chain %q: at least one rule required", raw.Name)
	}
	chain := bandage.Chain{Name: raw.Name, Rules: make([]bandage.Rule, 0, len(raw.Rules))}
	for i := range raw.Rules {
		rule, err := buildRule(raw.Name, &raw.Rules[i], seen)
		if err != nil {
			return bandage.Chain{}, err
		}
		chain.Rules = append(chain.Rules, rule)
	}
	return chain, nil
}

func buildRule(chainName string, raw *rawRule, seen map[string]bool) (bandage.Rule, error) {
	if raw.ID == "" {
		return bandage.Rule{}, fmt.Errorf("rules: chain %q: rule: id: required", chainName)
	}
	id := raw.ID
	if seen[id] {
		return bandage.Rule{}, fmt.Errorf("rules: duplicate rule id %q", id)
	}
	seen[id] = true

	rule := bandage.Rule{ID: id}

	flt := raw.Filter
	if flt == "" {
		flt = "any"
	}
	parsed, err := filter.Parse(flt)
	if err != nil {
		return bandage.Rule{}, fmt.Errorf("rules: rule %q: %w", id, err)
	}
	rule.Filter = parsed

	if raw.Tracker != nil {
		cfg, err := parseTracker(id, raw.Tracker)
		if err != nil {
			return bandage.Rule{}, err
		}
		rule.Tracker = cfg
	}

	for i := range raw.Actions {
		action, err := parseAction(id, &raw.Actions[i])
		if err != nil {
			return bandage.Rule{}, err
		}
		if action.Report != nil && rule.Tracker == nil {
			return bandage.Rule{}, fmt.Errorf("rules: rule %q: report requires a tracker", id)
		}
		rule.Actions = append(rule.Actions, action)
	}
	return rule, nil
}

// parseTracker builds the rule's tracker config: explicit leak and volume
// with the cache TTL derived as volume/leak.
func parseTracker(id string, raw *rawTracker) (*bandage.TrackerConfig, error) {
	var kind bandage.TrackKind
	switch raw.Track {
	case "":
		return nil, fmt.Errorf("rules: rule %q: tracker.track: required (want %q or %q)",
			id, bandage.TrackRate, bandage.TrackBandwidth)
	case string(bandage.TrackRate), string(bandage.TrackBandwidth):
		kind = bandage.TrackKind(raw.Track)
	case string(bandage.TrackReplay):
		return nil, fmt.Errorf("rules: rule %q: tracker.track: tracker kind %q is not supported yet (want %q or %q)",
			id, raw.Track, bandage.TrackRate, bandage.TrackBandwidth)
	default:
		return nil, fmt.Errorf("rules: rule %q: tracker.track: unknown tracker kind %q (want %q or %q)",
			id, raw.Track, bandage.TrackRate, bandage.TrackBandwidth)
	}

	leak, err := parseTrackerQuantity(id, "tracker.leak", &raw.Leak, kind)
	if err != nil {
		return nil, err
	}
	volume, err := parseTrackerQuantity(id, "tracker.volume", &raw.Volume, kind)
	if err != nil {
		return nil, err
	}
	if volume <= 0 {
		return nil, fmt.Errorf("rules: rule %q: tracker.volume: must be positive", id)
	}
	if leak < 0 {
		return nil, fmt.Errorf("rules: rule %q: tracker.leak: must be non-negative", id)
	}

	return &bandage.TrackerConfig{
		Kind:   kind,
		Leak:   leak,
		Volume: volume,
		TTL:    track.TTL(leak, volume),
	}, nil
}

// parseTrackerQuantity parses one explicit tracker quantity per kind:
// rate uses plain numbers (request counts), bandwidth byte quantities.
// Errors name the rule and the field (DECISIONS §5).
func parseTrackerQuantity(id, field string, node *yaml.Node, kind bandage.TrackKind) (float64, error) {
	if node == nil || node.Kind == 0 {
		return 0, fmt.Errorf("rules: rule %q: %s: required", id, field)
	}
	if node.Kind != yaml.ScalarNode {
		// Volume-method blocks land with the replay ticket.
		return 0, fmt.Errorf("rules: rule %q: %s: must be a quantity", id, field)
	}
	var (
		v   float64
		err error
	)
	if kind == bandage.TrackRate {
		v, err = track.ParseNumber(node.Value)
	} else {
		v, err = track.ParseBytes(node.Value)
	}
	if err != nil {
		return 0, fmt.Errorf("rules: rule %q: %s: %w", id, field, err)
	}
	return v, nil
}

// parseAction parses one action item (DECISIONS §9): `- stop`,
// `- goto: <chain>`, `- jump: <chain>`, `- log: "level,message"`, or
// `- report: {reason, ttl}`.
func parseAction(id string, node *yaml.Node) (bandage.Action, error) {
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Value == "stop" {
			return bandage.Action{Stop: true}, nil
		}
		if knownActions[node.Value] {
			return bandage.Action{}, fmt.Errorf("rules: rule %q: action %q: wants options", id, node.Value)
		}
		return bandage.Action{}, fmt.Errorf("rules: rule %q: unknown action %q", id, node.Value)
	case yaml.MappingNode:
		if len(node.Content) != 2 {
			return bandage.Action{}, fmt.Errorf("rules: rule %q: action must be a single name with options", id)
		}
		name, val := node.Content[0].Value, node.Content[1]
		switch name {
		case "report":
			var raw rawReportAction
			for i := 0; i < len(val.Content); i += 2 {
				switch key := val.Content[i].Value; key {
				case "reason", "ttl":
				default:
					return bandage.Action{}, fmt.Errorf("rules: rule %q: action report: unknown key %q", id, key)
				}
			}
			if err := val.Decode(&raw); err != nil {
				return bandage.Action{}, fmt.Errorf("rules: rule %q: action report: %w", id, err)
			}
			if !reasonRe.MatchString(raw.Reason) {
				return bandage.Action{}, fmt.Errorf("rules: rule %q: action report: reason: %q is not a valid slug (want %s)",
					id, raw.Reason, reasonRe.String())
			}
			ttl, err := parseTTL(raw.TTL)
			if err != nil {
				return bandage.Action{}, fmt.Errorf("rules: rule %q: action report: report.ttl: %w", id, err)
			}
			return bandage.Action{Report: &bandage.ReportAction{Reason: raw.Reason, TTL: ttl}}, nil
		case "log":
			return parseLogAction(id, val)
		case "goto", "jump":
			return parseChainAction(id, name, val)
		case "stop":
			return bandage.Action{}, fmt.Errorf("rules: rule %q: action stop takes no options", id)
		default:
			return bandage.Action{}, fmt.Errorf("rules: rule %q: unknown action %q", id, name)
		}
	default:
		return bandage.Action{}, fmt.Errorf("rules: rule %q: action must be a name or a name with options", id)
	}
}

// parseChainAction parses `goto: <chain>` and `jump: <chain>`. The
// target's existence and the graph's acyclicity are validated after all
// chains are built (see validateChainGraph).
func parseChainAction(id, name string, val *yaml.Node) (bandage.Action, error) {
	var target string
	if err := val.Decode(&target); err != nil || target == "" {
		return bandage.Action{}, fmt.Errorf("rules: rule %q: action %s: wants a chain name", id, name)
	}
	if name == "goto" {
		return bandage.Action{Goto: target}, nil
	}
	return bandage.Action{Jump: target}, nil
}

// parseLogAction parses `log: "level,message"` (flux's shape): exactly
// two comma-separated arguments — a debug/info/warn/error level and a
// message. The event and the rule's tracker reading are logged beside
// the message at evaluation time.
func parseLogAction(id string, val *yaml.Node) (bandage.Action, error) {
	if val.Kind != yaml.ScalarNode {
		return bandage.Action{}, fmt.Errorf("rules: rule %q: action log: wants a \"level,message\" string", id)
	}
	args := strings.Split(val.Value, ",")
	if len(args) != 2 {
		return bandage.Action{}, fmt.Errorf("rules: rule %q: action log: wants \"level,message\", got %q", id, val.Value)
	}
	var level slog.Level
	switch strings.ToLower(args[0]) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return bandage.Action{}, fmt.Errorf("rules: rule %q: action log: unknown level %q (want debug, info, warn or error)", id, args[0])
	}
	return bandage.Action{Log: &bandage.LogAction{Level: level, Message: args[1]}}, nil
}

// knownActions is the full action vocabulary of format version 0.
var knownActions = map[string]bool{"report": true, "log": true, "goto": true, "jump": true, "stop": true}

// parseTTL parses a report ttl: Go duration strings plus "d" for days
// (7d, 24h, 30m). It must be positive.
func parseTTL(s string) (time.Duration, error) {
	if s == "" {
		return 0, errors.New("required")
	}
	d, err := time.ParseDuration(s)
	if err != nil && strings.HasSuffix(s, "d") {
		// Day counts (7d) are not Go durations.
		var days int64
		if days, err = strconv.ParseInt(strings.TrimSuffix(s, "d"), 10, 64); err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		d = time.Duration(days) * 24 * time.Hour
	}
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	if d <= 0 {
		return 0, fmt.Errorf("must be positive, got %q", s)
	}
	return d, nil
}
