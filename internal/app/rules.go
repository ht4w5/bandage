package app

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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

// rawTargetPrefix is the tracker's target aggregation, per family:
// missing families default ({32, 64}); out-of-range values are load
// errors (spec: load-time validation of out-of-range target prefixes).
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
	prefix, err := parseTargetPrefix(id, &raw.TargetPrefix)
	if err != nil {
		return nil, err
	}

	return &bandage.TrackerConfig{
		Kind:         kind,
		Leak:         leak,
		Volume:       volume,
		TTL:          track.TTL(leak, volume),
		TargetPrefix: prefix,
	}, nil
}

// parseTargetPrefix builds the tracker's target aggregation: {32, 64} by
// default with each family defaulted independently; a value must fit its
// family (IPv4 up to 32, IPv6 up to 64 — IPv6 is never finer than /64)
// and be non-negative. Errors name the rule and the field (DECISIONS §5
// style).
func parseTargetPrefix(id string, raw *rawTargetPrefix) (bandage.TargetPrefix, error) {
	prefix := bandage.DefaultTargetPrefix
	if raw.IPv4 != nil {
		if *raw.IPv4 < 0 || *raw.IPv4 > 32 {
			return bandage.TargetPrefix{}, fmt.Errorf("rules: rule %q: tracker.target_prefix.ipv4: must be between 0 and 32, got %d", id, *raw.IPv4)
		}
		prefix.IPv4 = *raw.IPv4
	}
	if raw.IPv6 != nil {
		if *raw.IPv6 < 0 || *raw.IPv6 > 64 {
			return bandage.TargetPrefix{}, fmt.Errorf("rules: rule %q: tracker.target_prefix.ipv6: must be between 0 and 64, got %d", id, *raw.IPv6)
		}
		prefix.IPv6 = *raw.IPv6
	}
	return prefix, nil
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

// parseAction parses one action item. Only "report" executes in this
// ticket; the other action names are recognized and rejected gracefully
// until the chains/actions ticket lands.
func parseAction(id string, node *yaml.Node) (bandage.Action, error) {
	switch node.Kind {
	case yaml.ScalarNode:
		return bandage.Action{}, unsupportedAction(id, node.Value)
	case yaml.MappingNode:
		if len(node.Content) != 2 {
			return bandage.Action{}, fmt.Errorf("rules: rule %q: action must be a single name with options", id)
		}
		name, val := node.Content[0].Value, node.Content[1]
		if name != "report" {
			if isKnownAction(name) {
				return bandage.Action{}, unsupportedAction(id, name)
			}
			return bandage.Action{}, fmt.Errorf("rules: rule %q: unknown action %q", id, name)
		}

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
	default:
		return bandage.Action{}, fmt.Errorf("rules: rule %q: action must be a name or a name with options", id)
	}
}

// known-but-unsupported actions (later tickets).
var knownActions = map[string]bool{"report": true, "log": true, "goto": true, "jump": true, "stop": true}

func isKnownAction(name string) bool { return knownActions[name] }

func unsupportedAction(id, name string) error {
	return fmt.Errorf("rules: rule %q: action %q is not supported yet", id, name)
}

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
