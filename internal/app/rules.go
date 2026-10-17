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

// rawTracker keeps leak and volume as nodes: presence is validated
// ("explicit leak and volume") and replay's volume may be a scalar or a
// volume-method block (DECISIONS §8). A missing node has Kind zero.
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
	rule.FilterSource = flt

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

// parseTracker builds the rule's tracker config: explicit leak and
// volume. The cache TTL (volume/leak) is fixed at build for rate and
// bandwidth; replay re-derives it per event from its volume method
// output (DECISIONS §8), so its build-time TTL stays zero.
func parseTracker(id string, raw *rawTracker) (*bandage.TrackerConfig, error) {
	var kind bandage.TrackKind
	switch raw.Track {
	case "":
		return nil, fmt.Errorf("rules: rule %q: tracker.track: required (want %q, %q or %q)",
			id, bandage.TrackRate, bandage.TrackBandwidth, bandage.TrackReplay)
	case string(bandage.TrackRate), string(bandage.TrackBandwidth), string(bandage.TrackReplay):
		kind = bandage.TrackKind(raw.Track)
	default:
		return nil, fmt.Errorf("rules: rule %q: tracker.track: unknown tracker kind %q (want %q, %q or %q)",
			id, raw.Track, bandage.TrackRate, bandage.TrackBandwidth, bandage.TrackReplay)
	}

	leak, err := parseTrackerQuantity(id, "tracker.leak", &raw.Leak, kind)
	if err != nil {
		return nil, err
	}
	if leak < 0 {
		return nil, fmt.Errorf("rules: rule %q: tracker.leak: must be non-negative", id)
	}
	prefix, err := parseTargetPrefix(id, &raw.TargetPrefix)
	if err != nil {
		return nil, err
	}

	cfg := &bandage.TrackerConfig{Kind: kind, Leak: leak, TargetPrefix: prefix}
	if kind == bandage.TrackReplay {
		// Replay volume is a plain scalar (the constant method) or a
		// volume-method block scaling tolerated download equivalents
		// with file size (DECISIONS §8).
		volume, method, err := parseReplayVolume(id, &raw.Volume)
		if err != nil {
			return nil, err
		}
		cfg.Volume, cfg.VolumeMethod = volume, method
		return cfg, nil
	}
	if raw.Volume.Kind != 0 && raw.Volume.Kind != yaml.ScalarNode {
		return nil, fmt.Errorf("rules: rule %q: tracker.volume: must be a quantity (volume methods are replay-only)", id)
	}
	volume, err := parseTrackerQuantity(id, "tracker.volume", &raw.Volume, kind)
	if err != nil {
		return nil, err
	}
	if volume <= 0 {
		return nil, fmt.Errorf("rules: rule %q: tracker.volume: must be positive", id)
	}
	cfg.Volume = volume
	cfg.TTL = bandage.TTL(leak, volume)
	return cfg, nil
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

// parseTrackerQuantity parses one explicit scalar tracker quantity per
// kind: rate uses plain numbers (request counts), replay plain numbers
// (fractions per second), bandwidth byte quantities. Errors name the
// rule and the field (DECISIONS §5).
func parseTrackerQuantity(id, field string, node *yaml.Node, kind bandage.TrackKind) (float64, error) {
	if node == nil || node.Kind == 0 {
		return 0, fmt.Errorf("rules: rule %q: %s: required", id, field)
	}
	if node.Kind != yaml.ScalarNode {
		return 0, fmt.Errorf("rules: rule %q: %s: must be a quantity", id, field)
	}
	var (
		v   float64
		err error
	)
	if kind == bandage.TrackBandwidth {
		v, err = track.ParseBytes(node.Value)
	} else {
		v, err = track.ParseNumber(node.Value)
	}
	if err != nil {
		return 0, fmt.Errorf("rules: rule %q: %s: %w", id, field, err)
	}
	return v, nil
}

// parseReplayVolume parses the replay tracker's volume: a plain scalar
// number (the constant method, returned as the constant volume) or a
// volume-method block (returned as a VolumeMethod). A volume method is
// replay-only — rate and bandwidth reject non-scalar volumes at load.
func parseReplayVolume(id string, node *yaml.Node) (float64, bandage.VolumeMethod, error) {
	if node == nil || node.Kind == 0 {
		return 0, nil, fmt.Errorf("rules: rule %q: tracker.volume: required", id)
	}
	if node.Kind == yaml.ScalarNode {
		v, err := track.ParseNumber(node.Value)
		if err != nil {
			return 0, nil, fmt.Errorf("rules: rule %q: tracker.volume: %w", id, err)
		}
		if v <= 0 {
			return 0, nil, fmt.Errorf("rules: rule %q: tracker.volume: must be positive", id)
		}
		return v, nil, nil
	}
	if node.Kind != yaml.MappingNode {
		return 0, nil, fmt.Errorf("rules: rule %q: tracker.volume: must be a quantity or a volume method", id)
	}
	method, err := parseVolumeMethod(id, node)
	return 0, method, err
}

// volumeMethodKeys is each volume method's strict parameter set
// (besides the method name itself): unknown keys are load errors (spec:
// strict decode).
var volumeMethodKeys = map[string]map[string]bool{
	"constant":       {"value": true},
	"clamped-linear": {"intercept": true, "slope": true, "min": true, "max": true},
	"inverse-square": {"base": true, "pivot": true},
	"step":           {"threshold": true, "volume_low": true, "volume_high": true},
}

// parseVolumeMethod builds one replay volume method from its block,
// validating each method's parameters at load (DECISIONS §8).
func parseVolumeMethod(id string, node *yaml.Node) (bandage.VolumeMethod, error) {
	fields := map[string]*yaml.Node{}
	for i := 0; i+1 < len(node.Content); i += 2 {
		fields[node.Content[i].Value] = node.Content[i+1]
	}
	method := fields["method"]
	if method == nil || method.Kind != yaml.ScalarNode {
		return nil, fmt.Errorf("rules: rule %q: tracker.volume.method: required (want constant, clamped-linear, inverse-square or step)", id)
	}
	allowed := volumeMethodKeys[method.Value]
	if allowed == nil {
		return nil, fmt.Errorf("rules: rule %q: tracker.volume.method: unknown volume method %q (want constant, clamped-linear, inverse-square or step)", id, method.Value)
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if key := node.Content[i].Value; key != "method" && !allowed[key] {
			return nil, fmt.Errorf("rules: rule %q: tracker.volume: unknown key %q in volume method block", id, key)
		}
	}

	switch method.Value {
	case "constant":
		value, err := volumeNumber(id, "value", fields["value"])
		if err != nil {
			return nil, err
		}
		if value <= 0 {
			return nil, fmt.Errorf("rules: rule %q: tracker.volume.value: must be positive", id)
		}
		return track.ConstantVolume(value), nil

	case "clamped-linear":
		intercept, err := volumeNumber(id, "intercept", fields["intercept"])
		if err != nil {
			return nil, err
		}
		slope, err := volumeNumber(id, "slope", fields["slope"])
		if err != nil {
			return nil, err
		}
		minV, err := volumeNumber(id, "min", fields["min"])
		if err != nil {
			return nil, err
		}
		maxV, err := volumeNumber(id, "max", fields["max"])
		if err != nil {
			return nil, err
		}
		if minV < 0 {
			return nil, fmt.Errorf("rules: rule %q: tracker.volume.min: must be non-negative", id)
		}
		if maxV < minV {
			return nil, fmt.Errorf("rules: rule %q: tracker.volume.max: must be >= min", id)
		}
		return track.ClampedLinearVolume{Intercept: intercept, Slope: slope, Min: minV, Max: maxV}, nil

	case "inverse-square":
		base, err := volumeNumber(id, "base", fields["base"])
		if err != nil {
			return nil, err
		}
		pivot, err := volumeSize(id, "pivot", fields["pivot"])
		if err != nil {
			return nil, err
		}
		if base < 0 {
			return nil, fmt.Errorf("rules: rule %q: tracker.volume.base: must be non-negative", id)
		}
		if pivot <= 0 {
			return nil, fmt.Errorf("rules: rule %q: tracker.volume.pivot: must be positive", id)
		}
		return track.InverseSquareVolume{Base: base, Pivot: pivot}, nil

	case "step":
		threshold, err := volumeSize(id, "threshold", fields["threshold"])
		if err != nil {
			return nil, err
		}
		low, err := volumeNumber(id, "volume_low", fields["volume_low"])
		if err != nil {
			return nil, err
		}
		high, err := volumeNumber(id, "volume_high", fields["volume_high"])
		if err != nil {
			return nil, err
		}
		if threshold <= 0 {
			return nil, fmt.Errorf("rules: rule %q: tracker.volume.threshold: must be positive", id)
		}
		if low < 0 {
			return nil, fmt.Errorf("rules: rule %q: tracker.volume.volume_low: must be non-negative", id)
		}
		if high < 0 {
			return nil, fmt.Errorf("rules: rule %q: tracker.volume.volume_high: must be non-negative", id)
		}
		return track.StepVolume{Threshold: threshold, VolumeLow: low, VolumeHigh: high}, nil
	}
	return nil, fmt.Errorf("rules: rule %q: tracker.volume.method: unknown volume method %q", id, method.Value)
}

// volumeNumber parses one plain numeric volume-method parameter.
func volumeNumber(id, key string, node *yaml.Node) (float64, error) {
	if node == nil {
		return 0, fmt.Errorf("rules: rule %q: tracker.volume.%s: required", id, key)
	}
	if node.Kind != yaml.ScalarNode {
		return 0, fmt.Errorf("rules: rule %q: tracker.volume.%s: invalid number %q", id, key, node.Value)
	}
	v, err := strconv.ParseFloat(node.Value, 64)
	if err != nil {
		return 0, fmt.Errorf("rules: rule %q: tracker.volume.%s: invalid number %q", id, key, node.Value)
	}
	return v, nil
}

// volumeSize parses one byte-size volume-method parameter (flux decimal
// human sizes: 1GB = 1e9; DECISIONS §5).
func volumeSize(id, key string, node *yaml.Node) (float64, error) {
	if node == nil {
		return 0, fmt.Errorf("rules: rule %q: tracker.volume.%s: required", id, key)
	}
	if node.Kind != yaml.ScalarNode {
		return 0, fmt.Errorf("rules: rule %q: tracker.volume.%s: invalid quantity %q", id, key, node.Value)
	}
	v, err := track.ParseBytes(node.Value)
	if err != nil {
		return 0, fmt.Errorf("rules: rule %q: tracker.volume.%s: %w", id, key, err)
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
