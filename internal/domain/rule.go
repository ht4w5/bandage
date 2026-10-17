package bandage

import "time"

// TrackKind is a tracker kind: what a tracker accumulates per target.
type TrackKind string

const (
	// TrackRate accumulates requests (flux FREQ-BUCKET).
	TrackRate TrackKind = "rate"
	// TrackBandwidth accumulates sent bytes (flux BYTE-BUCKET).
	TrackBandwidth TrackKind = "bandwidth"
	// TrackReplay accumulates the transferred fraction of an estimated
	// file size (flux FILE-RATIO-BUCKET). Not supported in format
	// version 0 as loaded by this ticket.
	TrackReplay TrackKind = "replay"
)

// TrackerConfig is a rule's leaky-bucket tracker: explicit leak and
// volume with the cache-entry TTL derived as volume/leak.
type TrackerConfig struct {
	Kind   TrackKind
	Leak   float64
	Volume float64
	// TTL is the tracker cache entry TTL derived at build (volume/leak).
	TTL time.Duration
	// TargetPrefix is the tracker's target aggregation, defaulted at
	// build (DefaultTargetPrefix).
	TargetPrefix TargetPrefix
}

// ReportAction upserts a report for the tracker's target on match. It is
// the only write path to the report table.
type ReportAction struct {
	// Reason is the machine-readable slug feeding downstream ban rules.
	Reason string
	// TTL is the report's expiry since the trigger wall-clock time.
	TTL time.Duration
}

// Action is a step executed when a rule matches. Exactly one field is set;
// the action vocabulary grows with the chains/actions ticket.
type Action struct {
	Report *ReportAction
}

// Matcher decides whether a rule considers an event. The filter module's
// Filter satisfies it; the core stays dependency-free.
type Matcher interface {
	Match(event *Event) bool
}

// Rule is a named condition-action pairing: a filter, at most one
// tracker, and an ordered list of actions. A rule matches when its filter
// accepts the event and its tracker (if any) overflows. The ID namespaces
// the rule's tracker state.
type Rule struct {
	ID      string
	Filter  Matcher
	Tracker *TrackerConfig
	Actions []Action
}

// Chain is an ordered group of rules traversed for each event.
type Chain struct {
	Name  string
	Rules []Rule
}
