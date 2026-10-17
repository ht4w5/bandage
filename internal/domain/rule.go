package bandage

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// TrackKind is a tracker kind: what a tracker accumulates per target.
type TrackKind string

const (
	// TrackRate accumulates requests (flux FREQ-BUCKET).
	TrackRate TrackKind = "rate"
	// TrackBandwidth accumulates sent bytes (flux BYTE-BUCKET).
	TrackBandwidth TrackKind = "bandwidth"
	// TrackReplay accumulates the transferred fraction of an estimated
	// file size (flux FILE-RATIO-BUCKET). Its state is keyed per
	// (Target, path) and its volume may scale with the file size through
	// a VolumeMethod.
	TrackReplay TrackKind = "replay"
)

// VolumeMethod computes a tracker's tolerated volume from the estimated
// file size in bytes: the replay tracker's volume is "tolerated download
// equivalents" scaling with object size (PLAN §1; DECISIONS §8). The
// implementations (constant, clamped-linear, inverse-square, step) live
// in the track module; only the replay tracker configures one.
type VolumeMethod interface {
	Volume(sizeBytes float64) float64
	// String renders the method for the -check plan.
	String() string
}

// TrackerConfig is a rule's leaky-bucket tracker: explicit leak and
// volume with the cache-entry TTL derived as volume/leak.
type TrackerConfig struct {
	Kind TrackKind
	Leak float64
	// Volume is the constant volume: request counts for rate, bytes for
	// bandwidth, tolerated download equivalents for a plain scalar
	// replay volume.
	Volume float64
	// VolumeMethod computes the replay volume from the estimated file
	// size instead of the constant Volume; nil for rate and bandwidth
	// and for a scalar replay volume.
	VolumeMethod VolumeMethod
	// TTL is the cache-entry TTL derived at build (volume/leak) for rate
	// and bandwidth. Replay derives it per event from the volume-method
	// output (DECISIONS §8) and leaves this zero.
	TTL time.Duration
	// TargetPrefix is the tracker's target aggregation, defaulted at
	// build (DefaultTargetPrefix).
	TargetPrefix TargetPrefix
}

// VolumeFor returns the tolerated volume for an estimated file size in
// bytes: the volume method's output when configured, the constant
// volume otherwise.
func (c *TrackerConfig) VolumeFor(sizeBytes float64) float64 {
	if c.VolumeMethod != nil {
		return c.VolumeMethod.Volume(sizeBytes)
	}
	return c.Volume
}

// VolumeDesc renders the volume configuration for the -check plan: the
// volume method's description or the constant volume.
func (c *TrackerConfig) VolumeDesc() string {
	if c.VolumeMethod != nil {
		return c.VolumeMethod.String()
	}
	return strconv.FormatFloat(c.Volume, 'f', -1, 64)
}

// ReportAction upserts a report for the tracker's target on match. It is
// the only write path to the report table.
type ReportAction struct {
	// Reason is the machine-readable slug feeding downstream ban rules.
	Reason string
	// TTL is the report's expiry since the trigger wall-clock time.
	TTL time.Duration
}

// LogAction emits debug output for a match: flux's "level,message"
// shape (e.g. `log: "debug,ROUTE:"`), logging the event and the rule's
// tracker reading. It is never terminal.
type LogAction struct {
	// Level is the slog level parsed from the "level" argument.
	Level slog.Level
	// Message is the "message" argument (flux's prefix).
	Message string
}

// ParseLevel parses one level argument ("debug", "info", "warn" or
// "error", case-insensitive). It is the one level parser: the log
// action's "level,message" shape (spec story 18) and the -log-level
// flag share it.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown log level %q (want debug, info, warn or error)", s)
	}
}

// Action is a step executed when a rule matches; the actions of a match
// run in order. Exactly one field is set. The vocabulary is report, log,
// goto, jump and stop (the chains/actions ticket).
type Action struct {
	Report *ReportAction
	Log    *LogAction
	// Goto names the target chain: it runs, then this chain ends after
	// the rule's remaining actions have run.
	Goto string
	// Jump names the target chain: it runs, then this chain resumes.
	Jump string
	// Stop ends this chain after the rule's remaining actions have run.
	Stop bool
}

// ActionVisitor handles one action variant. The evaluation dispatcher
// and the -check describer both walk action lists through Action.Accept,
// so the five-case action vocabulary has a single dispatch point.
type ActionVisitor interface {
	VisitReport(*ReportAction) error
	VisitLog(*LogAction) error
	VisitGoto(target string) error
	VisitJump(target string) error
	VisitStop() error
}

// Accept dispatches the action to the matching visitor method. Exactly
// one field of Action is set; a zero Action visits nothing.
func (a Action) Accept(v ActionVisitor) error {
	switch {
	case a.Report != nil:
		return v.VisitReport(a.Report)
	case a.Log != nil:
		return v.VisitLog(a.Log)
	case a.Goto != "":
		return v.VisitGoto(a.Goto)
	case a.Jump != "":
		return v.VisitJump(a.Jump)
	case a.Stop:
		return v.VisitStop()
	}
	return nil
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
	ID string
	// FilterSource is the effective filter expression as written
	// ("any" when omitted), kept for the -check plan print.
	FilterSource string
	Filter       Matcher
	Tracker      *TrackerConfig
	Actions      []Action
}

// Terminal reports whether a match of this rule ends traversal of its
// chain after the rule's full action list has run (PLAN §1: a rule
// containing report, goto or stop is terminal; other chains are still
// evaluated for the event).
func (r Rule) Terminal() bool {
	for _, a := range r.Actions {
		if a.Report != nil || a.Goto != "" || a.Stop {
			return true
		}
	}
	return false
}

// Chain is an ordered group of rules traversed for each event.
type Chain struct {
	Name  string
	Rules []Rule
}
