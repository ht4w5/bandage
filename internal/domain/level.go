package bandage

import (
	"fmt"
	"strings"
)

// Level is the domain's log level enum: the log action's and log.level
// config's four-word vocabulary (debug, info, warn, error). It replaces
// the stdlib level type so the domain keeps its dependency rule (ADR
// 0005): zerolog's fatal/panic are deliberately not representable — a
// rule must never be able to exit the process.
type Level string

const (
	LevelDebug Level = "debug"
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

// String renders the canonical level word.
func (l Level) String() string { return string(l) }

// ParseLevel parses one level argument ("debug", "info", "warn" or
// "error", case-insensitive). It is the one level parser: the log
// action's "level,message" shape and the log.level config key share
// it.
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return LevelDebug, nil
	case "info":
		return LevelInfo, nil
	case "warn":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	default:
		return "", fmt.Errorf("unknown log level %q (want debug, info, warn or error)", s)
	}
}
