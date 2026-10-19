package bandage

import (
	"fmt"
	"strings"
)

// Level is the domain's log level enum (debug, info, warn, error).
// Fatal and panic are deliberately not representable (ADR 0005).
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
// "error"), case-insensitive.
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
