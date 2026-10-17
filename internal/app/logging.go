package app

import (
	"io"
	"maps"
	"slices"
	"time"

	"github.com/rs/zerolog"

	bandage "github.com/HT4w5/bandage/internal/domain"
)

// NewLogger builds the program-wide logger (spec: Logging, ADR 0005):
// zerolog rendering is fixed console-style text on w with timestamps,
// filtered at the given level. Construction and level policy live here
// alone — the command resolves the level (flag > config > default) and
// passes the one logger to the daemon and the adapters; tests capture
// records at the daemon's logger option.
func NewLogger(w io.Writer, level bandage.Level) zerolog.Logger {
	return zerolog.New(zerolog.ConsoleWriter{
		Out:        w,
		NoColor:    true,
		TimeFormat: time.RFC3339,
	}).Level(zerologLevel(level)).With().Timestamp().Logger()
}

// zerologLevel maps the domain's four level words onto zerolog levels.
// The domain enum has no fatal/panic (ADR 0005): a rule can never exit
// the process. An unmapped value (only possible for an unvalidated
// Level) falls back to info.
func zerologLevel(level bandage.Level) zerolog.Level {
	switch level {
	case bandage.LevelDebug:
		return zerolog.DebugLevel
	case bandage.LevelInfo:
		return zerolog.InfoLevel
	case bandage.LevelWarn:
		return zerolog.WarnLevel
	case bandage.LevelError:
		return zerolog.ErrorLevel
	default:
		return zerolog.InfoLevel
	}
}

// domainLogger adapts the zerolog logger to the domain's Logger port.
// The adapter lives in the app wiring — no dedicated logging package
// "for now" (spec: Logging). Fields are attached in sorted key order so
// raw records are deterministic.
type domainLogger struct {
	logger zerolog.Logger
}

func (a domainLogger) Log(level bandage.Level, msg string, fields map[string]any) {
	e := a.logger.WithLevel(zerologLevel(level))
	for _, k := range slices.Sorted(maps.Keys(fields)) {
		e = e.Interface(k, fields[k])
	}
	e.Msg(msg)
}
