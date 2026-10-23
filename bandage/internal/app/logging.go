package app

import (
	"io"
	"maps"
	"slices"
	"time"

	"github.com/rs/zerolog"

	"github.com/HT4w5/webmedkit/bandage/internal/domain"
)

// NewLogger builds the program-wide logger (ADR 0005): fixed
// console-style text on w with timestamps, filtered at level.
func NewLogger(w io.Writer, level domain.Level) zerolog.Logger {
	return zerolog.New(zerolog.ConsoleWriter{
		Out:        w,
		NoColor:    true,
		TimeFormat: time.RFC3339,
	}).Level(zerologLevel(level)).With().Timestamp().Logger()
}

// zerologLevel maps the four domain level words onto zerolog levels
// (no fatal/panic: a rule can never exit). Unmapped values are info.
func zerologLevel(level domain.Level) zerolog.Level {
	switch level {
	case domain.LevelDebug:
		return zerolog.DebugLevel
	case domain.LevelInfo:
		return zerolog.InfoLevel
	case domain.LevelWarn:
		return zerolog.WarnLevel
	case domain.LevelError:
		return zerolog.ErrorLevel
	default:
		return zerolog.InfoLevel
	}
}

// domainLogger adapts zerolog to the domain Logger port; fields are
// attached in sorted key order so records are deterministic.
type domainLogger struct {
	logger zerolog.Logger
}

func (a domainLogger) Log(level domain.Level, msg string, fields map[string]any) {
	e := a.logger.WithLevel(zerologLevel(level))
	for _, k := range slices.Sorted(maps.Keys(fields)) {
		e = e.Interface(k, fields[k])
	}
	e.Msg(msg)
}
