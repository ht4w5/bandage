package bandage

import (
	"testing"
)

// ParseLevel is the one level parser for the log action's
// "level,message" shape and the log.level config key (spec: the
// vocabulary stays exactly debug, info, warn, error — never zerolog's
// fatal/panic, which could exit the process).
func TestParseLevel(t *testing.T) {
	tests := []struct {
		in      string
		want    Level
		wantErr bool
	}{
		{in: "debug", want: LevelDebug},
		{in: "info", want: LevelInfo},
		{in: "warn", want: LevelWarn},
		{in: "error", want: LevelError},
		{in: "DEBUG", want: LevelDebug},
		{in: "Warn", want: LevelWarn},
		{in: "verbose", wantErr: true},
		{in: "", wantErr: true},
		{in: "fatal", wantErr: true},
		{in: "panic", wantErr: true},
		{in: "trace", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseLevel(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseLevel(%q) = %v, want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseLevel(%q) error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ParseLevel(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// Level.String is the canonical word — the vocabulary is exactly the
// four words, round-tripped through ParseLevel.
func TestLevelStringRoundTrip(t *testing.T) {
	for _, l := range []Level{LevelDebug, LevelInfo, LevelWarn, LevelError} {
		got, err := ParseLevel(l.String())
		if err != nil {
			t.Fatalf("ParseLevel(%q) error: %v", l.String(), err)
		}
		if got != l {
			t.Errorf("ParseLevel(%q) = %v, want %v", l.String(), got, l)
		}
	}
}
