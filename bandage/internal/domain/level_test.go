package domain

import (
	"testing"
)

// TestParseLevel covers the four-word vocabulary and its errors.
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

// TestLevelStringRoundTrip checks the words round-trip through ParseLevel.
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
