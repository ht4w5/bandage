package track

import (
	"errors"
	"testing"
)

// Quantity parsing: plain numbers for rate and replay, decimal human sizes for
// bandwidth - each optionally followed by "/s".

func TestParseNumber(t *testing.T) {
	tests := []struct {
		in      string
		want    float64
		wantErr bool
	}{
		{in: "10", want: 10},
		{in: "0", want: 0},
		{in: "0.1", want: 0.1},
		{in: "10/s", want: 10},
		{in: "0.1/s", want: 0.1},
		{in: "", wantErr: true},
		{in: "1MB", wantErr: true},
		{in: "-1", wantErr: true},
		{in: "10/x", wantErr: true},
		{in: "abc", wantErr: true},
		{in: "1e3", wantErr: true},
		{in: "inf", wantErr: true},
		{in: "NaN", wantErr: true},
		{in: ".5", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseNumber(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseNumber(%q) = %v, want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseNumber(%q) error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ParseNumber(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseBytes(t *testing.T) {
	tests := []struct {
		in      string
		want    float64
		wantErr bool
	}{
		{in: "10", want: 10},
		{in: "512", want: 512},
		{in: "0", want: 0},
		{in: "1kB", want: 1e3},
		{in: "1MB", want: 1e6},
		{in: "100GB", want: 1e11},
		{in: "1.5MB", want: 1.5e6},
		{in: "2m", want: 2e6},
		{in: "1MiB", want: 1e6},
		{in: "1TB", want: 1e12},
		{in: "1PB", want: 1e15},
		{in: "1MB/s", want: 1e6},
		{in: "0/s", want: 0},
		{in: "512/s", want: 512},
		{in: "", wantErr: true},
		{in: "-1MB", wantErr: true},
		{in: "1q", wantErr: true},
		{in: "1MB/x", wantErr: true},
		{in: "abc", wantErr: true},
		{in: "1.2.3", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseBytes(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseBytes(%q) = %v, want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseBytes(%q) error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ParseBytes(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseQuantityErrorsWrapValue(t *testing.T) {
	_, err := ParseBytes("1q")
	if err == nil {
		t.Fatal("want error")
	}
	var pe *QuantityError
	if !errors.As(err, &pe) {
		t.Fatalf("error %v is not a *QuantityError", err)
	}
	if pe.Value != "1q" {
		t.Errorf("QuantityError.Value = %q, want %q", pe.Value, "1q")
	}
}
