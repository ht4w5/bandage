package filter

import (
	"errors"
	"testing"

	bandage "github.com/HT4w5/bandage/internal/domain"
)

// Format version 0 supports only the "any" filter; the full webjail
// expression language lands with the filter-language ticket. Parse keeps
// webjail's signature and ParseError shape so it is a drop-in seam.
func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantErr bool
	}{
		{name: "any", src: "any"},
		{name: "any with surrounding whitespace", src: "  any\n"},
		{name: "empty expression", src: "", wantErr: true},
		{name: "none not supported yet", src: "none", wantErr: true},
		{name: "expression not supported yet", src: "src 10.0.0.0/8", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := Parse(tt.src)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Parse(%q) succeeded, want error", tt.src)
				}
				var pe *ParseError
				if !errors.As(err, &pe) {
					t.Fatalf("Parse(%q) error %v is not a *ParseError", tt.src, err)
				}
				if pe.Line != 1 || pe.Col != 1 {
					t.Errorf("ParseError position = %d:%d, want 1:1", pe.Line, pe.Col)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q) error: %v", tt.src, err)
			}
			if !f.Match(&bandage.Event{}) {
				t.Errorf("Parse(%q) does not match every event", tt.src)
			}
		})
	}
}

func TestParseErrorMessage(t *testing.T) {
	_, err := Parse("any and none")
	if err == nil {
		t.Fatal("want error")
	}
	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("error %v is not a *ParseError", err)
	}
	if got, want := pe.Error(), "filter: 1:1: "; len(got) < len(want) || got[:len(want)] != want {
		t.Errorf("Error() = %q, want prefix %q", got, want)
	}
}
