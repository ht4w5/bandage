package filter

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/HT4w5/bandage/internal/bandage"
)

// baseEvent is the event the table cases vary; zero fields never match.
func baseEvent() bandage.Event {
	return bandage.Event{
		RemoteAddr: mustAddr("203.0.113.7"),
		Method:     "GET",
		Path:       "/releases/24.04.iso",
		Agent:      "curl/8.5.0",
		Status:     200,
		SentBytes:  1024,
	}
}

func mustAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

func mustPrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return p
}

func TestFilterMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
		mut  func(*bandage.Event) // applied to baseEvent
		want bool
	}{
		// any / none.
		{"any matches", "any", nil, true},
		{"none does not match", "none", nil, false},
		{"not none matches", "not none", nil, true},

		// src: exact address or prefix containment.
		{"src exact address", "src 203.0.113.7", nil, true},
		{"src exact address mismatch", "src 203.0.113.8", nil, false},
		{"src prefix contains", "src 203.0.113.0/24", nil, true},
		{"src prefix excludes", "src 198.51.100.0/24", nil, false},
		{"src single-address prefix", "src 203.0.113.7/32", nil, true},
		{"src ipv6 exact", "src 2001:db8::1", func(e *bandage.Event) {
			e.RemoteAddr = mustAddr("2001:db8::1")
		}, true},
		{"src ipv6 prefix", "src 2001:db8::/64", func(e *bandage.Event) {
			e.RemoteAddr = mustAddr("2001:db8::42")
		}, true},
		{"src ipv4 does not match ipv6", "src 203.0.113.7", func(e *bandage.Event) {
			e.RemoteAddr = mustAddr("2001:db8::1")
		}, false},

		// method: exact and case-sensitive.
		{"method exact", "method GET", nil, true},
		{"method mismatch", "method POST", nil, false},
		{"method case-sensitive", "method get", nil, false},

		// path: exact / prefix / suffix / keyword, case-sensitive.
		{"path exact", `path "/releases/24.04.iso"`, nil, true},
		{"path exact mismatch", `path "/releases"`, nil, false},
		{"path prefix match", `path prefix "/releases"`, nil, true},
		{"path prefix mismatch", `path prefix "/api"`, nil, false},
		{"path prefix case-sensitive", `path prefix "/RELEASES"`, nil, false},
		{"path suffix match", `path suffix ".iso"`, nil, true},
		{"path suffix mismatch", `path suffix ".img"`, nil, false},
		{"path keyword match", `path keyword "24.04"`, nil, true},
		{"path keyword mismatch", `path keyword "22.04"`, nil, false},

		// agent: exact / keyword, case-sensitive.
		{"agent exact", `agent "curl/8.5.0"`, nil, true},
		{"agent exact mismatch", `agent "curl"`, nil, false},
		{"agent exact case-sensitive", `agent "CURL/8.5.0"`, nil, false},
		{"agent keyword match", `agent keyword "curl"`, nil, true},
		{"agent keyword mismatch", `agent keyword "wget"`, nil, false},

		// status: code or class.
		{"status exact", "status 200", nil, true},
		{"status mismatch", "status 404", nil, false},
		{"status class 2", "status class 2", nil, true},
		{"status class 3 on 200", "status class 3", nil, false},
		{"status class 4 on 404", "status class 4", func(e *bandage.Event) { e.Status = 404 }, true},
		{"status class 5 on 599", "status class 5", func(e *bandage.Event) { e.Status = 599 }, true},
		{"status class 1 on 100", "status class 1", func(e *bandage.Event) { e.Status = 100 }, true},

		// sent: >= / <= with binary units, inclusive boundaries.
		{"sent gte inclusive boundary", "sent >= 1024", nil, true},
		{"sent gte above", "sent >= 1023", nil, true},
		{"sent gte below", "sent >= 1025", nil, false},
		{"sent lte inclusive boundary", "sent <= 1024", nil, true},
		{"sent lte below", "sent <= 1025", nil, true},
		{"sent lte above", "sent <= 1023", nil, false},
		{"sent k is binary", "sent >= 1k", func(e *bandage.Event) { e.SentBytes = 1024 }, true},
		{"sent k decimal does not match", "sent >= 1k", func(e *bandage.Event) { e.SentBytes = 1000 }, false},
		{"sent m is binary", "sent <= 1m", func(e *bandage.Event) { e.SentBytes = 1 << 20 }, true},
		{"sent g is binary", "sent >= 1g", func(e *bandage.Event) { e.SentBytes = 1 << 30 }, true},
		{"sent zero limit", "sent >= 0", nil, true},

		// combinators: precedence not > and > or, parentheses override.
		{"and all match", `method GET and status 200`, nil, true},
		{"and one mismatch", `method GET and status 404`, nil, false},
		{"or one match", `method POST or status 200`, nil, true},
		{"or none match", `method POST or status 404`, nil, false},
		{"not mismatch matches", `not status 404`, nil, true},
		{"not match does not match", `not status 200`, nil, false},
		{"and binds tighter than or", `method POST or status 200 and method GET`, nil, true},
		{"and-or precedence excludes", `method POST or status 404 and method GET`, nil, false},
		{"parens override precedence", `(method POST or status 200) and method GET`, nil, true},
		{"parens change result", `(method POST or status 404) and method GET`, nil, false},
		{"not binds tighter than and", `not status 404 and method GET`, nil, true},
		{"not-and precedence", `not (status 404 and method GET)`, nil, true},

		// Symbols are spelled words.
		{"symbol and", `method GET && status 200`, nil, true},
		{"symbol or", `method POST || status 200`, nil, true},
		{"symbol not", `! status 404`, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := Parse(tt.src)
			if err != nil {
				t.Fatalf("Parse(%q) error: %v", tt.src, err)
			}
			ev := baseEvent()
			if tt.mut != nil {
				tt.mut(&ev)
			}
			if got := f.Match(&ev); got != tt.want {
				t.Errorf("Parse(%q).Match(%+v) = %v, want %v", tt.src, ev, got, tt.want)
			}
		})
	}
}

// The constructors validate their arguments.
func TestConstructorValidation(t *testing.T) {
	any, none := &FilterAny{}, &FilterNone{}
	validPrefix := mustPrefix("10.0.0.0/8")
	tests := []struct {
		name string
		err  error
	}{
		{"and empty", func() error { _, err := NewFilterAnd(); return err }()},
		{"and nil member", func() error { _, err := NewFilterAnd(any, nil); return err }()},
		{"or empty", func() error { _, err := NewFilterOr(); return err }()},
		{"or nil member", func() error { _, err := NewFilterOr(nil, none); return err }()},
		{"not nil", func() error { _, err := NewFilterNot(nil); return err }()},
		{"invalid prefix", func() error { _, err := NewFilterRemoteAddr(netip.Prefix{}); return err }()},
		{"empty method", func() error { _, err := NewFilterMethod(""); return err }()},
		{"empty path", func() error { _, err := NewFilterPath(""); return err }()},
		{"empty path prefix", func() error { _, err := NewFilterPathPrefix(""); return err }()},
		{"empty path suffix", func() error { _, err := NewFilterPathSuffix(""); return err }()},
		{"empty path keyword", func() error { _, err := NewFilterPathKeyword(""); return err }()},
		{"empty agent", func() error { _, err := NewFilterAgent(""); return err }()},
		{"empty agent keyword", func() error { _, err := NewFilterAgentKeyword(""); return err }()},
		{"status below range", func() error { _, err := NewFilterStatus(99); return err }()},
		{"status above range", func() error { _, err := NewFilterStatus(600); return err }()},
		{"class below range", func() error { _, err := NewFilterStatusClass(0); return err }()},
		{"class above range", func() error { _, err := NewFilterStatusClass(6); return err }()},
		{"sent at least negative", func() error { _, err := NewFilterSentAtLeast(-1); return err }()},
		{"sent at most negative", func() error { _, err := NewFilterSentAtMost(-1); return err }()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatal("constructor succeeded, want error")
			}
		})
	}
	// Valid constructions succeed.
	if _, err := NewFilterAnd(any, none); err != nil {
		t.Errorf("NewFilterAnd error: %v", err)
	}
	if _, err := NewFilterOr(any, none); err != nil {
		t.Errorf("NewFilterOr error: %v", err)
	}
	if _, err := NewFilterNot(none); err != nil {
		t.Errorf("NewFilterNot error: %v", err)
	}
	if _, err := NewFilterRemoteAddr(validPrefix); err != nil {
		t.Errorf("NewFilterRemoteAddr error: %v", err)
	}
}

// ParseError stays a *ParseError through the public API (errors.As).
func TestParseErrorType(t *testing.T) {
	_, err := Parse("bogus")
	if err == nil {
		t.Fatal("Parse succeeded, want error")
	}
	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("error %v is not a *ParseError", err)
	}
}
