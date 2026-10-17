package filter

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

// Parse trees, error positions and validation wrapping for the filter
// language (webjail's v0 grammar). Authored fresh from the grammar and
// position rules: webjail ships no filter tests (DECISIONS §2).

// treeString renders a parsed filter as a canonical s-expression so parse
// trees (precedence, n-ary flattening) are assertable. It lives in the
// test file: the AST shape is internal, the language contract is not.
func treeString(f Filter) string {
	switch v := f.(type) {
	case *FilterAny:
		return "any"
	case *FilterNone:
		return "none"
	case *FilterAnd:
		return "and(" + treeList(v.filters) + ")"
	case *FilterOr:
		return "or(" + treeList(v.filters) + ")"
	case *FilterNot:
		return "not(" + treeString(v.filter) + ")"
	case *FilterRemoteAddr:
		return "src " + v.prefix.String()
	case *FilterMethod:
		return "method " + v.method
	case *FilterPath:
		return `path "` + v.path + `"`
	case *FilterPathPrefix:
		return `path prefix "` + v.prefix + `"`
	case *FilterPathSuffix:
		return `path suffix "` + v.suffix + `"`
	case *FilterPathKeyword:
		return `path keyword "` + v.keyword + `"`
	case *FilterAgent:
		return `agent "` + v.agent + `"`
	case *FilterAgentKeyword:
		return `agent keyword "` + v.keyword + `"`
	case *FilterStatus:
		return "status " + itoa(v.status)
	case *FilterStatusClass:
		return "status class " + itoa(v.class)
	case *FilterSentAtLeast:
		return "sent >= " + ltoa(v.limit)
	case *FilterSentAtMost:
		return "sent <= " + ltoa(v.limit)
	default:
		return "?"
	}
}

func treeList(filters []Filter) string {
	parts := make([]string, len(filters))
	for i, f := range filters {
		parts[i] = treeString(f)
	}
	return strings.Join(parts, ", ")
}

func itoa(n int) string   { return strconv.Itoa(n) }
func ltoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestParseTrees(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		// Primitives.
		{"any", "any", "any"},
		{"none", "none", "none"},
		{"src address becomes full-length prefix", "src 10.0.0.1", "src 10.0.0.1/32"},
		{"src prefix", "src 10.0.0.0/8", "src 10.0.0.0/8"},
		{"src ipv6 address", "src 2001:db8::1", "src 2001:db8::1/128"},
		{"src ipv6 prefix", "src 2001:db8::/64", "src 2001:db8::/64"},
		{"method", "method GET", "method GET"},
		{"path exact", `path "/x"`, `path "/x"`},
		{"path prefix", `path prefix "/x"`, `path prefix "/x"`},
		{"path suffix", `path suffix ".iso"`, `path suffix ".iso"`},
		{"path keyword", `path keyword "iso"`, `path keyword "iso"`},
		{"agent exact", `agent "curl"`, `agent "curl"`},
		{"agent keyword", `agent keyword "curl"`, `agent keyword "curl"`},
		{"status code", "status 404", "status 404"},
		{"status class", "status class 5", "status class 5"},
		{"sent gte bare", "sent >= 1024", "sent >= 1024"},
		{"sent lte bare", "sent <= 0", "sent <= 0"},
		{"sent binary k", "sent >= 10k", "sent >= 10240"},
		{"sent binary m case-insensitive", "sent >= 10M", "sent >= 10485760"},
		{"sent binary g", "sent >= 2g", "sent >= 2147483648"},

		// String escapes unescape to the matched value.
		{"string escapes", `path "a\"b\\c\nd\te"`, "path \"a\"b\\c\nd\te\""},

		// Precedence: not > and > or; chains flatten to n-ary nodes.
		{"and chain flattens", "any and none and any", "and(any, none, any)"},
		{"or chain flattens", "any or none or any", "or(any, none, any)"},
		{"and binds tighter than or", "any and none or any and none", "or(and(any, none), and(any, none))"},
		{"not binds tighter than and", "not any and none", "and(not(any), none)"},
		{"not binds tighter than or", "not any or none", "or(not(any), none)"},
		{"double not", "not not any", "not(not(any))"},
		{"parens override", "(any or none) and any", "and(or(any, none), any)"},
		{"nested parens", "not (any and (none or any))", "not(and(any, or(none, any)))"},
		{"mixed symbols", "any && none || ! any", "or(and(any, none), not(any))"},

		// Newlines are whitespace; positions reset per line (see errors).
		{"newlines separate tokens", "any and\n none", "and(any, none)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := Parse(tt.src)
			if err != nil {
				t.Fatalf("Parse(%q) error: %v", tt.src, err)
			}
			if got := treeString(f); got != tt.want {
				t.Errorf("Parse(%q) tree = %s, want %s", tt.src, got, tt.want)
			}
		})
	}
}

func TestParseErrorPositions(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string // full Error() output: filter: L:C: message
	}{
		// Empty input errors point at end of input.
		{"empty expression", "", "filter: 1:1: empty filter expression"},
		{"whitespace expression", "  ", "filter: 1:3: empty filter expression"},

		// Lexer errors at the offending sequence.
		{"lone ampersand", "& any", `filter: 1:1: expected "&&"`},
		{"lone pipe", "| any", `filter: 1:1: expected "||"`},
		{"lone gt", "sent > 1", `filter: 1:6: expected ">="`},
		{"lone lt", "sent < 1", `filter: 1:6: expected "<="`},
		{"number out of range", "sent >= 9223372036854775808", `filter: 1:9: number "9223372036854775808" is out of range`},
		{"unterminated string", `path "abc`, "filter: 1:6: unterminated string"},
		{"trailing backslash in string", `path "abc\`, "filter: 1:6: unterminated string"},
		{"bad escape points at escape char", `path "a\qb"`, `filter: 1:9: unknown escape sequence \q`},

		// Parser errors at the offending token.
		{"missing operand", "any and", "filter: 1:8: unexpected end of filter, expected an operand"},
		{"trailing token", "any any", `filter: 1:5: unexpected "any", expected end of filter`},
		{"unknown keyword", "foo", `filter: 1:1: unknown keyword "foo"`},
		{"not without operand", "not", "filter: 1:4: unexpected end of filter, expected an operand"},
		{"empty parens", "()", `filter: 1:2: unexpected ")", expected an operand`},
		{"unclosed paren points at opening paren", "(any", `filter: 1:5: missing ")" for "(" at 1:1`},

		// Primitive argument errors.
		{"src missing value", "src", `filter: 1:4: expected a bare IP address or prefix after "src", got end of filter`},
		{"src bad address", "src 1.2.3.4.5", `filter: 1:5: invalid IP address or prefix "1.2.3.4.5"`},
		{"src bad prefix length", "src 10.0.0.0/33", `filter: 1:5: invalid IP address or prefix "10.0.0.0/33"`},
		{"method missing value", "method", `filter: 1:7: expected a bare method name after "method", got end of filter`},
		{"method number value", "method 5m", `filter: 1:8: expected a bare method name after "method", got "5m"`},
		{"path missing value", "path", `filter: 1:5: expected a quoted text value after "path", got end of filter`},
		{"path bare word value", "path x", `filter: 1:6: expected a quoted text value after "path", got "x"`},
		{"path prefix missing value", `path prefix`, `filter: 1:12: expected a quoted text value after "path", got end of filter`},
		{"path empty value", `path ""`, "filter: 1:6: path must not be empty"},
		{"path keyword empty value", `path keyword ""`, "filter: 1:14: keyword must not be empty"},
		{"agent empty value", `agent ""`, "filter: 1:7: agent must not be empty"},
		{"status missing value", "status", `filter: 1:7: expected a status code after "status", got end of filter`},
		{"status out of range", "status 20", "filter: 1:8: status must be within [100, 599]"},
		{"status size unit", "status 200k", `filter: 1:8: size units are only allowed after "sent"`},
		{"status class missing value", "status class", `filter: 1:13: expected a status class after "status", got end of filter`},
		{"status class out of range", "status class 9", "filter: 1:14: class must be within [1, 5]"},
		{"sent missing operator", "sent", `filter: 1:5: expected ">=" or "<=" after "sent", got end of filter`},
		{"sent bare number operator", "sent 5", `filter: 1:6: expected ">=" or "<=" after "sent", got "5"`},
		{"sent non-size value", `sent >= x`, `filter: 1:9: expected a size after "sent", got "x"`},
		{"sent decimal size is a word", "sent >= 0.1", `filter: 1:9: expected a size after "sent", got "0.1"`},
		{"sent MB spelling is a word", "sent >= 10MB", `filter: 1:9: expected a size after "sent", got "10MB"`},
		{"sent size overflow", "sent >= 9223372036854775807g", "filter: 1:9: size is out of range"},

		// Positions are 1-based rune counts; newlines reset the column.
		{"newline resets column", "any and\nfoo", `filter: 2:1: unknown keyword "foo"`},
		{"columns count runes", `path keyword "ä" and foo`, `filter: 1:22: unknown keyword "foo"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.src)
			if err == nil {
				t.Fatalf("Parse(%q) succeeded, want error", tt.src)
			}
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("Parse(%q) error %v is not a *ParseError", tt.src, err)
			}
			if got := err.Error(); got != tt.want {
				t.Errorf("Parse(%q) error = %q, want %q", tt.src, got, tt.want)
			}
			if pe.Line < 1 || pe.Col < 1 {
				t.Errorf("ParseError position %d:%d is not 1-based", pe.Line, pe.Col)
			}
		})
	}
}

// Validation errors wrap their cause and stay unwrappable at the value
// token's position.
func TestParseErrorUnwrapsValidation(t *testing.T) {
	_, err := Parse("status 20")
	if err == nil {
		t.Fatal("Parse succeeded, want error")
	}
	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("error %v is not a *ParseError", err)
	}
	if pe.Unwrap() == nil {
		t.Fatal("Unwrap() = nil, want the wrapped validation error")
	}
	if !strings.Contains(pe.Unwrap().Error(), "status") {
		t.Errorf("Unwrap() = %v, want the range validation error", pe.Unwrap())
	}
}

// The grammar doc examples parse.
func TestParseExamples(t *testing.T) {
	for _, src := range []string{
		`src 10.0.0.0/8 and (method GET or method HEAD) and path prefix "/api"`,
		`not agent keyword "curl" and sent >= 10m`,
		"status class 5 or none",
	} {
		if _, err := Parse(src); err != nil {
			t.Errorf("Parse(%q) error: %v", src, err)
		}
	}
}
