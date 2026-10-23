package filter

import (
	"fmt"
	"strconv"
	"unicode"
)

type tokKind int

const (
	tokEOF tokKind = iota
	tokWord
	tokString
	tokNumber
	tokAnd
	tokOr
	tokNot
	tokGte
	tokLte
	tokLParen
	tokRParen
)

// token is a lexical token of a filter expression. Line and col are 1-based
// positions of the token's first rune within the expression.
type token struct {
	kind tokKind
	// Word text, unescaped string content, number spelling, or operator spelling.
	text string
	// Value of tokNumber.
	num int64
	// Size unit of tokNumber: 0 or one of 'k', 'm', 'g'.
	unit rune
	line int
	col  int
}

// desc renders the token for error messages.
func (t token) desc() string {
	if t.kind == tokEOF {
		return "end of filter"
	}
	return fmt.Sprintf("%q", t.text)
}

// lexer splits a filter expression into tokens. Positions are 1-based and
// count runes; newlines are ordinary whitespace.
type lexer struct {
	runes []rune
	pos   int
	line  int
	col   int
}

func newLexer(src string) *lexer {
	return &lexer{runes: []rune(src), line: 1, col: 1}
}

func (l *lexer) errAt(line, col int, format string, args ...any) error {
	return &ParseError{Line: line, Col: col, Msg: fmt.Sprintf(format, args...)}
}

func (l *lexer) peekRune() rune {
	if l.pos >= len(l.runes) {
		return 0
	}
	return l.runes[l.pos]
}

func (l *lexer) nextRune() rune {
	if l.pos >= len(l.runes) {
		return 0
	}
	r := l.runes[l.pos]
	l.pos++
	if r == '\n' {
		l.line++
		l.col = 1
	} else {
		l.col++
	}
	return r
}

func (l *lexer) skipSpace() {
	for l.pos < len(l.runes) && unicode.IsSpace(l.runes[l.pos]) {
		l.nextRune()
	}
}

// isWordRune reports whether r can appear in a bare word; whitespace and operator characters terminate a word.
func isWordRune(r rune) bool {
	if unicode.IsSpace(r) {
		return false
	}
	switch r {
	case '(', ')', '"', '<', '>', '!', '|', '&':
		return false
	}
	return true
}

func (l *lexer) next() (token, error) {
	l.skipSpace()
	line, col := l.line, l.col
	if l.pos >= len(l.runes) {
		return token{kind: tokEOF, line: line, col: col}, nil
	}
	r := l.runes[l.pos]
	switch r {
	case '(':
		l.nextRune()
		return token{kind: tokLParen, text: "(", line: line, col: col}, nil
	case ')':
		l.nextRune()
		return token{kind: tokRParen, text: ")", line: line, col: col}, nil
	case '!':
		l.nextRune()
		return token{kind: tokNot, text: "!", line: line, col: col}, nil
	case '&':
		l.nextRune()
		if l.peekRune() != '&' {
			return token{}, l.errAt(line, col, `expected "&&"`)
		}
		l.nextRune()
		return token{kind: tokAnd, text: "&&", line: line, col: col}, nil
	case '|':
		l.nextRune()
		if l.peekRune() != '|' {
			return token{}, l.errAt(line, col, `expected "||"`)
		}
		l.nextRune()
		return token{kind: tokOr, text: "||", line: line, col: col}, nil
	case '>':
		l.nextRune()
		if l.peekRune() != '=' {
			return token{}, l.errAt(line, col, `expected ">="`)
		}
		l.nextRune()
		return token{kind: tokGte, text: ">=", line: line, col: col}, nil
	case '<':
		l.nextRune()
		if l.peekRune() != '=' {
			return token{}, l.errAt(line, col, `expected "<="`)
		}
		l.nextRune()
		return token{kind: tokLte, text: "<=", line: line, col: col}, nil
	case '"':
		return l.scanString(line, col)
	default:
		return l.scanWord(line, col)
	}
}

func (l *lexer) scanString(line, col int) (token, error) {
	l.nextRune() // opening quote
	var text []rune
	for l.pos < len(l.runes) {
		r := l.nextRune()
		switch r {
		case '"':
			return token{kind: tokString, text: string(text), line: line, col: col}, nil
		case '\\':
			eLine, eCol := l.line, l.col
			e := l.nextRune()
			switch e {
			case '"':
				text = append(text, '"')
			case '\\':
				text = append(text, '\\')
			case 'n':
				text = append(text, '\n')
			case 't':
				text = append(text, '\t')
			case 0:
				return token{}, l.errAt(line, col, "unterminated string")
			default:
				return token{}, l.errAt(eLine, eCol, `unknown escape sequence \%c`, e)
			}
		default:
			text = append(text, r)
		}
	}
	return token{}, l.errAt(line, col, "unterminated string")
}

func (l *lexer) scanWord(line, col int) (token, error) {
	start := l.pos
	for l.pos < len(l.runes) && isWordRune(l.runes[l.pos]) {
		l.nextRune()
	}
	text := string(l.runes[start:l.pos])
	tok := token{kind: tokWord, text: text, line: line, col: col}
	switch text {
	case "and":
		tok.kind = tokAnd
	case "or":
		tok.kind = tokOr
	case "not":
		tok.kind = tokNot
	}
	if tok.kind != tokWord {
		return tok, nil
	}

	// A word of digits, optionally suffixed with a size unit, is a number.
	digits := text
	if r := []rune(digits); len(r) > 1 && isSizeUnit(r[len(r)-1]) {
		tok.unit = unicode.ToLower(r[len(r)-1])
		digits = digits[:len(digits)-1] // unit letters are ASCII
	}
	if !isDigits(digits) {
		tok.unit = 0
		return tok, nil
	}
	num, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return token{}, l.errAt(line, col, "number %q is out of range", text)
	}
	tok.kind = tokNumber
	tok.num = num
	return tok, nil
}

func isSizeUnit(r rune) bool {
	switch unicode.ToLower(r) {
	case 'k', 'm', 'g':
		return true
	}
	return false
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
