package filter

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
)

// ParseError reports a filter expression syntax error at a 1-based line and
// column within the expression.
type ParseError struct {
	Line int
	Col  int
	Msg  string
	err  error
}

func (pe *ParseError) Error() string {
	return fmt.Sprintf("filter: %d:%d: %s", pe.Line, pe.Col, pe.Msg)
}

// Unwrap returns the wrapped validation error, if any.
func (pe *ParseError) Unwrap() error { return pe.err }

// Parse parses a filter expression into a Filter, the predicate a rule uses
// to decide whether it considers an event.
//
// Grammar (EBNF). Whitespace and newlines separate tokens; there is no comment
// syntax:
//
//	expr      = orExpr ;
//	orExpr    = andExpr { ("or"  | "||") andExpr } ;
//	andExpr   = notExpr { ("and" | "&&") notExpr } ;
//	notExpr   = ("not" | "!") notExpr | primary ;
//	primary   = "(" expr ")" | primitive ;
//	primitive =
//	      "any" | "none"
//	    | "src"    ( addr | prefix )
//	    | "method" word
//	    | "path"   [ "prefix" | "suffix" | "keyword" ] string
//	    | "agent"  [ "keyword" ] string
//	    | "status" ( number | "class" number )
//	    | "sent"   ( ">=" | "<=" ) size ;
//	size      = number [ "k" | "m" | "g" ] ;  (* binary units *)
//
// Text values are double-quoted (escapes: \" \\ \n \t); identifiers and numbers
// are bare words. Keywords "and", "or" and "not" are reserved and must be
// quoted when used as values. Values match event fields exactly and
// case-sensitively, without normalization. "not" binds tighter than "and",
// which binds tighter than "or".
//
// Examples:
//
//	src 10.0.0.0/8 and (method GET or method HEAD) and path prefix "/api"
//	not agent keyword "curl" and sent >= 10m
//	status class 5 or none
//
// Parsing fails on the first error; the returned error is a *ParseError.
func Parse(src string) (Filter, error) {
	p := &parser{lex: newLexer(src)}
	if err := p.advance(); err != nil {
		return nil, err
	}
	if p.tok.kind == tokEOF {
		return nil, p.errorf(p.tok, "empty filter expression")
	}
	f, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.tok.kind != tokEOF {
		return nil, p.errorf(p.tok, "unexpected %s, expected end of filter", p.tok.desc())
	}
	return f, nil
}

type parser struct {
	lex *lexer
	tok token
}

func (p *parser) advance() error {
	tok, err := p.lex.next()
	if err != nil {
		return err
	}
	p.tok = tok
	return nil
}

func (p *parser) errorf(tok token, format string, args ...any) error {
	return &ParseError{Line: tok.line, Col: tok.col, Msg: fmt.Sprintf(format, args...)}
}

func (p *parser) wrap(tok token, err error) error {
	return &ParseError{Line: tok.line, Col: tok.col, Msg: err.Error(), err: err}
}

func (p *parser) parseOr() (Filter, error) {
	return p.parseBinary(tokOr, p.parseAnd, func(filters ...Filter) (Filter, error) {
		f, err := NewFilterOr(filters...)
		if err != nil {
			return nil, err
		}
		return f, nil
	})
}

func (p *parser) parseAnd() (Filter, error) {
	return p.parseBinary(tokAnd, p.parseNot, func(filters ...Filter) (Filter, error) {
		f, err := NewFilterAnd(filters...)
		if err != nil {
			return nil, err
		}
		return f, nil
	})
}

// parseBinary parses a left-associative chain of the operator kind, flattening
// its operands into a single n-ary filter.
func (p *parser) parseBinary(op tokKind, sub func() (Filter, error), combine func(...Filter) (Filter, error)) (Filter, error) {
	first, err := sub()
	if err != nil {
		return nil, err
	}
	if p.tok.kind != op {
		return first, nil
	}
	operands := []Filter{first}
	for p.tok.kind == op {
		if err := p.advance(); err != nil {
			return nil, err
		}
		next, err := sub()
		if err != nil {
			return nil, err
		}
		operands = append(operands, next)
	}
	return combine(operands...)
}

func (p *parser) parseNot() (Filter, error) {
	if p.tok.kind != tokNot {
		return p.parsePrimary()
	}
	if err := p.advance(); err != nil {
		return nil, err
	}
	inner, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	f, err := NewFilterNot(inner)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (p *parser) parsePrimary() (Filter, error) {
	switch p.tok.kind {
	case tokLParen:
		open := p.tok
		if err := p.advance(); err != nil {
			return nil, err
		}
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.tok.kind != tokRParen {
			return nil, p.errorf(p.tok, `missing ")" for "(" at %d:%d`, open.line, open.col)
		}
		if err := p.advance(); err != nil {
			return nil, err
		}
		return inner, nil
	case tokWord:
		return p.parsePrimitive()
	default:
		return nil, p.errorf(p.tok, "unexpected %s, expected an operand", p.tok.desc())
	}
}

func (p *parser) parsePrimitive() (Filter, error) {
	kw := p.tok
	if err := p.advance(); err != nil {
		return nil, err
	}
	switch kw.text {
	case "any":
		return &FilterAny{}, nil
	case "none":
		return &FilterNone{}, nil
	case "src":
		return p.parseSrc(kw)
	case "method":
		return p.parseMethod(kw)
	case "path":
		return p.parsePath(kw)
	case "agent":
		return p.parseAgent(kw)
	case "status":
		return p.parseStatus(kw)
	case "sent":
		return p.parseSent(kw)
	default:
		return nil, p.errorf(kw, "unknown keyword %q", kw.text)
	}
}

// takeText consumes a quoted text value.
func (p *parser) takeText(kw token) (token, error) {
	tok := p.tok
	if tok.kind != tokString {
		return token{}, p.errorf(tok, "expected a quoted text value after %q, got %s", kw.text, tok.desc())
	}
	if err := p.advance(); err != nil {
		return token{}, err
	}
	return tok, nil
}

// takeWord consumes a bare word value.
func (p *parser) takeWord(kw token, what string) (token, error) {
	tok := p.tok
	if tok.kind != tokWord {
		return token{}, p.errorf(tok, "expected a bare %s after %q, got %s", what, kw.text, tok.desc())
	}
	if err := p.advance(); err != nil {
		return token{}, err
	}
	return tok, nil
}

// takeNumber consumes a number value, rejecting size units unless allowUnit.
func (p *parser) takeNumber(kw token, what string, allowUnit bool) (token, error) {
	tok := p.tok
	if tok.kind != tokNumber {
		return token{}, p.errorf(tok, "expected a %s after %q, got %s", what, kw.text, tok.desc())
	}
	if tok.unit != 0 && !allowUnit {
		return token{}, p.errorf(tok, `size units are only allowed after "sent"`)
	}
	if err := p.advance(); err != nil {
		return token{}, err
	}
	return tok, nil
}

func (p *parser) parseSrc(kw token) (Filter, error) {
	tok, err := p.takeWord(kw, "IP address or prefix")
	if err != nil {
		return nil, err
	}
	var prefix netip.Prefix
	addr, aerr := netip.ParseAddr(tok.text)
	if aerr == nil {
		prefix, _ = addr.Prefix(addr.BitLen())
	} else {
		var perr error
		prefix, perr = netip.ParsePrefix(tok.text)
		if perr != nil {
			return nil, p.errorf(tok, "invalid IP address or prefix %q", tok.text)
		}
	}
	f, err := NewFilterRemoteAddr(prefix)
	if err != nil {
		return nil, p.wrap(tok, err)
	}
	return f, nil
}

func (p *parser) parseMethod(kw token) (Filter, error) {
	tok, err := p.takeWord(kw, "method name")
	if err != nil {
		return nil, err
	}
	f, err := NewFilterMethod(tok.text)
	if err != nil {
		return nil, p.wrap(tok, err)
	}
	return f, nil
}

func (p *parser) parsePath(kw token) (Filter, error) {
	mod, err := p.takeMod("prefix", "suffix", "keyword")
	if err != nil {
		return nil, err
	}
	tok, err := p.takeText(kw)
	if err != nil {
		return nil, err
	}
	switch mod {
	case "prefix":
		f, err := NewFilterPathPrefix(tok.text)
		if err != nil {
			return nil, p.wrap(tok, err)
		}
		return f, nil
	case "suffix":
		f, err := NewFilterPathSuffix(tok.text)
		if err != nil {
			return nil, p.wrap(tok, err)
		}
		return f, nil
	case "keyword":
		f, err := NewFilterPathKeyword(tok.text)
		if err != nil {
			return nil, p.wrap(tok, err)
		}
		return f, nil
	default:
		f, err := NewFilterPath(tok.text)
		if err != nil {
			return nil, p.wrap(tok, err)
		}
		return f, nil
	}
}

func (p *parser) parseAgent(kw token) (Filter, error) {
	mod, err := p.takeMod("keyword")
	if err != nil {
		return nil, err
	}
	tok, err := p.takeText(kw)
	if err != nil {
		return nil, err
	}
	if mod == "keyword" {
		f, err := NewFilterAgentKeyword(tok.text)
		if err != nil {
			return nil, p.wrap(tok, err)
		}
		return f, nil
	}
	f, err := NewFilterAgent(tok.text)
	if err != nil {
		return nil, p.wrap(tok, err)
	}
	return f, nil
}

func (p *parser) parseStatus(kw token) (Filter, error) {
	if p.tok.kind == tokWord && p.tok.text == "class" {
		if err := p.advance(); err != nil {
			return nil, err
		}
		tok, err := p.takeNumber(kw, "status class", false)
		if err != nil {
			return nil, err
		}
		f, err := NewFilterStatusClass(int(tok.num))
		if err != nil {
			return nil, p.wrap(tok, err)
		}
		return f, nil
	}
	tok, err := p.takeNumber(kw, "status code", false)
	if err != nil {
		return nil, err
	}
	f, err := NewFilterStatus(int(tok.num))
	if err != nil {
		return nil, p.wrap(tok, err)
	}
	return f, nil
}

func (p *parser) parseSent(kw token) (Filter, error) {
	op := p.tok
	if op.kind != tokGte && op.kind != tokLte {
		return nil, p.errorf(op, `expected ">=" or "<=" after %q, got %s`, kw.text, op.desc())
	}
	if err := p.advance(); err != nil {
		return nil, err
	}
	tok, err := p.takeNumber(kw, "size", true)
	if err != nil {
		return nil, err
	}
	limit, err := sizeLimit(tok)
	if err != nil {
		return nil, p.wrap(tok, err)
	}
	if op.kind == tokGte {
		f, err := NewFilterSentAtLeast(limit)
		if err != nil {
			return nil, p.wrap(tok, err)
		}
		return f, nil
	}
	f, err := NewFilterSentAtMost(limit)
	if err != nil {
		return nil, p.wrap(tok, err)
	}
	return f, nil
}

// takeMod consumes an optional bare modifier word from the given set and
// returns it, or "" if the next token is not one of them.
func (p *parser) takeMod(mods ...string) (string, error) {
	if p.tok.kind != tokWord {
		return "", nil
	}
	for _, m := range mods {
		if p.tok.text == m {
			if err := p.advance(); err != nil {
				return "", err
			}
			return m, nil
		}
	}
	return "", nil
}

// sizeLimit converts a number token with an optional binary size unit to bytes.
func sizeLimit(tok token) (int64, error) {
	mult := int64(1)
	switch tok.unit {
	case 'k':
		mult = 1 << 10
	case 'm':
		mult = 1 << 20
	case 'g':
		mult = 1 << 30
	}
	if tok.num > math.MaxInt64/mult {
		return 0, errors.New("size is out of range")
	}
	return tok.num * mult, nil
}
