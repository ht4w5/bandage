// Package filter holds the filter language: a predicate over an Event
// deciding whether a rule considers the event.
//
// Format version 0 supports only the "any" filter. Parse keeps webjail's
// signature and positioned ParseError shape; the full webjail expression
// language slots into this seam later.
package filter

import (
	"errors"
	"fmt"
	"strings"

	bandage "github.com/HT4w5/bandage/internal/domain"
)

// Filter is a predicate over an Event.
type Filter interface {
	Match(event *bandage.Event) (matched bool)
}

// FilterAny matches every event.
type FilterAny struct{}

func (*FilterAny) Match(*bandage.Event) bool { return true }

// ParseError reports a filter expression syntax error at a 1-based line
// and column within the expression (webjail shape).
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

// Parse parses a filter expression into a Filter. Only "any" parses in
// format version 0; anything else is a positioned *ParseError.
func Parse(src string) (Filter, error) {
	if strings.TrimSpace(src) == "" {
		return nil, &ParseError{Line: 1, Col: 1, Msg: "empty filter expression"}
	}
	if strings.TrimSpace(src) == "any" {
		return &FilterAny{}, nil
	}
	return nil, &ParseError{Line: 1, Col: 1,
		Msg: fmt.Sprintf("unsupported filter expression %q (only \"any\" is supported in format version 0)", src),
		err: errors.New("unsupported filter expression"),
	}
}
