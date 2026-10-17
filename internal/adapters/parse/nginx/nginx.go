// Package nginx parses nginx JSON access-log lines (flux log format:
// escape=json, $msec/$remote_addr/$request_method/$uri/$status/
// $body_bytes_sent/$http_user_agent) into domain events.
//
// The $msec time keeps its fractional part (DECISIONS §7); every required
// field is validated and a bad one drops the line. Host, server and
// duration are reserved and ignored; unknown fields are ignored.
package nginx

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"

	bandage "github.com/HT4w5/bandage/internal/domain"
)

// FieldError reports an invalid required (or typed) field. The ingest
// driver counts these as invalid-field drops; other parse errors are
// malformed-line drops.
type FieldError struct {
	Field string
	Msg   string
}

func (e *FieldError) Error() string {
	return fmt.Sprintf("invalid field %q: %s", e.Field, e.Msg)
}

// Parser parses nginx JSON log lines into events. It is stateless and
// safe for concurrent use.
type Parser struct{}

// New returns a new nginx JSON parser.
func New() *Parser { return &Parser{} }

// Parse maps one raw log line onto a domain Event, validating all
// required fields. Malformed lines and invalid fields return an error and
// the event is dropped.
func (p *Parser) Parse(line []byte) (bandage.Event, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(line, &fields); err != nil {
		return bandage.Event{}, fmt.Errorf("parse nginx json: %w", err)
	}

	ev := bandage.Event{SizeBytes: bandage.FilesizeUnknown}

	raw, err := require(fields, "time")
	if err != nil {
		return bandage.Event{}, err
	}
	if ev.Time, err = parseTime(raw); err != nil {
		return bandage.Event{}, &FieldError{Field: "time", Msg: err.Error()}
	}

	if raw, err = require(fields, "client"); err != nil {
		return bandage.Event{}, err
	}
	s, err := parseString(raw)
	if err != nil {
		return bandage.Event{}, &FieldError{Field: "client", Msg: err.Error()}
	}
	if ev.RemoteAddr, err = netip.ParseAddr(s); err != nil {
		return bandage.Event{}, &FieldError{Field: "client", Msg: "not an IP address"}
	}

	if raw, err = require(fields, "method"); err != nil {
		return bandage.Event{}, err
	}
	if ev.Method, err = parseNonEmptyString(raw); err != nil {
		return bandage.Event{}, &FieldError{Field: "method", Msg: err.Error()}
	}

	if raw, err = require(fields, "url"); err != nil {
		return bandage.Event{}, err
	}
	if ev.Path, err = parseNonEmptyString(raw); err != nil {
		return bandage.Event{}, &FieldError{Field: "url", Msg: err.Error()}
	}

	if raw, err = require(fields, "status"); err != nil {
		return bandage.Event{}, err
	}
	n, err := parseInt(raw)
	if err != nil {
		return bandage.Event{}, &FieldError{Field: "status", Msg: err.Error()}
	}
	if n < 100 || n > 599 {
		return bandage.Event{}, &FieldError{Field: "status", Msg: "out of range 100–599"}
	}
	ev.Status = int(n)

	if raw, err = require(fields, "sent"); err != nil {
		return bandage.Event{}, err
	}
	sent, err := parseInt(raw)
	if err != nil {
		return bandage.Event{}, &FieldError{Field: "sent", Msg: err.Error()}
	}
	if sent < 0 {
		return bandage.Event{}, &FieldError{Field: "sent", Msg: "must be non-negative"}
	}
	ev.SentBytes = sent

	// agent is optional; when present it must be a string (null = absent).
	if raw, ok := fields["agent"]; ok && !isNull(raw) {
		if ev.Agent, err = parseString(raw); err != nil {
			return bandage.Event{}, &FieldError{Field: "agent", Msg: err.Error()}
		}
	}

	// host, server, duration are accepted and ignored; unknown fields too.
	return ev, nil
}

func require(fields map[string]json.RawMessage, name string) (json.RawMessage, error) {
	raw, ok := fields[name]
	if !ok || isNull(raw) {
		return nil, &FieldError{Field: name, Msg: "required field missing"}
	}
	return raw, nil
}

func isNull(raw json.RawMessage) bool {
	return string(raw) == "null"
}

func parseString(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", errors.New("must be a string")
	}
	return s, nil
}

func parseNonEmptyString(raw json.RawMessage) (string, error) {
	s, err := parseString(raw)
	if err != nil {
		return "", err
	}
	if s == "" {
		return "", errors.New("must not be empty")
	}
	return s, nil
}

func parseInt(raw json.RawMessage) (int64, error) {
	n, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil {
		return 0, errors.New("must be an integer")
	}
	return n, nil
}

// parseTime parses the $msec time: Unix seconds with an optional
// fraction, as a JSON string or JSON number. The fraction is kept.
func parseTime(raw json.RawMessage) (time.Time, error) {
	text := string(raw)
	if strings.HasPrefix(text, `"`) {
		s, err := parseString(raw)
		if err != nil {
			return time.Time{}, err
		}
		text = s
	}
	if text == "" || strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") {
		return time.Time{}, errors.New("must be Unix seconds with fraction")
	}

	secPart := text
	var nsec int64
	if i := strings.IndexByte(text, '.'); i >= 0 {
		secPart = text[:i]
		frac := text[i+1:]
		if frac == "" {
			return time.Time{}, errors.New("empty fraction")
		}
		for _, r := range frac {
			if !unicode.IsDigit(r) {
				return time.Time{}, errors.New("bad fraction")
			}
		}
		if len(frac) > 9 {
			frac = frac[:9]
		}
		for len(frac) < 9 {
			frac += "0"
		}
		n, err := strconv.ParseInt(frac, 10, 64)
		if err != nil {
			return time.Time{}, errors.New("bad fraction")
		}
		nsec = n
	}

	sec, err := strconv.ParseInt(secPart, 10, 64)
	if err != nil || secPart == "" {
		return time.Time{}, errors.New("must be Unix seconds with fraction")
	}
	return time.Unix(sec, nsec).UTC(), nil
}
