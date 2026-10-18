// Package nginx parses nginx JSON access-log lines (flux log format:
// escape=json, $msec/$remote_addr/$request_method/$uri/$status/
// $body_bytes_sent/$http_user_agent) into domain events.
//
// The $msec time keeps its fractional part (DECISIONS §7); every required
// field is validated and a bad one drops the line. Host, server and
// duration are reserved and ignored; unknown fields are ignored.
package nginx

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"

	bandage "github.com/HT4w5/bandage/internal/domain"
)

// decodeOpts keeps the log-format contract of the historic map decoder:
// duplicate member names resolve last-wins instead of being rejected, and
// raw non-UTF-8 bytes (nginx escape=json passes them through unescaped)
// are accepted and kept as U+FFFD instead of dropping the line.
var decodeOpts = json.JoinOptions(
	jsontext.AllowDuplicateNames(true),
	jsontext.AllowInvalidUTF8(true),
)

// FieldError reports an invalid required (or typed) field. Its identity —
// the field name and message — is the parser's field-level error contract;
// drop accounting counts every parse error alike.
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

// fieldValue is one captured JSON member value. A JSON string is decoded
// once at capture time into str; every other kind keeps its exact bytes
// in raw (a zero-copy view of the input line, valid for the duration of
// Parse). A field absent from the line is not present at all.
type fieldValue struct {
	str     string
	raw     []byte
	isStr   bool
	present bool
}

// UnmarshalJSONFrom captures the member's value without copying (except
// the decoded string) or validating; the typed helpers below do the
// validating. The last member wins on duplicate names, matching map
// semantics.
func (v *fieldValue) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	*v = fieldValue{present: true}
	if d.PeekKind() == jsontext.KindString {
		tok, err := d.ReadToken()
		if err != nil {
			return err
		}
		v.str = tok.String()
		v.isStr = true
		return nil
	}
	raw, err := d.ReadValue()
	if err != nil {
		return err
	}
	v.raw = raw
	return nil
}

// isNull reports whether the member was present as a JSON null.
func isNull(v fieldValue) bool {
	return v.present && !v.isStr && string(v.raw) == "null"
}

// rawFields holds the captured values of the known log fields. Unknown
// and reserved fields are never captured.
type rawFields struct {
	Time   fieldValue `json:"time"`
	Client fieldValue `json:"client"`
	Method fieldValue `json:"method"`
	URL    fieldValue `json:"url"`
	Status fieldValue `json:"status"`
	Sent   fieldValue `json:"sent"`
	Agent  fieldValue `json:"agent"`
}

// Parse maps one raw log line onto a domain Event, validating all
// required fields. Malformed lines and invalid fields return an error and
// the event is dropped.
func (p *Parser) Parse(line []byte) (bandage.Event, error) {
	var fields rawFields
	if err := json.Unmarshal(line, &fields, decodeOpts); err != nil {
		return bandage.Event{}, fmt.Errorf("parse nginx json: %w", err)
	}

	ev := bandage.Event{SizeBytes: bandage.FilesizeUnknown}

	raw, err := require(fields.Time, "time")
	if err != nil {
		return bandage.Event{}, err
	}
	if ev.Time, err = parseTime(raw); err != nil {
		return bandage.Event{}, &FieldError{Field: "time", Msg: err.Error()}
	}

	if raw, err = require(fields.Client, "client"); err != nil {
		return bandage.Event{}, err
	}
	s, err := parseString(raw)
	if err != nil {
		return bandage.Event{}, &FieldError{Field: "client", Msg: err.Error()}
	}
	if ev.RemoteAddr, err = netip.ParseAddr(s); err != nil {
		return bandage.Event{}, &FieldError{Field: "client", Msg: "not an IP address"}
	}

	if raw, err = require(fields.Method, "method"); err != nil {
		return bandage.Event{}, err
	}
	if ev.Method, err = parseNonEmptyString(raw); err != nil {
		return bandage.Event{}, &FieldError{Field: "method", Msg: err.Error()}
	}

	if raw, err = require(fields.URL, "url"); err != nil {
		return bandage.Event{}, err
	}
	if ev.Path, err = parseNonEmptyString(raw); err != nil {
		return bandage.Event{}, &FieldError{Field: "url", Msg: err.Error()}
	}

	if raw, err = require(fields.Status, "status"); err != nil {
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

	if raw, err = require(fields.Sent, "sent"); err != nil {
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
	if raw = fields.Agent; raw.present && !isNull(raw) {
		if ev.Agent, err = parseString(raw); err != nil {
			return bandage.Event{}, &FieldError{Field: "agent", Msg: err.Error()}
		}
	}

	// host, server, duration are accepted and ignored; unknown fields too.
	return ev, nil
}

// require returns a required field's value: absent and null fields are
// reported as missing.
func require(v fieldValue, name string) (fieldValue, error) {
	if !v.present || isNull(v) {
		return fieldValue{}, &FieldError{Field: name, Msg: "required field missing"}
	}
	return v, nil
}

func parseString(v fieldValue) (string, error) {
	if !v.isStr {
		return "", errors.New("must be a string")
	}
	return v.str, nil
}

func parseNonEmptyString(v fieldValue) (string, error) {
	s, err := parseString(v)
	if err != nil {
		return "", err
	}
	if s == "" {
		return "", errors.New("must not be empty")
	}
	return s, nil
}

func parseInt(v fieldValue) (int64, error) {
	// A JSON string never parses as an integer, whatever its content.
	if v.isStr {
		return 0, errors.New("must be an integer")
	}
	n, err := strconv.ParseInt(string(v.raw), 10, 64)
	if err != nil {
		return 0, errors.New("must be an integer")
	}
	return n, nil
}

// parseTime parses the $msec time: Unix seconds with an optional
// fraction, as a JSON string or JSON number. The fraction is kept.
func parseTime(v fieldValue) (time.Time, error) {
	text := v.str
	if !v.isStr {
		text = string(v.raw)
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
		var buf [9]byte // nanoseconds: fractions are truncated or padded to 9 digits
		w := copy(buf[:], frac)
		for ; w < len(buf); w++ {
			buf[w] = '0'
		}
		n, err := strconv.ParseInt(string(buf[:]), 10, 64)
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
