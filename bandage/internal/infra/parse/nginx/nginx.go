// Package nginx parses nginx JSON access-log lines in the bandage nginx
// log format (flux-compatible) into domain events: required fields
// validated, reserved and unknown ignored.
package nginx

import (
	jsonv1 "encoding/json"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/HT4w5/webmedkit/bandage/internal/domain"
)

// decodeOpts keeps the historic map-decoder contract: duplicate names resolve
// last-wins, raw non-UTF-8 bytes are kept as U+FFFD instead of dropping the line.
var decodeOpts = json.JoinOptions(
	jsontext.AllowDuplicateNames(true),
	jsontext.AllowInvalidUTF8(true),
)

// FieldError reports an invalid required (or typed) field; Field and Msg are
// the parser's field-level error contract (drop accounting counts all errors alike).
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

// fieldValue is one captured JSON member value: strings decode once into str,
// other kinds keep exact bytes in raw (zero-copy for Parse's duration).
type fieldValue struct {
	str     string
	raw     []byte
	isStr   bool
	present bool
}

// UnmarshalJSONFrom captures the member's value without copying (except the
// decoded string) or validating; last member wins on duplicate names.
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

// rawFields holds the captured values of the known log fields; unknown and
// reserved fields are never captured.
type rawFields struct {
	Time   fieldValue `json:"time"`
	Client fieldValue `json:"client"`
	Method fieldValue `json:"method"`
	URL    fieldValue `json:"url"`
	Status fieldValue `json:"status"`
	Sent   fieldValue `json:"sent"`
	Agent  fieldValue `json:"agent"`
}

// Parse maps one raw log line onto a domain Event, validating required fields;
// malformed lines and invalid fields return an error and the event is dropped.
func (p *Parser) Parse(line []byte) (domain.Event, error) {
	var fields rawFields
	if err := json.Unmarshal(line, &fields, decodeOpts); err != nil {
		return domain.Event{}, fmt.Errorf("parse nginx json: %w", legacyLineError(line, err))
	}

	ev := domain.Event{SizeBytes: domain.FilesizeUnknown}

	raw, err := require(fields.Time, "time")
	if err != nil {
		return domain.Event{}, err
	}
	if ev.Time, err = parseTime(raw); err != nil {
		return domain.Event{}, &FieldError{Field: "time", Msg: err.Error()}
	}

	if raw, err = require(fields.Client, "client"); err != nil {
		return domain.Event{}, err
	}
	s, err := parseString(raw)
	if err != nil {
		return domain.Event{}, &FieldError{Field: "client", Msg: err.Error()}
	}
	if ev.RemoteAddr, err = netip.ParseAddr(s); err != nil {
		return domain.Event{}, &FieldError{Field: "client", Msg: "not an IP address"}
	}

	if raw, err = require(fields.Method, "method"); err != nil {
		return domain.Event{}, err
	}
	if ev.Method, err = parseNonEmptyString(raw); err != nil {
		return domain.Event{}, &FieldError{Field: "method", Msg: err.Error()}
	}

	if raw, err = require(fields.URL, "url"); err != nil {
		return domain.Event{}, err
	}
	if ev.Path, err = parseNonEmptyString(raw); err != nil {
		return domain.Event{}, &FieldError{Field: "url", Msg: err.Error()}
	}

	if raw, err = require(fields.Status, "status"); err != nil {
		return domain.Event{}, err
	}
	n, err := parseInt(raw)
	if err != nil {
		return domain.Event{}, &FieldError{Field: "status", Msg: err.Error()}
	}
	if n < 100 || n > 599 {
		return domain.Event{}, &FieldError{Field: "status", Msg: "out of range 100-599"}
	}
	ev.Status = int(n)

	if raw, err = require(fields.Sent, "sent"); err != nil {
		return domain.Event{}, err
	}
	sent, err := parseInt(raw)
	if err != nil {
		return domain.Event{}, &FieldError{Field: "sent", Msg: err.Error()}
	}
	if sent < 0 {
		return domain.Event{}, &FieldError{Field: "sent", Msg: "must be non-negative"}
	}
	ev.SentBytes = sent

	// agent is optional; when present it must be a string (null = absent).
	if raw = fields.Agent; raw.present && !isNull(raw) {
		if ev.Agent, err = parseString(raw); err != nil {
			return domain.Event{}, &FieldError{Field: "agent", Msg: err.Error()}
		}
	}

	// host, server, duration are accepted and ignored; unknown fields too.
	return ev, nil
}

// legacyLineError re-renders a decode failure as the historic decoder's
// encoding/json v1 text, keeping the drop-log message byte-identical.
func legacyLineError(line []byte, err error) error {
	var serr *jsontext.SyntacticError
	if errors.As(err, &serr) {
		return legacySyntaxError(err)
	}
	// v1's whole-line scan: a type error at the first value must not
	// hide later syntax garbage.
	var raw jsontext.Value
	if serr := json.Unmarshal(line, &raw, decodeOpts); serr != nil {
		return legacySyntaxError(serr)
	}
	var sem *json.SemanticError
	if errors.As(err, &sem) {
		return legacySemanticError(err, sem)
	}
	return err
}

// legacySyntaxError re-renders a jsontext syntactic error as the historic
// v1 text: plain wording, no prefix or position info. Others pass through.
func legacySyntaxError(err error) error {
	var serr *jsontext.SyntacticError
	if !errors.As(err, &serr) || serr.Err == nil {
		return err
	}
	msg := "unexpected end of JSON input"
	if !errors.Is(serr.Err, io.ErrUnexpectedEOF) && !errors.Is(serr.Err, io.EOF) {
		msg = serr.Err.Error()
		if i := strings.Index(msg, " (expecting"); i >= 0 && !strings.Contains(msg, " in literal") {
			msg = msg[:i]
		}
		msg = syntaxErrorReplacer.Replace(msg)
	}
	return &syntaxTextError{text: msg, err: err}
}

// syntaxErrorReplacer maps v2 wording to the historical v1 rendering
// ("object key", "looking for ..." phrasings), as encoding/json's v1 shim.
var syntaxErrorReplacer = strings.NewReplacer(
	"object name", "object key",
	"at start of value", "looking for beginning of value",
	"at start of string", "looking for beginning of object key string",
	"after object value", "after object key:value pair",
	"in number", "in numeric literal",
)

// syntaxTextError presents legacy error text while keeping the error chain.
type syntaxTextError struct {
	text string
	err  error
}

func (e *syntaxTextError) Error() string { return e.text }
func (e *syntaxTextError) Unwrap() error { return e.err }

// legacySemanticError re-renders a v2 semantic (type) error as v1's
// UnmarshalTypeError text with the historic decode target.
func legacySemanticError(err error, serr *json.SemanticError) error {
	kind, ok := v1KindWords[serr.JSONKind]
	if !ok {
		return err
	}
	return &syntaxTextError{
		text: "json: cannot unmarshal " + kind + " into Go value of type " + legacyTargetType.String(),
		err:  err,
	}
}

// legacyTargetType is the historic decode target (map[string]
// json.RawMessage, rendering as "map[string]jsontext.Value").
var legacyTargetType = reflect.TypeOf(map[string]jsonv1.RawMessage(nil))

// v1KindWords maps a JSON kind onto encoding/json v1's UnmarshalTypeError kind words.
var v1KindWords = map[jsontext.Kind]string{
	jsontext.KindNull:        "null",
	jsontext.KindFalse:       "bool",
	jsontext.KindTrue:        "bool",
	jsontext.KindString:      "string",
	jsontext.KindNumber:      "number",
	jsontext.KindBeginObject: "object",
	jsontext.KindBeginArray:  "array",
}

// require returns a required field's value; absent and null fields report as missing.
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
