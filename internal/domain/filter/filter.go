// Package filter holds the filter language: a predicate over an Event
// deciding whether a rule considers the event (webjail's v0 expression
// language, ported essentially as-is).
//
// Filters are built by Parse from expressions like
//
//	src 10.0.0.0/8 and (method GET or method HEAD) and path prefix "/api"
//
// and match events exactly and case-sensitively, without normalization.
package filter

import (
	"errors"
	"net/netip"
	"strings"

	bandage "github.com/HT4w5/bandage/internal/domain"
)

// Filter is a predicate over an Event.
type Filter interface {
	Match(event *bandage.Event) (matched bool)
}

// Logical Filters

// FilterAny matches every event.
type FilterAny struct{}

func (*FilterAny) Match(*bandage.Event) bool { return true }

// FilterNone matches no event.
type FilterNone struct{}

func (*FilterNone) Match(*bandage.Event) bool { return false }

// FilterAnd matches events every given filter matches.
type FilterAnd struct {
	filters []Filter
}

// NewFilterAnd returns a filter that matches events every given filter matches.
func NewFilterAnd(filters ...Filter) (*FilterAnd, error) {
	if err := checkFilters(filters); err != nil {
		return nil, err
	}
	return &FilterAnd{filters: filters}, nil
}

func (fa *FilterAnd) Match(event *bandage.Event) bool {
	for _, f := range fa.filters {
		if !f.Match(event) {
			return false
		}
	}
	return true
}

// FilterOr matches events at least one given filter matches.
type FilterOr struct {
	filters []Filter
}

// NewFilterOr returns a filter that matches events at least one given filter matches.
func NewFilterOr(filters ...Filter) (*FilterOr, error) {
	if err := checkFilters(filters); err != nil {
		return nil, err
	}
	return &FilterOr{filters: filters}, nil
}

func (fo *FilterOr) Match(event *bandage.Event) bool {
	for _, f := range fo.filters {
		if f.Match(event) {
			return true
		}
	}
	return false
}

// FilterNot matches events the given filter does not match.
type FilterNot struct {
	filter Filter
}

// NewFilterNot returns a filter that matches events the given filter does not match.
func NewFilterNot(filter Filter) (*FilterNot, error) {
	if filter == nil {
		return nil, errors.New("filter must not be nil")
	}
	return &FilterNot{filter: filter}, nil
}

func (fn *FilterNot) Match(event *bandage.Event) bool {
	return !fn.filter.Match(event)
}

func checkFilters(filters []Filter) error {
	if len(filters) == 0 {
		return errors.New("filters must not be empty")
	}
	for _, f := range filters {
		if f == nil {
			return errors.New("filters must not contain nil")
		}
	}
	return nil
}

// Field Filters

// FilterRemoteAddr matches events from within the given prefix.
type FilterRemoteAddr struct {
	prefix netip.Prefix
}

// NewFilterRemoteAddr returns a filter matching events whose remote
// address is contained in prefix.
func NewFilterRemoteAddr(prefix netip.Prefix) (*FilterRemoteAddr, error) {
	if !prefix.IsValid() {
		return nil, errors.New("prefix must be a valid IP prefix")
	}
	return &FilterRemoteAddr{prefix: prefix}, nil
}

func (fra *FilterRemoteAddr) Match(event *bandage.Event) bool {
	return fra.prefix.Contains(event.RemoteAddr)
}

// FilterMethod matches events with exactly the given method.
type FilterMethod struct {
	method string
}

// NewFilterMethod returns a filter matching events with exactly method.
func NewFilterMethod(method string) (*FilterMethod, error) {
	if method == "" {
		return nil, errors.New("method must not be empty")
	}
	return &FilterMethod{method: method}, nil
}

func (fm *FilterMethod) Match(event *bandage.Event) bool {
	return fm.method == event.Method
}

// FilterPath matches events with exactly the given path.
type FilterPath struct {
	path string
}

// NewFilterPath returns a filter matching events with exactly path.
func NewFilterPath(path string) (*FilterPath, error) {
	if path == "" {
		return nil, errors.New("path must not be empty")
	}
	return &FilterPath{path: path}, nil
}

func (fp *FilterPath) Match(event *bandage.Event) bool {
	return fp.path == event.Path
}

// FilterPathPrefix matches events whose path starts with the given prefix.
type FilterPathPrefix struct {
	prefix string
}

// NewFilterPathPrefix returns a filter matching events whose path starts
// with prefix.
func NewFilterPathPrefix(prefix string) (*FilterPathPrefix, error) {
	if prefix == "" {
		return nil, errors.New("prefix must not be empty")
	}
	return &FilterPathPrefix{prefix: prefix}, nil
}

func (fpp *FilterPathPrefix) Match(event *bandage.Event) bool {
	return strings.HasPrefix(event.Path, fpp.prefix)
}

// FilterPathSuffix matches events whose path ends with the given suffix.
type FilterPathSuffix struct {
	suffix string
}

// NewFilterPathSuffix returns a filter matching events whose path ends
// with suffix.
func NewFilterPathSuffix(suffix string) (*FilterPathSuffix, error) {
	if suffix == "" {
		return nil, errors.New("suffix must not be empty")
	}
	return &FilterPathSuffix{suffix: suffix}, nil
}

func (fps *FilterPathSuffix) Match(event *bandage.Event) bool {
	return strings.HasSuffix(event.Path, fps.suffix)
}

// FilterPathKeyword matches events whose path contains the given keyword.
type FilterPathKeyword struct {
	keyword string
}

// NewFilterPathKeyword returns a filter matching events whose path
// contains keyword.
func NewFilterPathKeyword(keyword string) (*FilterPathKeyword, error) {
	if keyword == "" {
		return nil, errors.New("keyword must not be empty")
	}
	return &FilterPathKeyword{keyword: keyword}, nil
}

func (fpk *FilterPathKeyword) Match(event *bandage.Event) bool {
	return strings.Contains(event.Path, fpk.keyword)
}

// FilterAgent matches events with exactly the given user agent.
type FilterAgent struct {
	agent string
}

// NewFilterAgent returns a filter matching events with exactly agent.
func NewFilterAgent(agent string) (*FilterAgent, error) {
	if agent == "" {
		return nil, errors.New("agent must not be empty")
	}
	return &FilterAgent{agent: agent}, nil
}

func (fa *FilterAgent) Match(event *bandage.Event) bool {
	return fa.agent == event.Agent
}

// FilterAgentKeyword matches events whose user agent contains the given
// keyword.
type FilterAgentKeyword struct {
	keyword string
}

// NewFilterAgentKeyword returns a filter matching events whose user agent
// contains keyword.
func NewFilterAgentKeyword(keyword string) (*FilterAgentKeyword, error) {
	if keyword == "" {
		return nil, errors.New("keyword must not be empty")
	}
	return &FilterAgentKeyword{keyword: keyword}, nil
}

func (fak *FilterAgentKeyword) Match(event *bandage.Event) bool {
	return strings.Contains(event.Agent, fak.keyword)
}

// FilterStatus matches events with exactly the given status code.
type FilterStatus struct {
	status int
}

// NewFilterStatus returns a filter matching events with exactly status
// (within [100, 599]).
func NewFilterStatus(status int) (*FilterStatus, error) {
	if status < 100 || status > 599 {
		return nil, errors.New("status must be within [100, 599]")
	}
	return &FilterStatus{status: status}, nil
}

func (fs *FilterStatus) Match(event *bandage.Event) bool {
	return fs.status == event.Status
}

// FilterStatusClass matches a status code class, e.g. 2 for 2xx.
type FilterStatusClass struct {
	class int
}

// NewFilterStatusClass returns a filter matching events whose status code
// class (within [1, 5]) is exactly class.
func NewFilterStatusClass(class int) (*FilterStatusClass, error) {
	if class < 1 || class > 5 {
		return nil, errors.New("class must be within [1, 5]")
	}
	return &FilterStatusClass{class: class}, nil
}

func (fsc *FilterStatusClass) Match(event *bandage.Event) bool {
	return event.Status/100 == fsc.class
}

// FilterSentAtLeast matches events that sent at least limit bytes (inclusive).
type FilterSentAtLeast struct {
	// Unit B.
	limit int64
}

// NewFilterSentAtLeast returns a filter matching events that sent at
// least limit bytes (inclusive).
func NewFilterSentAtLeast(limit int64) (*FilterSentAtLeast, error) {
	if limit < 0 {
		return nil, errors.New("limit must be greater or equal to 0")
	}
	return &FilterSentAtLeast{limit: limit}, nil
}

func (fsat *FilterSentAtLeast) Match(event *bandage.Event) bool {
	return event.SentBytes >= fsat.limit
}

// FilterSentAtMost matches events that sent at most limit bytes (inclusive).
type FilterSentAtMost struct {
	// Unit B.
	limit int64
}

// NewFilterSentAtMost returns a filter matching events that sent at most
// limit bytes (inclusive).
func NewFilterSentAtMost(limit int64) (*FilterSentAtMost, error) {
	if limit < 0 {
		return nil, errors.New("limit must be greater or equal to 0")
	}
	return &FilterSentAtMost{limit: limit}, nil
}

func (fsam *FilterSentAtMost) Match(event *bandage.Event) bool {
	return event.SentBytes <= fsam.limit
}
