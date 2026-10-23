// Package domain is the analyzer's domain core: the Event value type flowing through
// enrichment and evaluation, the rule model, and the Report record that is
// the product of the analyzer.
package domain

import (
	"net/netip"
	"time"
)

// FilesizeUnknown marks an event whose estimated file size is not known
// yet (enrichment warm-up).
const FilesizeUnknown int64 = 0

// Event is a single parsed access-log record as it flows through
// enrichment and evaluation.
type Event struct {
	// Original fields.
	Time       time.Time
	RemoteAddr netip.Addr
	Method     string
	Path       string
	Agent      string
	Status     int
	SentBytes  int64

	// Derived fields, set by enrichment.
	SizeBytes int64
}
