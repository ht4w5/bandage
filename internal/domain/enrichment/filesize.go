// Package enrichment derives Event fields from observed traffic: the
// Filesize estimate (GLOSSARY: Filesize) learned per path from observed
// transfers. The EWMA and warm-up gate are ported from webjail
// (.reference/webjail/internal/domain/enrichment/filesize.go).
package enrichment

import (
	"context"
	"errors"
	"fmt"

	bandage "github.com/HT4w5/bandage/internal/domain"
)

// FilesizeRecord is one path's file-size estimate state: the smoothed
// average and how many transfers have contributed to it.
type FilesizeRecord struct {
	// SizeEWMA is the smoothed average size in bytes (webjail's integer
	// EWMA: prev + (observed−prev)/period, truncating division).
	SizeEWMA int64
	// Samples counts the observed transfers of the path.
	Samples int
}

// FilesizeCache stores file-size records keyed by path.
//
// Update atomically applies fn to the record for path (a zero-valued
// record if none exists) and returns it afterwards. fn runs under the
// store's per-path lock, so it must not perform I/O or use ctx. The
// in-memory adapter serves this from the shared tracker store under the
// reserved bandage.FilesizeNamespace without TTL (state is memory-only
// and cold after restart — ADR 0002).
type FilesizeCache interface {
	Update(ctx context.Context, path string, fn func(*FilesizeRecord)) (FilesizeRecord, error)
}

// FilesizeEnricher estimates each path's file size from observed
// transfers and sets the derived event.SizeBytes (Event.SizeBytes).
type FilesizeEnricher struct {
	cache      FilesizeCache
	period     int64
	minSamples int
}

// NewFilesizeEnricher builds an enricher over cache. period is the EWMA
// smoothing window (alpha = 1/period); minSamples is the number of
// observations that must be seen before an estimate is served (else
// SizeBytes stays FilesizeUnknown). Both must be at least 1.
func NewFilesizeEnricher(cache FilesizeCache, period int64, minSamples int) (*FilesizeEnricher, error) {
	if period < 1 {
		return nil, errors.New("enrichment: period must be at least 1")
	}
	if minSamples < 1 {
		return nil, errors.New("enrichment: minSamples must be at least 1")
	}
	return &FilesizeEnricher{
		cache:      cache,
		period:     period,
		minSamples: minSamples,
	}, nil
}

// Enrich records the event's transfer and sets event.SizeBytes: the
// path's estimate once minSamples transfers have been seen (the current
// sample included — the Nth sample's event is already enriched), or
// FilesizeUnknown while warming. The unknown case always overwrites any
// stale derived value.
func (fe *FilesizeEnricher) Enrich(ctx context.Context, event *bandage.Event) error {
	rec, err := fe.cache.Update(ctx, event.Path, func(r *FilesizeRecord) {
		if r.Samples == 0 {
			// Seed with the first observation exactly (no blending).
			r.SizeEWMA = event.SentBytes
			r.Samples = 1
			return
		}
		r.SizeEWMA = ewma(r.SizeEWMA, event.SentBytes, fe.period)
		r.Samples++
	})
	if err != nil {
		return fmt.Errorf("enrichment: update filesize record: %w", err)
	}

	if rec.Samples >= fe.minSamples {
		event.SizeBytes = rec.SizeEWMA
	} else {
		event.SizeBytes = bandage.FilesizeUnknown
	}
	return nil
}

// ewma is webjail's integer smoothing: prev + (observed−prev)/period
// with truncating division (DECISIONS §3: no floating point anywhere).
func ewma(prev, observed, period int64) int64 {
	return prev + (observed-prev)/period
}
