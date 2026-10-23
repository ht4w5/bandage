// Package enrichment derives Event fields from observed traffic: a
// Filesize estimate (GLOSSARY: Filesize) learned per path from transfers.
package enrichment

import (
	"context"
	"errors"
	"fmt"

	"github.com/HT4w5/bandage/internal/bandage"
)

// FilesizeRecord is one path's file-size estimate state.
type FilesizeRecord struct {
	// SizeEWMA is the smoothed average size in bytes (integer EWMA).
	SizeEWMA int64
	// Samples counts the observed transfers of the path.
	Samples int
}

// FilesizeCache stores file-size records keyed by path.
type FilesizeCache interface {
	// Update atomically applies fn to the record for path (zero-valued if none
	// exists); fn runs under the store's per-path lock and must not do I/O.
	Update(ctx context.Context, path string, fn func(*FilesizeRecord)) (FilesizeRecord, error)
}

// FilesizeEnricher estimates each path's file size from observed transfers.
type FilesizeEnricher struct {
	cache      FilesizeCache
	period     int64
	minSamples int
}

// NewFilesizeEnricher builds an enricher over cache; period is the EWMA window (alpha = 1/period) and minSamples the warm-up gate (both >= 1).
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

// Enrich records the event's transfer and sets event.SizeBytes: the estimate from sample minSamples on (the Nth event included), else FilesizeUnknown.
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

// ewma is prev + (observed-prev)/period with truncating division (no floats).
func ewma(prev, observed, period int64) int64 {
	return prev + (observed-prev)/period
}
