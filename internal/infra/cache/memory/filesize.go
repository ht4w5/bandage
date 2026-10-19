package memory

import (
	"context"

	bandage "github.com/HT4w5/bandage/internal/domain"
	"github.com/HT4w5/bandage/internal/domain/enrichment"
	"github.com/HT4w5/bandage/internal/domain/track"
)

// Filesize adapts Store to the enrichment.FilesizeCache port: file-size
// records live under FilesizeNamespace without TTL (the entry cap bounds them).
type Filesize struct {
	store *Store
}

// NewFilesize returns a FilesizeCache over store.
func NewFilesize(store *Store) Filesize {
	return Filesize{store: store}
}

// Update atomically applies fn to the file-size record for path; fn runs
// under the store's per-key lock, so it must not perform I/O or use ctx.
func (f Filesize) Update(ctx context.Context, path string, fn func(*enrichment.FilesizeRecord)) (enrichment.FilesizeRecord, error) {
	var out enrichment.FilesizeRecord
	_, err := f.store.Update(ctx, bandage.FilesizeNamespace, path, 0, func(r *track.Record) {
		rec := decodeFilesize(*r)
		fn(&rec)
		*r = encodeFilesize(rec)
		out = rec
	})
	return out, err
}

// track.Record slots hold file-size state (field puns): LastUpdate (int64) <->
// SizeEWMA, Value (float64) <-> Samples. Sizes ride the int64 slot (exact > 2^53).

// decodeFilesize maps the store's track.Record slots back to the file-size record.
func decodeFilesize(r track.Record) enrichment.FilesizeRecord {
	return enrichment.FilesizeRecord{SizeEWMA: r.LastUpdate, Samples: int(r.Value)}
}

// encodeFilesize maps a file-size record onto track.Record slots (inverse of decodeFilesize).
func encodeFilesize(rec enrichment.FilesizeRecord) track.Record {
	return track.Record{Value: float64(rec.Samples), LastUpdate: rec.SizeEWMA}
}
