package memory

import (
	"context"

	bandage "github.com/HT4w5/bandage/internal/domain"
	"github.com/HT4w5/bandage/internal/domain/enrichment"
	"github.com/HT4w5/bandage/internal/domain/track"
)

// Filesize adapts Store to the enrichment.FilesizeCache port: file-size
// records share the tracker store under the reserved FilesizeNamespace
// without TTL, so the entry cap bounds them together with tracker state.
// The encode/decode pair below is the only place the two record shapes
// meet.
type Filesize struct {
	store *Store
}

// NewFilesize returns a FilesizeCache over store.
func NewFilesize(store *Store) Filesize {
	return Filesize{store: store}
}

// Update atomically applies fn to the file-size record for path. fn
// runs under the store's per-key lock, so it must not perform I/O or use
// ctx (the enrichment port's contract).
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

// The shared store carries generic track.Record values; file-size state
// occupies those slots with entirely different meaning. The mapping is
// slot-wise and named here so no reader has to decode a field pun:
//
//	track.Record.LastUpdate (int64)   ↔ FilesizeRecord.SizeEWMA (int64)
//	track.Record.Value      (float64) ↔ FilesizeRecord.Samples   (int)
//
// Sizes ride the int64 slot, so byte counts stay exact beyond float64's
// 2^53 integer precision; the sample count is a small integer and stays
// exact in the float64 slot.

// decodeFilesize maps the store's track.Record slots back to the
// file-size record they encode.
func decodeFilesize(r track.Record) enrichment.FilesizeRecord {
	return enrichment.FilesizeRecord{SizeEWMA: r.LastUpdate, Samples: int(r.Value)}
}

// encodeFilesize maps a file-size record onto the store's track.Record
// slots: the inverse of decodeFilesize.
func encodeFilesize(rec enrichment.FilesizeRecord) track.Record {
	return track.Record{Value: float64(rec.Samples), LastUpdate: rec.SizeEWMA}
}
