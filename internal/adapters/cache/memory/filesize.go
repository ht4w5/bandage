package memory

import (
	"context"

	"github.com/HT4w5/bandage/internal/domain/enrichment"
	"github.com/HT4w5/bandage/internal/domain/track"
)

// filesizeNS is the shared store namespace for file-size enrichment
// state. Entries carry no TTL: estimates are memory-only and cold after
// restart (PLAN §5, ADR 0002).
const filesizeNS = "filesize"

// Filesize adapts Store to the enrichment.FilesizeCache port: file-size
// records share the tracker store under namespace "filesize" without
// TTL, so the entry cap bounds them together with tracker state.
//
// The store holds generic track.Record values, so a record maps SizeEWMA
// into LastUpdate (int64-exact) and Samples into Value (a small integer,
// exact in float64).
type Filesize struct {
	store *Store
}

// NewFilesize returns a FilesizeCache over store.
func NewFilesize(store *Store) Filesize {
	return Filesize{store: store}
}

// Update atomically applies fn to the file-size record for path. fn
// runs under the store's per-key lock and must not perform I/O or use
// ctx (the enrichment port's contract).
func (f Filesize) Update(ctx context.Context, path string, fn func(*enrichment.FilesizeRecord)) (enrichment.FilesizeRecord, error) {
	var out enrichment.FilesizeRecord
	_, err := f.store.Update(ctx, filesizeNS, path, 0, func(r *track.Record) {
		rec := enrichment.FilesizeRecord{SizeEWMA: r.LastUpdate, Samples: int(r.Value)}
		fn(&rec)
		r.LastUpdate = rec.SizeEWMA
		r.Value = float64(rec.Samples)
		out = rec
	})
	return out, err
}
