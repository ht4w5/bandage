package memory

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/HT4w5/bandage/internal/domain/enrichment"
)

// The Filesize adapter shares the tracker store under namespace
// "filesize" without TTL and round-trips records exactly.
func TestFilesizeUpdateRoundTrip(t *testing.T) {
	store := New(16, time.Now, testLogger(&bytes.Buffer{}))
	cache := NewFilesize(store)

	got, err := cache.Update(context.Background(), "/a", func(r *enrichment.FilesizeRecord) {
		r.SizeEWMA = 1<<53 + 1 // beyond float64 int precision
		r.Samples = 3
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.SizeEWMA != 1<<53+1 || got.Samples != 3 {
		t.Errorf("record = %+v, want {1<<53+1 3} (SizeEWMA must survive exactly)", got)
	}

	got, err = cache.Update(context.Background(), "/a", func(r *enrichment.FilesizeRecord) {
		if r.Samples != 3 {
			t.Errorf("stored samples = %d, want 3", r.Samples)
		}
		r.Samples++
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Samples != 4 {
		t.Errorf("samples = %d, want 4", got.Samples)
	}

	other, err := cache.Update(context.Background(), "/b", func(r *enrichment.FilesizeRecord) {
		if r.Samples != 0 {
			t.Errorf("/b samples = %d, want 0 (records are keyed per path)", r.Samples)
		}
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if other.Samples != 0 {
		t.Errorf("/b record = %+v, want zero-valued", other)
	}
}
