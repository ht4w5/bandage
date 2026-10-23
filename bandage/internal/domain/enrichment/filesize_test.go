package enrichment

import (
	"context"
	"testing"

	"github.com/HT4w5/webmedkit/bandage/internal/domain"
)

// stubCache is a FilesizeCache test double keyed by path.
type stubCache struct {
	records map[string]FilesizeRecord
}

func (c *stubCache) Update(_ context.Context, path string, fn func(*FilesizeRecord)) (FilesizeRecord, error) {
	if c.records == nil {
		c.records = make(map[string]FilesizeRecord)
	}
	r := c.records[path]
	fn(&r)
	c.records[path] = r
	return r, nil
}

func enrichOnce(t *testing.T, fe *FilesizeEnricher, path string, sent int64) int64 {
	t.Helper()
	ev := &domain.Event{Path: path, SentBytes: sent}
	if err := fe.Enrich(context.Background(), ev); err != nil {
		t.Fatalf("Enrich error: %v", err)
	}
	return ev.SizeBytes
}

func TestNewFilesizeEnricherValidation(t *testing.T) {
	tests := []struct {
		name       string
		period     int64
		minSamples int
		wantErr    bool
	}{
		{"valid", 5, 5, false},
		{"period 1 is valid", 1, 1, false},
		{"zero period rejected", 0, 1, true},
		{"negative period rejected", -1, 1, true},
		{"zero minSamples rejected", 1, 0, true},
		{"negative minSamples rejected", 1, -3, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewFilesizeEnricher(&stubCache{}, tt.period, tt.minSamples)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewFilesizeEnricher(%d, %d) error = %v, wantErr %v", tt.period, tt.minSamples, err, tt.wantErr)
			}
		})
	}
}

// EWMA: prev + (observed-prev)/period with int64 truncating division.
// The first row pins the seed: the first observation lands exactly,
// with no blend against an implied zero.
func TestEnrichEWMAIntegerMath(t *testing.T) {
	tests := []struct {
		observed int64
		want     int64
	}{
		{1000, 1000}, // seed: first observation exactly
		{100, 820},   // 1000 + (100-1000)/5 = 1000 - 180
		{1821, 1020}, // 820 + 1001/5 = 820 + 200 (truncates .2)
		{993, 1015},  // 1020 + (-27)/5 = 1020 - 5 (truncates toward zero)
		{2000, 1212}, // 1015 + 985/5
	}
	fe, err := NewFilesizeEnricher(&stubCache{}, 5, 1)
	if err != nil {
		t.Fatal(err)
	}
	for i, tt := range tests {
		if got := enrichOnce(t, fe, "/a", tt.observed); got != tt.want {
			t.Errorf("sample %d (observed %d): size = %d, want %d", i+1, tt.observed, got, tt.want)
		}
	}
}

// period 1 means no smoothing: the estimate tracks the last observation.
func TestEnrichPeriodOneTracksObservations(t *testing.T) {
	fe, err := NewFilesizeEnricher(&stubCache{}, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, sent := range []int64{500, 7, 3000} {
		if got := enrichOnce(t, fe, "/a", sent); got != sent {
			t.Errorf("size after %d = %d, want %d", sent, got, sent)
		}
	}
}

// Warm-up: SizeBytes stays unknown until minSamples, and the Nth sample's
// own event is already enriched.
func TestEnrichWarmUpGating(t *testing.T) {
	fe, err := NewFilesizeEnricher(&stubCache{}, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	wants := []int64{0, 0, 1000, 1000, 1000}
	for i, want := range wants {
		got := enrichOnce(t, fe, "/a", 1000)
		if got != want {
			t.Errorf("sample %d: size = %d, want %d (0 = unknown until sample %d)", i+1, got, want, 3)
		}
	}
}

// While warming, SizeBytes is overwritten with FilesizeUnknown: a stale
// derived value never leaks through.
func TestEnrichOverwritesStaleSizeBytes(t *testing.T) {
	fe, err := NewFilesizeEnricher(&stubCache{}, 5, 2)
	if err != nil {
		t.Fatal(err)
	}
	ev := &domain.Event{Path: "/a", SentBytes: 100, SizeBytes: 999}
	if err := fe.Enrich(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if ev.SizeBytes != domain.FilesizeUnknown {
		t.Errorf("size = %d, want %d (stale value overwritten while warming)", ev.SizeBytes, domain.FilesizeUnknown)
	}
}

// Estimates are per path: one path's observations never move another's.
func TestEnrichStateIsPerPath(t *testing.T) {
	fe, err := NewFilesizeEnricher(&stubCache{}, 5, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got := enrichOnce(t, fe, "/a", 1000); got != 0 {
		t.Errorf("/a first size = %d, want unknown", got)
	}
	if got := enrichOnce(t, fe, "/b", 2000); got != 0 {
		t.Errorf("/b first size = %d, want unknown", got)
	}
	if got := enrichOnce(t, fe, "/a", 1000); got != 1000 {
		t.Errorf("/a warm size = %d, want 1000", got)
	}
	if got := enrichOnce(t, fe, "/b", 2000); got != 2000 {
		t.Errorf("/b warm size = %d, want 2000", got)
	}
}
