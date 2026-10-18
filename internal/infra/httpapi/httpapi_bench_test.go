package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/HT4w5/bandage/internal/bench"
	bandage "github.com/HT4w5/bandage/internal/domain"
	"github.com/HT4w5/bandage/internal/domain/report"
	"github.com/HT4w5/bandage/internal/infra/persistence/sqlite"
)

// BenchmarkReportsList measures the read path (GET /reports): sqlite
// List with its per-row JSON body decode, plus the document marshal and
// encode, at 10/1k/10k seeded rows. One op is one request. The request
// and response recorder are reused across ops (the recorder's buffer is
// reset), so B/op and allocs/op are the read path, not harness
// allocation.

// benchNow is the fixed wall clock the report document runs on: the
// shared fixture epoch (internal/bench.Epoch).
func benchNow() time.Time { return bench.Epoch }

// benchStats is a StatsSource the /reports read path never calls.
type benchStats struct{}

func (benchStats) Stats() Stats { return Stats{} }

// benchListReport is one seeded report; target disambiguates rows.
func benchListReport(target string) bandage.Report {
	now := benchNow()
	return bandage.Report{
		Rule:      "sustained-egress",
		Chain:     "download-abuse",
		Reason:    "egress-overflow",
		Target:    target,
		CreatedAt: now,
		UpdatedAt: now,
		ExpiresAt: now.Add(time.Hour),
		Tracker:   bandage.TrackerReading{Track: "bandwidth", Value: 11000, Leak: 1000, Volume: 10000},
		Sample:    bandage.Sample{Time: now, Path: "/releases/24.04.iso", Agent: "Wget/1.21", Status: 200, Sent: 6000},
	}
}

// seedReports fills the repository with rows distinct reports and
// checks the read path really returns every one of them.
func seedReports(b *testing.B, repo *sqlite.ReportRepository, rows int) {
	b.Helper()
	ctx := context.Background()
	for i := 0; i < rows; i++ {
		if err := repo.Upsert(ctx, benchListReport("bench-target-"+strconv.Itoa(i)+"/32")); err != nil {
			b.Fatalf("seed Upsert: %v", err)
		}
	}
	got, err := repo.List(ctx, report.Query{Now: benchNow()})
	if err != nil {
		b.Fatalf("seed List: %v", err)
	}
	if len(got) != rows {
		b.Fatalf("seeded %d rows, List returned %d", rows, len(got))
	}
}

func BenchmarkReportsList(b *testing.B) {
	for _, tt := range []struct {
		name string
		rows int
	}{{"10-rows", 10}, {"1k-rows", 1000}, {"10k-rows", 10000}} {
		b.Run(tt.name, func(b *testing.B) {
			repo, err := sqlite.Open(":memory:")
			if err != nil {
				b.Fatalf("sqlite.Open: %v", err)
			}
			b.Cleanup(func() { repo.Close() })
			seedReports(b, repo, tt.rows)
			srv := New(repo, benchStats{}, benchNow)
			req := httptest.NewRequest(http.MethodGet, "/reports", nil)
			w := httptest.NewRecorder()
			for b.Loop() {
				w.Body.Reset()
				srv.ServeHTTP(w, req)
				if w.Code != http.StatusOK {
					b.Fatalf("GET /reports: status %d", w.Code)
				}
			}
		})
	}
}
