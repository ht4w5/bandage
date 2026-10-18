package sqlite

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	bandage "github.com/HT4w5/bandage/internal/domain"
)

// BenchmarkReportUpsert measures the report write path (H4): inserting
// a fresh (rule, target) row vs updating over an existing one, on a
// :memory: database vs a file database (the file case pays real durable
// storage cost on every transaction). One op is one report.Trigger-style
// Upsert of one report.

// benchUpsertReport is the report every op upserts; insert ops vary
// only its Target.
func benchUpsertReport() bandage.Report {
	now := time.Unix(1734345934, 0).UTC()
	return bandage.Report{
		Rule:      "sustained-egress",
		Chain:     "download-abuse",
		Reason:    "egress-overflow",
		Target:    "203.0.113.7/32",
		CreatedAt: now,
		UpdatedAt: now,
		ExpiresAt: now.Add(time.Hour),
		Tracker:   bandage.TrackerReading{Track: "bandwidth", Value: 11000, Leak: 1000, Volume: 10000},
		Sample:    bandage.Sample{Time: now, Path: "/releases/24.04.iso", Agent: "Wget/1.21", Status: 200, Sent: 6000},
	}
}

// targetPool hands out fresh distinct target strings, growing in
// batches with the timer stopped so fixture generation never counts
// toward B/op and allocs/op.
type targetPool struct{ targets []string }

func (p *targetPool) at(b *testing.B, i int) string {
	b.Helper()
	if i >= len(p.targets) {
		b.StopTimer()
		grown := make([]string, max(i+1, 2*len(p.targets), 256))
		copy(grown, p.targets)
		for j := len(p.targets); j < len(grown); j++ {
			grown[j] = "bench-target-" + strconv.Itoa(j) + "/32"
		}
		p.targets = grown
		b.StartTimer()
	}
	return p.targets[i]
}

func BenchmarkReportUpsert(b *testing.B) {
	for _, tc := range []struct {
		name   string
		disk   bool
		insert bool
	}{
		{"memory/insert", false, true},
		{"memory/update", false, false},
		{"file/insert", true, true},
		{"file/update", true, false},
	} {
		b.Run(tc.name, func(b *testing.B) {
			path := ":memory:"
			if tc.disk {
				path = filepath.Join(b.TempDir(), "reports.db")
			}
			repo, err := Open(path)
			if err != nil {
				b.Fatalf("Open: %v", err)
			}
			b.Cleanup(func() { repo.Close() })
			rec := benchUpsertReport()
			ctx := context.Background()
			if !tc.insert {
				// update-over-existing: the row lands before timing.
				if err := repo.Upsert(ctx, rec); err != nil {
					b.Fatalf("seed Upsert: %v", err)
				}
			}
			pool := &targetPool{}
			for i := 0; b.Loop(); i++ {
				if tc.insert {
					rec.Target = pool.at(b, i)
				}
				if err := repo.Upsert(ctx, rec); err != nil {
					b.Fatalf("Upsert: %v", err)
				}
			}
		})
	}
}
