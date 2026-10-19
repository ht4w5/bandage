package sqlite

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/HT4w5/bandage/internal/bench"
	bandage "github.com/HT4w5/bandage/internal/domain"
)

// BenchmarkReportUpsert measures the report write path: inserting a fresh
// (rule, target) row vs updating over an existing one, :memory: vs file.

// benchUpsertReport is the report every op upserts; insert ops vary only its Target.
func benchUpsertReport() bandage.Report {
	now := bench.Epoch
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

// targetPool hands out fresh distinct targets, growing in batches with the
// timer stopped so fixture generation never counts toward B/op.
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

// insertReportsSQL renders a fixture multi-row INSERT seeding n rows at
// expiresAt; fixture setup, not the write path under test, so it bypasses Upsert.
func insertReportsSQL(n int, expiresAt time.Time) string {
	var sb strings.Builder
	sb.WriteString("INSERT INTO reports (rule, target, created_at, updated_at, expires_at, body) VALUES ")
	for i := range n {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, "('bench-rule','bench-target-%d',%d,%d,%d,'{}')",
			i, bench.Epoch.UnixNano(), bench.Epoch.UnixNano(), expiresAt.UnixNano())
	}
	return sb.String()
}

// BenchmarkReportDeleteExpired measures one expired-report sweeper pass
// (DeleteExpired's indexed delete); the expiring case re-seeds with the timer stopped.
func BenchmarkReportDeleteExpired(b *testing.B) {
	const rows = 64
	for _, tc := range []struct {
		name     string
		expiring bool
	}{
		{"live", false},
		{"expiring", true},
	} {
		b.Run(tc.name, func(b *testing.B) {
			repo, err := Open(":memory:")
			if err != nil {
				b.Fatalf("Open: %v", err)
			}
			b.Cleanup(func() { repo.Close() })
			expiresAt := bench.Epoch.Add(time.Hour)
			if tc.expiring {
				expiresAt = bench.Epoch.Add(-time.Hour)
			}
			seed := insertReportsSQL(rows, expiresAt)
			if !tc.expiring {
				// The expiring case re-seeds every op (its rows are gone
				// after each sweep), so pre-seeding would collide on the PK.
				if _, err := repo.write.Exec(seed); err != nil {
					b.Fatalf("seed: %v", err)
				}
			}
			ctx := context.Background()
			for b.Loop() {
				if tc.expiring {
					b.StopTimer()
					if _, err := repo.write.Exec(seed); err != nil {
						b.Fatalf("seed: %v", err)
					}
					b.StartTimer()
				}
				if _, err := repo.DeleteExpired(ctx, bench.Epoch); err != nil {
					b.Fatalf("DeleteExpired: %v", err)
				}
			}
		})
	}
}
