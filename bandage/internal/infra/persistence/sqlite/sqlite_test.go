package sqlite

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HT4w5/webmedkit/bandage/internal/domain"
	"github.com/HT4w5/webmedkit/bandage/internal/domain/report"
)

// Schema contract: one row per (rule, target) with indexed rule, target and
// expiry columns, so ?target=-only queries never full-scan the table.

func openTestRepo(t *testing.T) *ReportRepository {
	t.Helper()
	repo, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { repo.Close() })
	return repo
}

// TestConcurrentUpsertsAreDeterministic: one connection serializes concurrent
// writes (ADR 0007) - every upsert lands, duplicates refresh the same row.
func TestConcurrentUpsertsAreDeterministic(t *testing.T) {
	for _, path := range []string{":memory:", filepath.Join(t.TempDir(), "reports.db")} {
		t.Run(path, func(t *testing.T) {
			repo, err := Open(path)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer repo.Close()
			base := time.Date(2025, 10, 17, 18, 0, 0, 0, time.UTC)

			// 8 writers x 8 upserts; even writers share one
			// (rule, target), odd writers have one distinct target each.
			const writers, perWriter = 8, 8
			var wg sync.WaitGroup
			errs := make(chan error, writers*perWriter)
			for w := range writers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := range perWriter {
						target := fmt.Sprintf("203.0.113.%d/32", i)
						if w%2 == 0 {
							target = "198.51.100.7/32"
						}
						rec := domain.Report{
							Rule: "r", Chain: "c", Reason: "why", Target: target,
							CreatedAt: base, UpdatedAt: base, ExpiresAt: base.Add(time.Hour),
						}
						if err := repo.Upsert(context.Background(), rec); err != nil {
							errs <- err
						}
					}
				}()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Errorf("Upsert error: %v", err)
			}

			// The shared row plus the 8 distinct ones, all visible.
			got, err := repo.List(context.Background(), report.Query{Now: base})
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(got) != 9 {
				t.Errorf("rows = %d, want 9 (one per (rule, target))", len(got))
			}
		})
	}
}

// singleColumnIndexes returns the table's single-column index names by the
// column they cover (PRAGMA index_list/index_info).
func singleColumnIndexes(t *testing.T, repo *ReportRepository) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	rows, err := repo.read.Query(`SELECT name FROM pragma_index_list('reports')`)
	if err != nil {
		t.Fatalf("pragma_index_list: %v", err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		cols, err := repo.read.Query(`SELECT name FROM pragma_index_info(?)`, name)
		if err != nil {
			t.Fatalf("pragma_index_info(%q): %v", name, err)
		}
		var indexCols []string
		for cols.Next() {
			var col string
			if err := cols.Scan(&col); err != nil {
				cols.Close()
				t.Fatal(err)
			}
			indexCols = append(indexCols, col)
		}
		cols.Close()
		if err := cols.Err(); err != nil {
			t.Fatal(err)
		}
		if len(indexCols) == 1 {
			out[indexCols[0]] = true
		}
	}
	return out
}

// TestSchemaHasStandaloneIndexesOnRuleTargetAndExpiry: standalone indexes on
// rule, target (the composite PK alone serves only rule-prefix lookups) and expiry.
func TestSchemaHasStandaloneIndexesOnRuleTargetAndExpiry(t *testing.T) {
	repo := openTestRepo(t)
	indexed := singleColumnIndexes(t, repo)
	for _, col := range []string{"rule", "target", "expires_at"} {
		if !indexed[col] {
			t.Errorf("no standalone index on column %q (indexes: %v)", col, indexed)
		}
	}
}

// queryPlan returns the detail column of EXPLAIN QUERY PLAN for one statement.
func queryPlan(t *testing.T, repo *ReportRepository, query string, args ...any) []string {
	t.Helper()
	rows, err := repo.read.Query("EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		t.Fatalf("EXPLAIN QUERY PLAN %s: %v", query, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		out = append(out, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestTargetOnlyQueriesDoNotFullScan: target-only List and Delete run as
// index searches on the target column, never a full scan.
func TestTargetOnlyQueriesDoNotFullScan(t *testing.T) {
	repo := openTestRepo(t)
	for _, tt := range []struct {
		name  string
		query string
		args  []any
	}{
		{"list", `SELECT rule, target, created_at, updated_at, expires_at, body FROM reports WHERE expires_at > ? AND target = ?`, []any{0, ""}},
		{"delete", `DELETE FROM reports WHERE target = ?`, []any{""}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			plan := queryPlan(t, repo, tt.query, tt.args...)
			searched := false
			for _, detail := range plan {
				if detail == "SCAN reports" {
					t.Errorf("target-only query full-scans the table: %v", plan)
				}
				if strings.Contains(detail, "SEARCH reports USING INDEX") && strings.Contains(detail, "target=?") {
					searched = true
				}
			}
			if !searched {
				t.Errorf("target-only query does not search the target index: %v", plan)
			}
		})
	}
}

// TestTargetOnlyListAndDelete: target-only delete and list stay correct
// with the indexes in place.
func TestTargetOnlyListAndDelete(t *testing.T) {
	repo := openTestRepo(t)
	ctx := context.Background()
	base := time.Date(2025, 10, 17, 18, 0, 0, 0, time.UTC)
	rec := domain.Report{
		Rule: "r", Chain: "c", Reason: "why", Target: "203.0.113.0/24",
		CreatedAt: base, UpdatedAt: base, ExpiresAt: base.Add(time.Hour),
	}
	other := rec
	other.Rule = "r2"
	other.Target = "198.51.100.0/24"
	for _, r := range []domain.Report{rec, other} {
		if err := repo.Upsert(ctx, r); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}

	got, err := repo.List(ctx, report.Query{Target: rec.Target, Now: base})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || got[0].Target != rec.Target {
		t.Errorf("List by target = %+v, want only %q", got, rec.Target)
	}

	n, err := repo.Delete(ctx, report.Query{Target: rec.Target})
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if n != 1 {
		t.Errorf("Delete by target = %d, want 1", n)
	}
}

// TestFileDatabaseRunsInWALSynchronousNormal: file databases open in
// journal_mode=WAL with synchronous=NORMAL (commits survive process crashes).
func TestFileDatabaseRunsInWALSynchronousNormal(t *testing.T) {
	repo, err := Open(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { repo.Close() })

	var mode string
	if err := repo.write.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatalf("journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want %q", mode, "wal")
	}
	var syncMode int64
	if err := repo.write.QueryRow(`PRAGMA synchronous`).Scan(&syncMode); err != nil {
		t.Fatalf("synchronous: %v", err)
	}
	if syncMode != 1 {
		t.Errorf("synchronous = %d, want 1 (NORMAL)", syncMode)
	}
}

// TestWrittenReportSurvivesReopen: a written report survives reopening the
// database (WAL + synchronous=NORMAL), keeping its original created_at and
// its penalty.
func TestWrittenReportSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reports.db")
	ctx := context.Background()
	base := time.Date(2025, 10, 17, 18, 0, 0, 0, time.UTC)
	rate := int64(1000000)
	rec := domain.Report{
		Rule: "r", Chain: "c", Reason: "why", Target: "203.0.113.7/32",
		CreatedAt: base, UpdatedAt: base, ExpiresAt: base.Add(time.Hour),
		Penalty: &domain.Penalty{Action: domain.PenaltyLimitBandwidth, Rate: &rate},
	}

	repo, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := repo.Upsert(ctx, rec); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := repo.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	got, err := reopened.List(ctx, report.Query{Now: base})
	if err != nil {
		t.Fatalf("List after reopen: %v", err)
	}
	if len(got) != 1 || got[0].CreatedAt != rec.CreatedAt {
		t.Errorf("rows after reopen = %+v, want the written report with created_at %v", got, rec.CreatedAt)
	}
	if p := got[0].Penalty; p == nil || p.Action != domain.PenaltyLimitBandwidth ||
		p.Rate == nil || *p.Rate != rate {
		t.Errorf("penalty after reopen = %+v, want limit-bandwidth at %d", got[0].Penalty, rate)
	}
}

// TestQueryDoesNotWaitBehindInflightWrite: holding the sole write connection
// never blocks List (the read path has its own connections).
func TestQueryDoesNotWaitBehindInflightWrite(t *testing.T) {
	repo, err := Open(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { repo.Close() })
	ctx := context.Background()
	base := time.Date(2025, 10, 17, 18, 0, 0, 0, time.UTC)
	rec := domain.Report{
		Rule: "r", Chain: "c", Reason: "why", Target: "203.0.113.7/32",
		CreatedAt: base, UpdatedAt: base, ExpiresAt: base.Add(time.Hour),
	}
	if err := repo.Upsert(ctx, rec); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// The in-flight write holds the write connection.
	conn, err := repo.write.Conn(ctx)
	if err != nil {
		t.Fatalf("write conn: %v", err)
	}
	defer conn.Close()

	type result struct {
		reports []domain.Report
		err     error
	}
	done := make(chan result, 1)
	go func() {
		got, err := repo.List(ctx, report.Query{Now: base})
		done <- result{got, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("List: %v", r.err)
		}
		if len(r.reports) != 1 {
			t.Errorf("List during the in-flight write = %+v, want the committed row", r.reports)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("List waited for the in-flight write")
	}
}

// TestWriteDoesNotWaitBehindInflightQuery: a query holding its connection
// never blocks Upsert on the single write connection.
func TestWriteDoesNotWaitBehindInflightQuery(t *testing.T) {
	repo, err := Open(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { repo.Close() })
	ctx := context.Background()
	base := time.Date(2025, 10, 17, 18, 0, 0, 0, time.UTC)
	rec := domain.Report{
		Rule: "r", Chain: "c", Reason: "why", Target: "203.0.113.7/32",
		CreatedAt: base, UpdatedAt: base, ExpiresAt: base.Add(time.Hour),
	}

	// The in-flight query holds the read path's connection.
	conn, err := repo.read.Conn(ctx)
	if err != nil {
		t.Fatalf("read conn: %v", err)
	}
	defer conn.Close()

	done := make(chan error, 1)
	go func() { done <- repo.Upsert(ctx, rec) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Upsert waited for the in-flight query")
	}

	got, err := repo.List(ctx, report.Query{Now: base})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("rows after the concurrent write = %+v, want the upserted report", got)
	}
}

// TestMemoryDatabaseWorksAcrossSplitPaths: :memory: cannot split connections,
// so the read path falls back to the single write connection (ADR 0009).
func TestMemoryDatabaseWorksAcrossSplitPaths(t *testing.T) {
	repo := openTestRepo(t)
	if repo.read != repo.write {
		t.Fatalf(":memory: read path = %p, want the write-connection fallback %p", repo.read, repo.write)
	}
	ctx := context.Background()
	base := time.Date(2025, 10, 17, 18, 0, 0, 0, time.UTC)
	rec := domain.Report{
		Rule: "r", Chain: "c", Reason: "why", Target: "203.0.113.7/32",
		CreatedAt: base, UpdatedAt: base, ExpiresAt: base.Add(time.Hour),
	}
	if err := repo.Upsert(ctx, rec); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	got, err := repo.List(ctx, report.Query{Now: base})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || got[0].Target != rec.Target {
		t.Errorf("rows = %+v, want the upserted report", got)
	}
}

// TestUpsertPreservesCreatedAtOnUpdate: a later Trigger overwrites updated_at,
// expiry, tracker, sample and penalty but never the first-trigger created_at
// (no pre-read).
func TestUpsertPreservesCreatedAtOnUpdate(t *testing.T) {
	repo := openTestRepo(t)
	ctx := context.Background()
	first := time.Date(2025, 10, 17, 18, 0, 0, 0, time.UTC)
	second := first.Add(time.Hour)
	rec := domain.Report{
		Rule: "r", Chain: "c", Reason: "why", Target: "203.0.113.7/32",
		CreatedAt: first, UpdatedAt: first, ExpiresAt: first.Add(24 * time.Hour),
		Penalty: &domain.Penalty{Action: domain.PenaltyReject},
	}
	if err := repo.Upsert(ctx, rec); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// The update arrives with a different CreatedAt and penalty; the row's
	// first-trigger timestamp wins, the body is replaced.
	rec.CreatedAt = second
	rec.UpdatedAt = second
	rec.ExpiresAt = second.Add(24 * time.Hour)
	rec.Penalty = &domain.Penalty{Action: domain.PenaltyDrop}
	if err := repo.Upsert(ctx, rec); err != nil {
		t.Fatalf("Upsert update: %v", err)
	}

	got, err := repo.List(ctx, report.Query{Now: second})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("rows = %+v, want one", got)
	}
	if got[0].CreatedAt != first {
		t.Errorf("created_at = %v, want the first-trigger %v", got[0].CreatedAt, first)
	}
	if got[0].UpdatedAt != second {
		t.Errorf("updated_at = %v, want the update %v", got[0].UpdatedAt, second)
	}
	if p := got[0].Penalty; p == nil || p.Action != domain.PenaltyDrop {
		t.Errorf("penalty = %+v, want the update's drop", got[0].Penalty)
	}
}
