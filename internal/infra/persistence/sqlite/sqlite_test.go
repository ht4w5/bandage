package sqlite

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	bandage "github.com/HT4w5/bandage/internal/domain"
	"github.com/HT4w5/bandage/internal/domain/report"
)

// The schema contract (spec: Reports, Repository): one row per
// (rule, target) with indexed rule, target and expiry columns, so that
// ?target=-only queries never full-scan the table.

func openTestRepo(t *testing.T) *ReportRepository {
	t.Helper()
	repo, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { repo.Close() })
	return repo
}

// Concurrent writes are deterministic under concurrency: one
// connection serializes them (ADR 0007), for file and memory databases
// alike — every upsert lands without a locking error, and duplicate
// concurrent triggers refresh the same (rule, target) row.
func TestConcurrentUpsertsAreDeterministic(t *testing.T) {
	for _, path := range []string{":memory:", filepath.Join(t.TempDir(), "reports.db")} {
		t.Run(path, func(t *testing.T) {
			repo, err := Open(path)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer repo.Close()
			base := time.Date(2025, 10, 17, 18, 0, 0, 0, time.UTC)

			// 8 writers × 8 upserts; the even writers all write the same
			// (rule, target), the odd writers one distinct target each.
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
						rec := bandage.Report{
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

			// One row per (rule, target): the shared row plus the 8
			// distinct ones, and every write is visible.
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

// singleColumnIndexes returns the table's single-column index names by
// the column they cover (PRAGMA index_list/index_info).
func singleColumnIndexes(t *testing.T, repo *ReportRepository) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	rows, err := repo.db.Query(`SELECT name FROM pragma_index_list('reports')`)
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
		cols, err := repo.db.Query(`SELECT name FROM pragma_index_info(?)`, name)
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

// The indexed columns contract: standalone indexes on rule and target
// (the composite primary key alone serves rule-prefix lookups only),
// plus the expiry index.
func TestSchemaHasStandaloneIndexesOnRuleTargetAndExpiry(t *testing.T) {
	repo := openTestRepo(t)
	indexed := singleColumnIndexes(t, repo)
	for _, col := range []string{"rule", "target", "expires_at"} {
		if !indexed[col] {
			t.Errorf("no standalone index on column %q (indexes: %v)", col, indexed)
		}
	}
}

// queryPlan returns the detail column of EXPLAIN QUERY PLAN for one
// statement.
func queryPlan(t *testing.T, repo *ReportRepository, query string, args ...any) []string {
	t.Helper()
	rows, err := repo.db.Query("EXPLAIN QUERY PLAN "+query, args...)
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

// ?target= without ?rule= must not full-scan: the target-only List and
// Delete shapes run as index searches on the target column.
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

// Behavior of the target-only shapes stays correct with the indexes in
// place (dismiss by target, list by target).
func TestTargetOnlyListAndDelete(t *testing.T) {
	repo := openTestRepo(t)
	ctx := context.Background()
	base := time.Date(2025, 10, 17, 18, 0, 0, 0, time.UTC)
	rec := bandage.Report{
		Rule: "r", Chain: "c", Reason: "why", Target: "203.0.113.0/24",
		CreatedAt: base, UpdatedAt: base, ExpiresAt: base.Add(time.Hour),
	}
	other := rec
	other.Rule = "r2"
	other.Target = "198.51.100.0/24"
	for _, r := range []bandage.Report{rec, other} {
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
