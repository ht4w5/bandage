// Package sqlite is the sqlite report repository adapter (modernc.org/sqlite,
// pure Go). One row per (rule, target) with indexed rule/target/expiry
// columns and a JSON record body; reports survive restarts while tracker
// state stays memory-only (ADR 0002). The store opens a single
// connection for every path (file and memory alike), so concurrent
// writes serialize through it and land deterministically (ADR 0007).
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	bandage "github.com/HT4w5/bandage/internal/domain"
	"github.com/HT4w5/bandage/internal/domain/report"

	_ "modernc.org/sqlite"
)

const driverName = "sqlite"

// ReportRepository is a report.Repository backed by a sqlite database.
type ReportRepository struct {
	db *sql.DB
}

// Open opens (creating if needed) the report database at path and ensures
// the schema exists. One connection serves every path — the special
// ":memory:" (tests) and file databases alike — making writes
// deterministic under concurrency (ADR 0007).
func Open(path string) (*ReportRepository, error) {
	db, err := sql.Open(driverName, path)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: schema: %w", err)
	}
	return &ReportRepository{db: db}, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS reports (
	rule       TEXT    NOT NULL,
	target     TEXT    NOT NULL,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	body       TEXT    NOT NULL,
	PRIMARY KEY (rule, target)
);
CREATE INDEX IF NOT EXISTS idx_reports_rule ON reports (rule);
CREATE INDEX IF NOT EXISTS idx_reports_target ON reports (target);
CREATE INDEX IF NOT EXISTS idx_reports_expires_at ON reports (expires_at);
`

// body is the JSON record body: everything but the indexed columns.
type body struct {
	Chain   string                 `json:"chain"`
	Reason  string                 `json:"reason"`
	Tracker bandage.TrackerReading `json:"tracker"`
	Sample  bandage.Sample         `json:"sample"`
}

func (r *ReportRepository) Close() error {
	return r.db.Close()
}

// Upsert inserts or overwrites the report for (rule, target). created_at
// is fixed at the row's first insert.
func (r *ReportRepository) Upsert(ctx context.Context, rec bandage.Report) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite: upsert: %w", err)
	}
	defer tx.Rollback()

	var createdNS int64
	err = tx.QueryRowContext(ctx,
		`SELECT created_at FROM reports WHERE rule = ? AND target = ?`, rec.Rule, rec.Target).
		Scan(&createdNS)
	switch {
	case err == nil:
		rec.CreatedAt = time.Unix(0, createdNS).UTC()
	case errors.Is(err, sql.ErrNoRows):
		// First trigger: keep rec.CreatedAt.
	default:
		return fmt.Errorf("sqlite: upsert: %w", err)
	}

	rawBody, err := json.Marshal(body{
		Chain:   rec.Chain,
		Reason:  rec.Reason,
		Tracker: rec.Tracker,
		Sample:  rec.Sample,
	})
	if err != nil {
		return fmt.Errorf("sqlite: upsert: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
INSERT INTO reports (rule, target, created_at, updated_at, expires_at, body)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (rule, target) DO UPDATE SET
	updated_at = excluded.updated_at,
	expires_at = excluded.expires_at,
	body       = excluded.body`,
		rec.Rule, rec.Target,
		rec.CreatedAt.UnixNano(), rec.UpdatedAt.UnixNano(), rec.ExpiresAt.UnixNano(),
		string(rawBody))
	if err != nil {
		return fmt.Errorf("sqlite: upsert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: upsert: %w", err)
	}
	return nil
}

// List returns matching, unexpired reports sorted by created_at
// descending (ties broken by rule, target for determinism).
func (r *ReportRepository) List(ctx context.Context, q report.Query) ([]bandage.Report, error) {
	query := `SELECT rule, target, created_at, updated_at, expires_at, body FROM reports WHERE expires_at > ?`
	args := []any{q.Now.UnixNano()}
	if q.Rule != "" {
		query += ` AND rule = ?`
		args = append(args, q.Rule)
	}
	if q.Target != "" {
		query += ` AND target = ?`
		args = append(args, q.Target)
	}
	query += ` ORDER BY created_at DESC, rule ASC, target ASC`

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list: %w", err)
	}
	defer rows.Close()

	var out []bandage.Report
	for rows.Next() {
		var (
			rec       bandage.Report
			createdNS int64
			updatedNS int64
			expiresNS int64
			rawBody   string
		)
		if err := rows.Scan(&rec.Rule, &rec.Target, &createdNS, &updatedNS, &expiresNS, &rawBody); err != nil {
			return nil, fmt.Errorf("sqlite: list: %w", err)
		}
		var b body
		if err := json.Unmarshal([]byte(rawBody), &b); err != nil {
			return nil, fmt.Errorf("sqlite: list: %w", err)
		}
		rec.Chain = b.Chain
		rec.Reason = b.Reason
		rec.Tracker = b.Tracker
		rec.Sample = b.Sample
		rec.CreatedAt = time.Unix(0, createdNS).UTC()
		rec.UpdatedAt = time.Unix(0, updatedNS).UTC()
		rec.ExpiresAt = time.Unix(0, expiresNS).UTC()
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: list: %w", err)
	}
	return out, nil
}

// Delete removes reports matching the query regardless of expiry and
// returns the number of deleted rows. At least one filter is required
// (ErrUnfiltered otherwise): dismissal is never delete-all.
func (r *ReportRepository) Delete(ctx context.Context, q report.Query) (int, error) {
	var (
		query string
		args  []any
	)
	switch {
	case q.Rule != "" && q.Target != "":
		query = `DELETE FROM reports WHERE rule = ? AND target = ?`
		args = []any{q.Rule, q.Target}
	case q.Rule != "":
		query = `DELETE FROM reports WHERE rule = ?`
		args = []any{q.Rule}
	case q.Target != "":
		query = `DELETE FROM reports WHERE target = ?`
		args = []any{q.Target}
	default:
		return 0, fmt.Errorf("sqlite: delete: %w", report.ErrUnfiltered)
	}
	res, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("sqlite: delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("sqlite: delete: %w", err)
	}
	return int(n), nil
}

// DeleteExpired deletes rows whose expires_at has passed.
func (r *ReportRepository) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM reports WHERE expires_at <= ?`, now.UnixNano())
	if err != nil {
		return 0, fmt.Errorf("sqlite: delete expired: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("sqlite: delete expired: %w", err)
	}
	return int(n), nil
}
