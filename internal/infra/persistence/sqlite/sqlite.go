// Package sqlite is the sqlite report repository adapter (modernc.org/sqlite):
// one row per (rule, target) with a JSON body; reports survive restarts (ADR 0002).
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	bandage "github.com/HT4w5/bandage/internal/domain"
	"github.com/HT4w5/bandage/internal/domain/report"

	_ "modernc.org/sqlite"
)

const driverName = "sqlite"

// ReportRepository is a report.Repository backed by a sqlite database.
type ReportRepository struct {
	// write is the sole writer (one connection): writes serialize
	// through it and land deterministically (ADR 0007).
	write *sql.DB
	// read serves queries on its own bounded pool (ADR 0009); for a
	// :memory: database it is write (each connection would be its own database).
	read *sql.DB
	// upsert is prepared once at Open and reused by every Upsert.
	upsert *sql.Stmt
}

// upsertSQL inserts the row or refreshes the mutable columns on conflict;
// created_at is excluded from the UPDATE set, so it survives without a pre-read.
const upsertSQL = `
INSERT INTO reports (rule, target, created_at, updated_at, expires_at, body)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (rule, target) DO UPDATE SET
	updated_at = excluded.updated_at,
	expires_at = excluded.expires_at,
	body       = excluded.body`

// Open opens (creating if needed) the report database at path and ensures the
// schema; file databases run WAL/synchronous=NORMAL (ADR 0009), :memory: does not split.
func Open(path string) (*ReportRepository, error) {
	write, err := sql.Open(driverName, path)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	write.SetMaxOpenConns(1)
	if !isMemory(path) {
		if _, err := write.Exec(`PRAGMA journal_mode=WAL`); err != nil {
			write.Close()
			return nil, fmt.Errorf("sqlite: journal mode: %w", err)
		}
	}
	// synchronous is per connection (only the write one commits);
	// NORMAL in WAL mode survives process crashes (ADR 0009).
	if _, err := write.Exec(`PRAGMA synchronous=NORMAL`); err != nil {
		write.Close()
		return nil, fmt.Errorf("sqlite: synchronous: %w", err)
	}
	if _, err := write.Exec(schema); err != nil {
		write.Close()
		return nil, fmt.Errorf("sqlite: schema: %w", err)
	}
	read := write
	if !isMemory(path) {
		// Opened after the pragmas (WAL is a property of the database
		// file); each read connection gets a busy timeout via the DSN.
		readDSN := path + "?_pragma=busy_timeout(5000)"
		if strings.Contains(path, "?") {
			readDSN = path + "&_pragma=busy_timeout(5000)"
		}
		read, err = sql.Open(driverName, readDSN)
		if err != nil {
			write.Close()
			return nil, fmt.Errorf("sqlite: open read path: %w", err)
		}
		read.SetMaxOpenConns(4)
		read.SetMaxIdleConns(4)
	}
	upsert, err := write.Prepare(upsertSQL)
	if err != nil {
		read.Close()
		write.Close()
		return nil, fmt.Errorf("sqlite: prepare upsert: %w", err)
	}
	return &ReportRepository{write: write, read: read, upsert: upsert}, nil
}

// isMemory reports whether path names an in-memory database: WAL does not apply
// there and each connection would be a separate database (ADR 0009).
func isMemory(path string) bool {
	return path == ":memory:" || strings.Contains(path, "mode=memory")
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
	err := r.read.Close()
	if r.read != r.write {
		if werr := r.write.Close(); err == nil {
			err = werr
		}
	}
	return err
}

// Upsert inserts or overwrites the report for (rule, target) in one prepared
// statement; created_at is fixed at first insert by the statement, no pre-read.
func (r *ReportRepository) Upsert(ctx context.Context, rec bandage.Report) error {
	rawBody, err := json.Marshal(body{
		Chain:   rec.Chain,
		Reason:  rec.Reason,
		Tracker: rec.Tracker,
		Sample:  rec.Sample,
	})
	if err != nil {
		return fmt.Errorf("sqlite: upsert: %w", err)
	}
	_, err = r.upsert.ExecContext(ctx,
		rec.Rule, rec.Target,
		rec.CreatedAt.UnixNano(), rec.UpdatedAt.UnixNano(), rec.ExpiresAt.UnixNano(),
		string(rawBody))
	if err != nil {
		return fmt.Errorf("sqlite: upsert: %w", err)
	}
	return nil
}

// List returns matching, unexpired reports sorted by created_at descending
// (ties by rule, target), on the read path's own connections (ADR 0009).
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

	rows, err := r.read.QueryContext(ctx, query, args...)
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

// Delete removes matching reports regardless of expiry and returns the count;
// at least one filter is required (ErrUnfiltered): deletion is never delete-all.
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
	res, err := r.write.ExecContext(ctx, query, args...)
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
	res, err := r.write.ExecContext(ctx, `DELETE FROM reports WHERE expires_at <= ?`, now.UnixNano())
	if err != nil {
		return 0, fmt.Errorf("sqlite: delete expired: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("sqlite: delete expired: %w", err)
	}
	return int(n), nil
}
