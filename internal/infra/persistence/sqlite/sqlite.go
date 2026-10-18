// Package sqlite is the sqlite report repository adapter (modernc.org/sqlite,
// pure Go). One row per (rule, target) with indexed rule/target/expiry
// columns and a JSON record body; reports survive restarts while tracker
// state stays memory-only (ADR 0002). Writes flow through a single
// connection so concurrent writes serialize through it and land
// deterministically (ADR 0007); queries run on their own connections so
// the API never queues behind upserts (ADR 0009). File databases run
// journal_mode=WAL with synchronous=NORMAL: a commit survives a process
// crash, losing only the final moments on power failure. :memory:
// databases (tests) ignore WAL and treat every connection as a separate
// database, so the read path falls back to the single write connection
// there.
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
	// write is the sole writer: exactly one connection, so every write
	// serializes through it and lands deterministically (ADR 0007).
	write *sql.DB
	// read serves the query paths on its own connections (ADR 0009): a
	// bounded pool, so the API never queues behind upserts and the read
	// side cannot grow without limit. For a :memory: database it is
	// write — every connection to an in-memory database would be its
	// own private database.
	read *sql.DB
	// upsert is prepared once at Open and reused by every Upsert.
	upsert *sql.Stmt
}

// upsertSQL inserts the row or refreshes the mutable columns on
// conflict. created_at is deliberately absent from the UPDATE set: the
// statement preserves it on update without reading the row first (spec:
// Upsert sheds its pre-read).
const upsertSQL = `
INSERT INTO reports (rule, target, created_at, updated_at, expires_at, body)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (rule, target) DO UPDATE SET
	updated_at = excluded.updated_at,
	expires_at = excluded.expires_at,
	body       = excluded.body`

// Open opens (creating if needed) the report database at path and
// ensures the schema exists. File databases run in journal_mode=WAL
// with synchronous=NORMAL (ADR 0009); writes keep one connection
// (ADR 0007) and queries get their own. A :memory: path (tests) keeps
// everything on the single write connection.
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
	// synchronous is per connection; the write connection is the only
	// one that commits. NORMAL in WAL mode is durable across process
	// crashes — only power failure can lose the final moments (ADR 0009).
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
		// Opened after the pragmas: journal_mode=WAL is a property of
		// the database file, so every read connection sees it.
		// The pool is bounded (spec story 19 needs only its own
		// connections, not an unbounded number: 4 covers concurrent API
		// reads and the startup rebuild) and every read connection gets
		// a busy timeout through the DSN, so a query that loses a WAL
		// checkpoint race retries instead of failing the request.
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

// isMemory reports whether path names an in-memory database: WAL does
// not apply there and each connection would be a separate database
// (ADR 0009 consequences), so reads fall back to the write connection.
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

// Upsert inserts or overwrites the report for (rule, target) in one
// prepared statement: created_at is fixed at the row's first insert by
// the statement itself — no read precedes the write.
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

// List returns matching, unexpired reports sorted by created_at
// descending (ties broken by rule, target for determinism). It runs on
// the read path's own connections (ADR 0009).
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

// Delete removes reports matching the query regardless of expiry and
// returns the number of deleted rows. At least one filter is required
// (ErrUnfiltered otherwise): deletion is never delete-all.
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
