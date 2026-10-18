// Package report holds the report lifecycle: the Service every report
// mutation flows through — the Trigger write, delete-by-filter (the API)
// and expiry deletion (the sweeper) — and the persistence port behind
// it. The report action is the only write path to the report table
// (spec: Reports).
package report

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	bandage "github.com/HT4w5/bandage/internal/domain"
)

// Query filters reports by rule and/or target (empty = no filter).
type Query struct {
	Rule   string
	Target string
	// Now bounds expiry: rows with expires_at <= Now are never returned
	// (safety net for the periodic sweeper).
	Now time.Time
}

// Matches reports whether a (rule, target) pair falls in the query's
// filter: an empty Rule or Target matches everything. It is the one
// filter predicate — the service applies it to the live set, the
// repositories to their rows.
func (q Query) Matches(rule, target string) bool {
	return (q.Rule == "" || q.Rule == rule) && (q.Target == "" || q.Target == target)
}

// ErrUnfiltered is returned by Repository.Delete when neither Rule nor
// Target is set: deletion is by filter, never delete-all.
var ErrUnfiltered = errors.New("report: delete requires a rule or target filter")

// Repository persists reports, one row per (rule, target).
type Repository interface {
	// Upsert inserts or overwrites the report for (rule, target).
	// created_at stays fixed at the row's first insert; updated_at,
	// expires_at, tracker reading and sample are overwritten.
	Upsert(ctx context.Context, rec bandage.Report) error
	// List returns matching, unexpired reports sorted by created_at
	// descending.
	List(ctx context.Context, q Query) ([]bandage.Report, error)
	// Delete removes reports matching the query and returns the number
	// of deleted rows. At least one of Rule or Target must be set
	// (ErrUnfiltered otherwise): deletion is never delete-all. Rows
	// match regardless of expiry — deletion addresses storage, not
	// just the live list — and tracker state is untouched.
	Delete(ctx context.Context, q Query) (int, error)
	// DeleteExpired deletes rows whose expires_at has passed and returns
	// the number of deleted rows.
	DeleteExpired(ctx context.Context, now time.Time) (int, error)
}

// Service is the one report lifecycle module: a Trigger upserts exactly
// one report per (rule, target), delete-by-filter and expiry deletion
// remove rows. Every report mutation goes through it — the API and the
// sweeper call the service, never the repository directly — so later
// lifecycle rules can hang off these methods.
//
// The service also owns the write suppression (ADR 0008): while a
// report for (rule, target) is alive a Trigger writes nothing but
// completes without error (the report action ran). The live-report set
// behind it is keyed exactly like report rows — (rule, target) — and
// derived from the report table: rebuilt at startup (Rebuild),
// maintained on Trigger, delete and expiry. In-memory state is only an
// optimization: the report table is the correctness source, so a
// restart re-derives it. A report is alive until expiry or deletion
// (spec: Report): an expired entry stops suppressing even before the
// sweeper removes its row, and the Trigger writes over it.
//
// Delete and DeleteExpired pass repository errors through unwrapped:
// the repository's error contract (ErrUnfiltered, the adapter's error
// strings) is operator-visible and unchanged.
type Service struct {
	repo Repository

	mu   sync.Mutex
	live map[reportKey]*liveEntry
}

// reportKey is a report row's identity: (rule, target).
type reportKey struct {
	rule   string
	target string
}

// liveEntry is one (rule, target)'s suppression state. A settled entry
// is the live report's expiry: it decides aliveness at Trigger time.
// An entry with inflight set marks a report write pending for the key:
// concurrent Triggers wait for its outcome instead of mistaking the
// pending write for a live report (spec stories 4, 5, 14).
type liveEntry struct {
	expiresAt time.Time
	// inflight is non-nil only while this key's write is in flight and
	// is closed under s.mu once the outcome is settled (expiresAt set
	// on success, the entry deleted on failure).
	inflight chan struct{}
}

func NewService(repo Repository) *Service {
	return &Service{repo: repo, live: make(map[reportKey]*liveEntry)}
}

// Trigger records the report for the matching (rule, target) — unless
// that report is already alive, in which case the write is suppressed
// and Trigger completes without error (the report action ran; its
// caller empties the tracker either way). Aliveness is decided at the
// Trigger's wall time (rec.UpdatedAt): a report is alive while
// expires_at is still ahead of it.
//
// Concurrent Triggers for one (rule, target) produce at most one write
// (spec story 14): the first writes while the key is marked in flight,
// and later Triggers wait for that write's outcome and re-evaluate —
// suppressed once it lands (a live report now exists), writing it
// themselves if it failed (spec story 5: a failed write is not a
// Trigger outcome and must not lose the episode's detection; the
// GLOSSARY Trigger carve-out). Trigger returns nil exactly when the
// write landed or a live report suppressed it, so the caller's tracker
// reset stays honest (spec story 4).
func (s *Service) Trigger(ctx context.Context, rec bandage.Report) error {
	key := reportKey{rule: rec.Rule, target: rec.Target}
	var e *liveEntry
	for {
		s.mu.Lock()
		cur, ok := s.live[key]
		if ok && cur.inflight != nil {
			// A write for this key is pending: wait for its outcome,
			// then re-evaluate. The pending write is not a live report.
			ch := cur.inflight
			s.mu.Unlock()
			select {
			case <-ch:
				continue
			case <-ctx.Done():
				return fmt.Errorf("trigger report: %w", ctx.Err())
			}
		}
		if ok && cur.expiresAt.After(rec.UpdatedAt) {
			s.mu.Unlock()
			return nil
		}
		e = &liveEntry{inflight: make(chan struct{})}
		s.live[key] = e
		s.mu.Unlock()
		break
	}
	if err := s.repo.Upsert(ctx, rec); err != nil {
		s.mu.Lock()
		if s.live[key] == e {
			delete(s.live, key)
		}
		ch := e.inflight
		e.inflight = nil
		close(ch)
		s.mu.Unlock()
		return fmt.Errorf("trigger report: %w", err)
	}
	s.mu.Lock()
	e.expiresAt = rec.ExpiresAt
	ch := e.inflight
	e.inflight = nil
	close(ch)
	s.mu.Unlock()
	return nil
}

// Rebuild derives the live-report set from the report table at startup
// (spec story 13): the rows the table still serves — the unexpired ones
// at now — suppress; deleted or expired rows have left no state behind.
// It supplants whatever the set held, except entries whose write is
// still in flight: those settle on their own outcome and are never
// discarded, so a Trigger racing the rebuild keeps its suppression.
// The whole derivation runs under s.mu — including the repository
// list — so a Trigger cannot interleave between the listing and the
// swap.
func (s *Service) Rebuild(ctx context.Context, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.repo.List(ctx, Query{Now: now})
	if err != nil {
		return err
	}
	live := make(map[reportKey]*liveEntry, len(rows))
	for _, rec := range rows {
		live[reportKey{rule: rec.Rule, target: rec.Target}] = &liveEntry{expiresAt: rec.ExpiresAt}
	}
	for key, e := range s.live {
		if e.inflight != nil {
			live[key] = e
		}
	}
	s.live = live
	return nil
}

// List returns matching, unexpired reports sorted by created_at
// descending (Repository.List).
func (s *Service) List(ctx context.Context, q Query) ([]bandage.Report, error) {
	return s.repo.List(ctx, q)
}

// Delete removes reports matching the query and returns the number of
// deleted rows. At least one of Rule or Target must be set
// (ErrUnfiltered otherwise); rows match regardless of expiry and
// tracker state is untouched (Repository.Delete). The deleted rows'
// (rule, target) pairs leave the live-report set: deletion re-arms
// writing (spec story 9).
func (s *Service) Delete(ctx context.Context, q Query) (int, error) {
	n, err := s.repo.Delete(ctx, q)
	if err != nil {
		return n, err
	}
	s.mu.Lock()
	for key := range s.live {
		if q.Matches(key.rule, key.target) {
			delete(s.live, key)
		}
	}
	s.mu.Unlock()
	return n, nil
}

// DeleteExpired deletes rows whose expires_at has passed and returns
// the number of deleted rows (Repository.DeleteExpired). The swept
// reports leave the live-report set: expiry re-arms writing (spec story
// 10).
func (s *Service) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	n, err := s.repo.DeleteExpired(ctx, now)
	if err != nil {
		return n, err
	}
	s.mu.Lock()
	for key, e := range s.live {
		if !e.expiresAt.After(now) {
			delete(s.live, key)
		}
	}
	s.mu.Unlock()
	return n, nil
}
