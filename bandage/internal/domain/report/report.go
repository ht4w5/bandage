// Package report holds the report lifecycle: the Service every report mutation
// flows through (Trigger write, delete-by-filter, expiry deletion) and its port.
package report

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/HT4w5/webmedkit/bandage/internal/domain"
)

// Query filters reports by rule and/or target (empty = no filter).
type Query struct {
	Rule   string
	Target string
	// Now bounds expiry: rows with expires_at <= Now are never returned.
	Now time.Time
}

// Matches reports whether a (rule, target) pair falls in the query's filter: an empty Rule or Target matches everything.
func (q Query) Matches(rule, target string) bool {
	return (q.Rule == "" || q.Rule == rule) && (q.Target == "" || q.Target == target)
}

// ErrUnfiltered is returned by Repository.Delete when neither Rule nor Target is set: deletion is never delete-all.
var ErrUnfiltered = errors.New("report: delete requires a rule or target filter")

// Repository persists reports, one row per (rule, target).
type Repository interface {
	// Upsert inserts or overwrites the report for (rule, target); created_at
	// stays fixed at the row's first insert.
	Upsert(ctx context.Context, rec domain.Report) error
	// List returns matching, unexpired reports sorted by created_at descending.
	List(ctx context.Context, q Query) ([]domain.Report, error)
	// Delete removes reports matching the query and returns the deleted row count.
	// Rule or Target must be set (ErrUnfiltered otherwise); rows match regardless of expiry.
	Delete(ctx context.Context, q Query) (int, error)
	// DeleteExpired deletes rows whose expires_at has passed and returns the number of deleted rows.
	DeleteExpired(ctx context.Context, now time.Time) (int, error)
}

// Service is the one report lifecycle module: Trigger upserts one report per (rule, target);
// while a report is alive Triggers write nothing but return nil (ADR 0008).
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

// liveEntry is one (rule, target)'s suppression state: settled expiry decides
// aliveness at Trigger time; a non-nil inflight marks a pending write.
type liveEntry struct {
	expiresAt time.Time
	// inflight is non-nil only while this key's write is in flight; closed under
	// s.mu once settled (entry kept on success, deleted on failure).
	inflight chan struct{}
}

func NewService(repo Repository) *Service {
	return &Service{repo: repo, live: make(map[reportKey]*liveEntry)}
}

// Trigger records the report for (rule, target) unless it is already alive, in
// which case the write is suppressed; concurrent Triggers produce at most one write.
func (s *Service) Trigger(ctx context.Context, rec domain.Report) error {
	key := reportKey{rule: rec.Rule, target: rec.Target}
	var e *liveEntry
	for {
		s.mu.Lock()
		cur, ok := s.live[key]
		if ok && cur.inflight != nil {
			// A write for this key is pending: wait for its outcome, then
			// re-evaluate (the pending write is not a live report).
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

// Rebuild derives the live-report set from the report table at now and
// supplants the set, keeping in-flight entries; runs under s.mu (no interleaving).
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

// List returns matching, unexpired reports (Repository.List).
func (s *Service) List(ctx context.Context, q Query) ([]domain.Report, error) {
	return s.repo.List(ctx, q)
}

// Delete removes reports matching the query and returns the number of deleted
// rows (Repository.Delete). The deleted pairs leave the live set: re-arms writing.
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

// DeleteExpired deletes rows whose expires_at has passed and returns the number
// of deleted rows (Repository.DeleteExpired). Swept reports leave the live set.
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
