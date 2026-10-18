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
// Delete and DeleteExpired pass repository errors through unwrapped:
// the repository's error contract (ErrUnfiltered, the adapter's error
// strings) is operator-visible and unchanged.
type Service struct {
	repo Repository
}

func NewService(repo Repository) *Service {
	return &Service{repo: repo}
}

// Trigger records the report for the matching (rule, target).
func (s *Service) Trigger(ctx context.Context, rec bandage.Report) error {
	if err := s.repo.Upsert(ctx, rec); err != nil {
		return fmt.Errorf("trigger report: %w", err)
	}
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
// tracker state is untouched (Repository.Delete).
func (s *Service) Delete(ctx context.Context, q Query) (int, error) {
	return s.repo.Delete(ctx, q)
}

// DeleteExpired deletes rows whose expires_at has passed and returns
// the number of deleted rows (Repository.DeleteExpired).
func (s *Service) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	return s.repo.DeleteExpired(ctx, now)
}
