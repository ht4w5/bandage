// Package report holds the report write path: the ReportService a Trigger
// writes through, and the persistence port behind it. The report action is
// the only write path to the report table (spec: Reports).
package report

import (
	"context"
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

// Repository persists reports, one row per (rule, target).
type Repository interface {
	// Upsert inserts or overwrites the report for (rule, target).
	// created_at stays fixed at the row's first insert; updated_at,
	// expires_at, tracker reading and sample are overwritten.
	Upsert(ctx context.Context, rec bandage.Report) error
	// List returns matching, unexpired reports sorted by created_at
	// descending.
	List(ctx context.Context, q Query) ([]bandage.Report, error)
	// DeleteExpired deletes rows whose expires_at has passed and returns
	// the number of deleted rows.
	DeleteExpired(ctx context.Context, now time.Time) (int, error)
}

// Service is the named write path: a Trigger upserts exactly one report
// per (rule, target).
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
