package report

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	bandage "github.com/HT4w5/bandage/internal/domain"
)

// stubRepository is the Repository stub the service is tested over
// (spec Testing Decisions: the report service over a stub repository):
// it records every call and returns configured results, no framework.
type stubRepository struct {
	ups     []bandage.Report
	upErr   error
	lists   []Query
	rows    []bandage.Report
	listErr error
	deletes []Query
	delN    int
	delErr  error
	expires []time.Time
	expN    int
	expErr  error
}

func (s *stubRepository) Upsert(_ context.Context, rec bandage.Report) error {
	s.ups = append(s.ups, rec)
	return s.upErr
}

func (s *stubRepository) List(_ context.Context, q Query) ([]bandage.Report, error) {
	s.lists = append(s.lists, q)
	return s.rows, s.listErr
}

func (s *stubRepository) Delete(_ context.Context, q Query) (int, error) {
	s.deletes = append(s.deletes, q)
	return s.delN, s.delErr
}

func (s *stubRepository) DeleteExpired(_ context.Context, now time.Time) (int, error) {
	s.expires = append(s.expires, now)
	return s.expN, s.expErr
}

// TestServiceTriggerWritesThroughRepository pins the Trigger write
// contract: the report reaches the repository unchanged and a
// repository failure surfaces wrapped but identifiable.
func TestServiceTriggerWritesThroughRepository(t *testing.T) {
	rec := bandage.Report{Rule: "sustained-egress", Target: "203.0.113.7/32"}
	errStub := errors.New("stub failure")

	t.Run("forwards the report", func(t *testing.T) {
		repo := &stubRepository{}
		if err := NewService(repo).Trigger(context.Background(), rec); err != nil {
			t.Fatalf("Trigger: %v", err)
		}
		if !reflect.DeepEqual(repo.ups, []bandage.Report{rec}) {
			t.Errorf("upserts = %+v, want %+v", repo.ups, []bandage.Report{rec})
		}
	})

	t.Run("wraps repository failures", func(t *testing.T) {
		repo := &stubRepository{upErr: errStub}
		err := NewService(repo).Trigger(context.Background(), rec)
		if !errors.Is(err, errStub) {
			t.Errorf("Trigger error = %v, want it to identify %v", err, errStub)
		}
	})
}

// TestServiceDeleteByFilter pins the delete-by-filter contract the API
// calls through: the filter reaches the repository unchanged, the
// deletion count is reported unchanged and repository errors —
// including ErrUnfiltered — pass through unwrapped (their strings are
// operator-visible).
func TestServiceDeleteByFilter(t *testing.T) {
	errStub := errors.New("stub failure")
	tests := []struct {
		name string
		q    Query
		n    int
		err  error
	}{
		{"rule and target", Query{Rule: "sustained-egress", Target: "203.0.113.7/32"}, 2, nil},
		{"rule only", Query{Rule: "sustained-egress"}, 7, nil},
		{"target only", Query{Target: "203.0.113.7/32"}, 1, nil},
		{"unfiltered keeps the repository contract", Query{}, 0, fmt.Errorf("sqlite: delete: %w", ErrUnfiltered)},
		{"repository failure passes through unwrapped", Query{Rule: "r"}, 0, errStub},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &stubRepository{delN: tt.n, delErr: tt.err}
			n, err := NewService(repo).Delete(context.Background(), tt.q)
			if err != tt.err {
				t.Errorf("Delete error = %v, want the repository error unchanged (%v)", err, tt.err)
			}
			if n != tt.n {
				t.Errorf("Delete count = %d, want %d", n, tt.n)
			}
			if !reflect.DeepEqual(repo.deletes, []Query{tt.q}) {
				t.Errorf("delete queries = %+v, want %+v", repo.deletes, []Query{tt.q})
			}
		})
	}
}

// TestServiceDeleteExpired pins the expiry-deletion contract the
// sweeper calls through: the wall clock reaches the repository
// unchanged, the deletion count is reported unchanged and repository
// errors pass through unwrapped.
func TestServiceDeleteExpired(t *testing.T) {
	now := time.Date(2025, 10, 17, 18, 0, 0, 0, time.UTC)
	errStub := errors.New("stub failure")
	tests := []struct {
		name string
		n    int
		err  error
	}{
		{"forwards the clock and reports the count", 3, nil},
		{"repository failure passes through unwrapped", 0, errStub},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &stubRepository{expN: tt.n, expErr: tt.err}
			n, err := NewService(repo).DeleteExpired(context.Background(), now)
			if err != tt.err {
				t.Errorf("DeleteExpired error = %v, want the repository error unchanged (%v)", err, tt.err)
			}
			if n != tt.n {
				t.Errorf("DeleteExpired count = %d, want %d", n, tt.n)
			}
			if len(repo.expires) != 1 || !repo.expires[0].Equal(now) {
				t.Errorf("delete-expired clocks = %+v, want [%v]", repo.expires, now)
			}
		})
	}
}

// TestServiceList pins the read contract the API calls through: the
// query reaches the repository unchanged and the matching reports come
// back unchanged.
func TestServiceList(t *testing.T) {
	q := Query{Rule: "sustained-egress", Now: time.Date(2025, 10, 17, 18, 0, 0, 0, time.UTC)}
	rows := []bandage.Report{{Rule: "sustained-egress", Target: "203.0.113.7/32"}}
	errStub := errors.New("stub failure")

	t.Run("forwards the query and returns the reports", func(t *testing.T) {
		repo := &stubRepository{rows: rows}
		got, err := NewService(repo).List(context.Background(), q)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if !reflect.DeepEqual(got, rows) {
			t.Errorf("List = %+v, want %+v", got, rows)
		}
		if !reflect.DeepEqual(repo.lists, []Query{q}) {
			t.Errorf("list queries = %+v, want %+v", repo.lists, []Query{q})
		}
	})

	t.Run("repository failure passes through unwrapped", func(t *testing.T) {
		repo := &stubRepository{listErr: errStub}
		_, err := NewService(repo).List(context.Background(), q)
		if err != errStub {
			t.Errorf("List error = %v, want the repository error unchanged (%v)", err, errStub)
		}
	})
}
