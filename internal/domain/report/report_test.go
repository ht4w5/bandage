package report

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	bandage "github.com/HT4w5/bandage/internal/domain"
)

// stubRepository is the Repository stub the service is tested over
// (spec Testing Decisions: the report service over a stub repository):
// it records every call and returns configured results, no framework.
// upWedge, when set, holds every Upsert in flight — the pending write
// the contention tests drive — signalling upEntered on arrival and
// failing exactly the first write that passes when upFailFirst is set.
type stubRepository struct {
	mu          sync.Mutex
	ups         []bandage.Report
	upErr       error
	upWedge     chan struct{}
	upEntered   chan struct{}
	upFailFirst error
	upFailOnce  sync.Once
	lists       []Query
	rows        []bandage.Report
	listErr     error
	deletes     []Query
	delN        int
	delErr      error
	expires     []time.Time
	expN        int
	expErr      error
}

func (s *stubRepository) Upsert(_ context.Context, rec bandage.Report) error {
	if s.upWedge != nil {
		if s.upEntered != nil {
			s.upEntered <- struct{}{}
		}
		<-s.upWedge
	}
	s.mu.Lock()
	s.ups = append(s.ups, rec)
	err := s.upErr
	s.mu.Unlock()
	if err == nil {
		s.upFailOnce.Do(func() {
			if s.upFailFirst != nil {
				err = s.upFailFirst
			}
		})
	}
	return err
}

func (s *stubRepository) List(_ context.Context, q Query) ([]bandage.Report, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lists = append(s.lists, q)
	return s.rows, s.listErr
}

func (s *stubRepository) Delete(_ context.Context, q Query) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletes = append(s.deletes, q)
	return s.delN, s.delErr
}

func (s *stubRepository) DeleteExpired(_ context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expires = append(s.expires, now)
	return s.expN, s.expErr
}

// upserts returns the recorded write attempts (the call count).
func (s *stubRepository) upserts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.ups)
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

// --- suppression (ticket 03): one live report per (rule, target) ---

// liveRec is a Trigger's report at the given wall times for the
// suppression tests: UpdatedAt is the Trigger's wall time (aliveness is
// decided against it), ExpiresAt the report's lifetime.
func liveRec(rule, target string, now, expires time.Time) bandage.Report {
	return bandage.Report{Rule: rule, Target: target, UpdatedAt: now, ExpiresAt: expires}
}

// TestServiceTriggerSuppressesWhileReportAlive pins the suppression
// rule (ADR 0008): while a report for (rule, target) is alive further
// Triggers write nothing but complete without error (the report action
// ran — the tracker reset follows from the nil result). Suppression is
// per (rule, target): another rule or another target writes. A report
// is alive until expiry or deletion (GLOSSARY Report): past its expiry
// the Trigger writes over the stored row.
func TestServiceTriggerSuppressesWhileReportAlive(t *testing.T) {
	now := time.Date(2025, 10, 17, 18, 0, 0, 0, time.UTC)
	expiry := now.Add(time.Hour)
	rec := liveRec("sticky", "203.0.113.7/32", now, expiry)

	t.Run("a live report suppresses the write", func(t *testing.T) {
		repo := &stubRepository{}
		svc := NewService(repo)
		if err := svc.Trigger(context.Background(), rec); err != nil {
			t.Fatalf("first Trigger: %v", err)
		}
		if err := svc.Trigger(context.Background(), liveRec(rec.Rule, rec.Target, now.Add(10*time.Minute), expiry)); err != nil {
			t.Fatalf("suppressed Trigger: %v", err)
		}
		if len(repo.ups) != 1 {
			t.Errorf("upserts = %+v, want exactly the first write", repo.ups)
		}
	})

	t.Run("suppression is per (rule, target)", func(t *testing.T) {
		repo := &stubRepository{}
		svc := NewService(repo)
		if err := svc.Trigger(context.Background(), rec); err != nil {
			t.Fatalf("first Trigger: %v", err)
		}
		if err := svc.Trigger(context.Background(), liveRec("other", rec.Target, now, expiry)); err != nil {
			t.Fatalf("other rule: %v", err)
		}
		if err := svc.Trigger(context.Background(), liveRec(rec.Rule, "203.0.113.8/32", now, expiry)); err != nil {
			t.Fatalf("other target: %v", err)
		}
		if len(repo.ups) != 3 {
			t.Errorf("upserts = %d, want one per (rule, target)", len(repo.ups))
		}
	})

	t.Run("an expired report does not suppress", func(t *testing.T) {
		repo := &stubRepository{}
		svc := NewService(repo)
		if err := svc.Trigger(context.Background(), rec); err != nil {
			t.Fatalf("first Trigger: %v", err)
		}
		if err := svc.Trigger(context.Background(), liveRec(rec.Rule, rec.Target, expiry.Add(time.Minute), expiry.Add(2*time.Hour))); err != nil {
			t.Fatalf("Trigger past expiry: %v", err)
		}
		if len(repo.ups) != 2 {
			t.Errorf("upserts = %+v, want the write past expiry", repo.ups)
		}
	})
}

// TestServiceDeleteRearmsWriting pins the delete re-arm (spec story 9):
// once the report is deleted the next Trigger writes — and only the
// deleted filter's (rule, target) pairs re-arm.
func TestServiceDeleteRearmsWriting(t *testing.T) {
	now := time.Date(2025, 10, 17, 18, 0, 0, 0, time.UTC)
	expiry := now.Add(time.Hour)
	rec := liveRec("sticky", "203.0.113.7/32", now, expiry)

	t.Run("a matching delete re-arms", func(t *testing.T) {
		repo := &stubRepository{}
		svc := NewService(repo)
		if err := svc.Trigger(context.Background(), rec); err != nil {
			t.Fatalf("first Trigger: %v", err)
		}
		if _, err := svc.Delete(context.Background(), Query{Rule: "sticky"}); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if err := svc.Trigger(context.Background(), liveRec(rec.Rule, rec.Target, now.Add(10*time.Minute), expiry)); err != nil {
			t.Fatalf("re-armed Trigger: %v", err)
		}
		if len(repo.ups) != 2 {
			t.Errorf("upserts = %+v, want the re-armed write", repo.ups)
		}
	})

	t.Run("a non-matching delete keeps the suppression", func(t *testing.T) {
		repo := &stubRepository{}
		svc := NewService(repo)
		if err := svc.Trigger(context.Background(), rec); err != nil {
			t.Fatalf("first Trigger: %v", err)
		}
		if _, err := svc.Delete(context.Background(), Query{Rule: "other"}); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if err := svc.Trigger(context.Background(), liveRec(rec.Rule, rec.Target, now.Add(10*time.Minute), expiry)); err != nil {
			t.Fatalf("Trigger: %v", err)
		}
		if len(repo.ups) != 1 {
			t.Errorf("upserts = %+v, want the write still suppressed", repo.ups)
		}
	})
}

// TestServiceDeleteExpiredRearmsWriting pins the expiry re-arm (spec
// story 10): reports whose expiry the sweeper passes stop suppressing.
func TestServiceDeleteExpiredRearmsWriting(t *testing.T) {
	now := time.Date(2025, 10, 17, 18, 0, 0, 0, time.UTC)
	expiry := now.Add(time.Hour)
	rec := liveRec("sticky", "203.0.113.7/32", now, expiry)
	repo := &stubRepository{}
	svc := NewService(repo)
	if err := svc.Trigger(context.Background(), rec); err != nil {
		t.Fatalf("first Trigger: %v", err)
	}

	// A sweeper pass before the expiry must not re-arm.
	if _, err := svc.DeleteExpired(context.Background(), now.Add(30*time.Minute)); err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if err := svc.Trigger(context.Background(), liveRec(rec.Rule, rec.Target, now.Add(40*time.Minute), expiry)); err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	if len(repo.ups) != 1 {
		t.Fatalf("upserts = %+v, want the write still suppressed before expiry", repo.ups)
	}

	// The pass that sweeps the row re-arms writing.
	if _, err := svc.DeleteExpired(context.Background(), now.Add(2*time.Hour)); err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if err := svc.Trigger(context.Background(), liveRec(rec.Rule, rec.Target, now.Add(3*time.Hour), now.Add(4*time.Hour))); err != nil {
		t.Fatalf("re-armed Trigger: %v", err)
	}
	if len(repo.ups) != 2 {
		t.Errorf("upserts = %+v, want the re-armed write", repo.ups)
	}
}

// TestServiceFailedWriteDoesNotSuppressTheRetry pins story 5 at the
// write path: a failed write is not a Trigger outcome — nothing was
// written, so nothing suppresses the next Trigger's write.
func TestServiceFailedWriteDoesNotSuppressTheRetry(t *testing.T) {
	now := time.Date(2025, 10, 17, 18, 0, 0, 0, time.UTC)
	rec := liveRec("sticky", "203.0.113.7/32", now, now.Add(time.Hour))
	errStub := errors.New("stub failure")
	repo := &stubRepository{upErr: errStub}
	svc := NewService(repo)
	if err := svc.Trigger(context.Background(), rec); !errors.Is(err, errStub) {
		t.Fatalf("Trigger error = %v, want %v", err, errStub)
	}
	repo.upErr = nil
	if err := svc.Trigger(context.Background(), liveRec(rec.Rule, rec.Target, now.Add(time.Minute), now.Add(time.Hour))); err != nil {
		t.Fatalf("retry Trigger: %v", err)
	}
	if len(repo.ups) != 2 {
		t.Errorf("upserts = %+v, want the retry to write", repo.ups)
	}
}

// TestServiceRebuildDerivesLiveReportsFromTheTable pins the startup
// derivation (spec story 13): the live-report set is the report table's
// — Rebuild lists the table at Now and supplants the set, so alive rows
// suppress and absent rows do not.
func TestServiceRebuildDerivesLiveReportsFromTheTable(t *testing.T) {
	now := time.Date(2025, 10, 17, 18, 0, 0, 0, time.UTC)
	expiry := now.Add(time.Hour)
	stored := liveRec("sticky", "203.0.113.7/32", now, expiry)

	t.Run("stored rows suppress, absent rows write", func(t *testing.T) {
		repo := &stubRepository{rows: []bandage.Report{stored}}
		svc := NewService(repo)
		if err := svc.Rebuild(context.Background(), now); err != nil {
			t.Fatalf("Rebuild: %v", err)
		}
		if len(repo.lists) != 1 || !repo.lists[0].Now.Equal(now) {
			t.Errorf("list queries = %+v, want one at %v", repo.lists, now)
		}
		if err := svc.Trigger(context.Background(), liveRec(stored.Rule, stored.Target, now.Add(10*time.Minute), expiry)); err != nil {
			t.Fatalf("Trigger: %v", err)
		}
		if err := svc.Trigger(context.Background(), liveRec("other", "203.0.113.8/32", now.Add(10*time.Minute), expiry)); err != nil {
			t.Fatalf("Trigger: %v", err)
		}
		if len(repo.ups) != 1 {
			t.Errorf("upserts = %+v, want one write for the absent report", repo.ups)
		}
	})

	t.Run("rebuild supplants the set", func(t *testing.T) {
		repo := &stubRepository{}
		svc := NewService(repo)
		if err := svc.Trigger(context.Background(), stored); err != nil {
			t.Fatalf("first Trigger: %v", err)
		}
		if err := svc.Rebuild(context.Background(), now); err != nil {
			t.Fatalf("Rebuild: %v", err)
		}
		if err := svc.Trigger(context.Background(), liveRec(stored.Rule, stored.Target, now.Add(10*time.Minute), expiry)); err != nil {
			t.Fatalf("Trigger: %v", err)
		}
		if len(repo.ups) != 2 {
			t.Errorf("upserts = %+v, want the stale suppression gone", repo.ups)
		}
	})

	t.Run("repository failure passes through", func(t *testing.T) {
		errStub := errors.New("stub failure")
		repo := &stubRepository{listErr: errStub}
		if err := NewService(repo).Rebuild(context.Background(), now); err != errStub {
			t.Errorf("Rebuild error = %v, want the repository error unchanged (%v)", err, errStub)
		}
	})
}

// --- Trigger write contention (spec stories 4, 5, 14) ---

// waitPending is the unit-level settle window: a Trigger must not
// return while the key's write is still pending inside the repository
// (a premature return is exactly the hole — suppression decided before
// the write's outcome). The window is pure settle margin over goroutine
// scheduling, never a progress dependency: a slow machine can only
// weaken the assertion, never make it wrong.
func waitPending(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("Trigger returned %v while the write was still pending", err)
	case <-time.After(50 * time.Millisecond):
	}
}

// triggerAsync runs Trigger off the test goroutine, handing back its
// outcome (the in-test helpers fail inline and must not run from a
// goroutine).
func triggerAsync(svc *Service, rec bandage.Report) <-chan error {
	done := make(chan error, 1)
	go func() { done <- svc.Trigger(context.Background(), rec) }()
	return done
}

// TestServiceConcurrentTriggerWaitsForTheWriteOutcome pins the
// contention handoff: a Trigger arriving while the key's write is in
// flight waits for that write's outcome and re-evaluates — suppressed
// once it lands (a live report exists), writing it itself if it failed
// (a failed write is not a Trigger outcome: nothing suppressed the
// waiter and the detection must not be lost). Trigger returns nil
// exactly when the write landed or a live report suppressed it, so the
// caller's tracker reset follows the outcome (spec story 4).
func TestServiceConcurrentTriggerWaitsForTheWriteOutcome(t *testing.T) {
	now := time.Date(2025, 10, 17, 18, 0, 0, 0, time.UTC)
	expiry := now.Add(time.Hour)
	rec := liveRec("sticky", "203.0.113.7/32", now, expiry)
	errStub := errors.New("stub write failure")

	run := func(t *testing.T, failFirst error, wantUpserts int, wantFirst error) {
		t.Helper()
		wedge := make(chan struct{})
		repo := &stubRepository{upWedge: wedge, upEntered: make(chan struct{}, 4), upFailFirst: failFirst}
		svc := NewService(repo)

		a := triggerAsync(svc, rec)
		<-repo.upEntered // the write is in flight
		b := triggerAsync(svc, liveRec(rec.Rule, rec.Target, now, expiry))
		waitPending(t, b)
		close(wedge) // the in-flight write resolves

		if err := <-a; !errors.Is(err, wantFirst) {
			t.Errorf("in-flight Trigger error = %v, want %v", err, wantFirst)
		}
		if err := <-b; err != nil {
			t.Errorf("waiting Trigger error = %v, want nil", err)
		}
		if got := repo.upserts(); got != wantUpserts {
			t.Errorf("write attempts = %d, want %d", got, wantUpserts)
		}
		// Whatever landed suppresses the next Trigger (one write per
		// live (rule, Target)).
		if err := svc.Trigger(context.Background(), liveRec(rec.Rule, rec.Target, now.Add(time.Minute), expiry)); err != nil {
			t.Fatalf("next Trigger: %v", err)
		}
		if got := repo.upserts(); got != wantUpserts {
			t.Errorf("write attempts after the next Trigger = %d, want %d (suppressed)", got, wantUpserts)
		}
	}

	t.Run("the waiter retries after the in-flight write failed", func(t *testing.T) {
		run(t, errStub, 2, errStub)
	})

	t.Run("the waiter is suppressed once the write lands", func(t *testing.T) {
		run(t, nil, 1, nil)
	})

	t.Run("a cancelled waiter returns the context error", func(t *testing.T) {
		wedge := make(chan struct{})
		repo := &stubRepository{upWedge: wedge, upEntered: make(chan struct{}, 4)}
		svc := NewService(repo)
		a := triggerAsync(svc, rec)
		<-repo.upEntered

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- svc.Trigger(ctx, liveRec(rec.Rule, rec.Target, now, expiry)) }()
		waitPending(t, done)
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("cancelled waiter error = %v, want context.Canceled", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the cancelled waiter never returned")
		}
		close(wedge)
		if err := <-a; err != nil {
			t.Errorf("in-flight Trigger error = %v, want nil", err)
		}
		if got := repo.upserts(); got != 1 {
			t.Errorf("write attempts = %d, want 1 (the cancelled waiter wrote nothing)", got)
		}
	})
}

// TestServiceRebuildKeepsInFlightWrites pins the rebuild/Trigger
// interleaving: a write in flight while Rebuild derives the set must
// keep its suppression — the derivation runs under the service lock
// and in-flight entries settle on their own outcome, so a Trigger
// racing the rebuild is never discarded (a discarded entry lets the
// next Trigger duplicate the write).
func TestServiceRebuildKeepsInFlightWrites(t *testing.T) {
	now := time.Date(2025, 10, 17, 18, 0, 0, 0, time.UTC)
	expiry := now.Add(time.Hour)
	rec := liveRec("sticky", "203.0.113.7/32", now, expiry)
	wedge := make(chan struct{})
	repo := &stubRepository{upWedge: wedge, upEntered: make(chan struct{}, 4)}
	svc := NewService(repo)

	a := triggerAsync(svc, rec)
	<-repo.upEntered // the write is in flight

	// Rebuild derives the set from the table mid-write: the pending
	// report is not a row yet (List sees nothing).
	if err := svc.Rebuild(context.Background(), now); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	close(wedge) // the write lands
	if err := <-a; err != nil {
		t.Fatalf("in-flight Trigger: %v", err)
	}

	// The landed write still suppresses: its entry survived the rebuild.
	if err := svc.Trigger(context.Background(), liveRec(rec.Rule, rec.Target, now.Add(time.Minute), expiry)); err != nil {
		t.Fatalf("Trigger after rebuild: %v", err)
	}
	if got := repo.upserts(); got != 1 {
		t.Errorf("write attempts = %d, want 1 (the racing Trigger's suppression must survive the rebuild)", got)
	}
}
