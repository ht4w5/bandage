package memory

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/HT4w5/bandage/internal/domain/track"
)

// Tests at the store seam (the tracker-cache port's adapter): the entry
// cap and its per-shard LRU eviction, the capped-drop log line (logging
// IS the contract for capped drops per the spec's Testing Decisions),
// lazy TTL expiry plus the periodic sweep seam, no-TTL enrichment
// survival, and the statistics counters. Time is driven through the
// injected clock and direct sweep triggers — never sleep.

type testClock struct{ t time.Time }

func newTestClock(t time.Time) *testClock { return &testClock{t: t} }

func (c *testClock) Now() time.Time { return c.t }

func (c *testClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func testLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, nil))
}

// update runs one accumulate step (value += inc) for (ns, key).
func update(t *testing.T, s *Store, ns, key string, ttl time.Duration, inc float64) track.Record {
	t.Helper()
	rec, err := s.Update(context.Background(), ns, key, ttl, func(r *track.Record) {
		r.Value += inc
	})
	if err != nil {
		t.Fatalf("Update(%q, %q): %v", ns, key, err)
	}
	return rec
}

// Under the cap, least-recently-used entries are evicted: a touched
// entry survives the next insert, the stale one restarts from zero.
// Single shard pins the LRU order deterministically.
func TestStoreCapEvictsLeastRecentlyUsed(t *testing.T) {
	s := newStore(3, 1, newTestClock(time.Time{}).Now, testLogger(&bytes.Buffer{}))

	update(t, s, "rule-one", "a", time.Hour, 1)
	update(t, s, "rule-one", "b", time.Hour, 1)
	update(t, s, "rule-one", "c", time.Hour, 1)
	if rec := update(t, s, "rule-one", "a", time.Hour, 1); rec.Value != 2 {
		t.Fatalf("touched a = %v, want 2", rec.Value)
	}

	// Inserting d caps the shard: the least-recently-used entry is b.
	if rec := update(t, s, "rule-one", "d", time.Hour, 1); rec.Value != 1 {
		t.Fatalf("d = %v, want 1", rec.Value)
	}
	if st := s.Statistics(); st.Size != 3 {
		t.Errorf("size = %d, want 3 (never above the cap)", st.Size)
	}

	// a was touched last: its state survived the capped drop.
	if rec := update(t, s, "rule-one", "a", time.Hour, 1); rec.Value != 3 {
		t.Errorf("a after drop = %v, want 3 (LRU order kept a)", rec.Value)
	}
	// The evicted bucket accumulates fresh state from zero on the next
	// event — never a crash, never a stale continuation.
	if rec := update(t, s, "rule-one", "b", time.Hour, 1); rec.Value != 1 {
		t.Errorf("b after eviction = %v, want 1 (fresh accumulation)", rec.Value)
	}
}

// Every capped drop is logged with its tracker namespace and Target and
// counted in statistics (spec: capped drops are the one place where log
// text IS the contract).
func TestStoreCappedDropLoggedWithNamespaceAndTarget(t *testing.T) {
	buf := &bytes.Buffer{}
	s := newStore(1, 1, newTestClock(time.Time{}).Now, testLogger(buf))

	update(t, s, "rule-one", "203.0.113.7", time.Hour, 1)
	update(t, s, "rule-two", "203.0.113.8", time.Hour, 1) // caps: drops rule-one's entry

	logs := buf.String()
	if !strings.Contains(logs, "namespace=rule-one") {
		t.Errorf("capped drop log missing tracker namespace:\n%s", logs)
	}
	if !strings.Contains(logs, "target=203.0.113.7") {
		t.Errorf("capped drop log missing Target:\n%s", logs)
	}
	if st := s.Statistics(); st.Evictions != 1 {
		t.Errorf("evictions = %d, want 1 (capped drop counted)", st.Evictions)
	}
}

// TTL expiry is enforced lazily on access: an expired entry restarts
// from zero and is counted as a miss, not an eviction.
func TestStoreLazyTTLExpiry(t *testing.T) {
	clock := newTestClock(time.Time{})
	s := newStore(4, 1, clock.Now, testLogger(&bytes.Buffer{}))

	if rec := update(t, s, "rule-one", "203.0.113.7", time.Minute, 5); rec.Value != 5 {
		t.Fatalf("first update = %v, want 5", rec.Value)
	}
	clock.Advance(2 * time.Minute)
	rec := update(t, s, "rule-one", "203.0.113.7", time.Minute, 1)
	if rec.Value != 1 {
		t.Errorf("after expiry = %v, want 1 (lazy expiry restarts from zero)", rec.Value)
	}
	st := s.Statistics()
	if st.Misses != 2 {
		t.Errorf("misses = %d, want 2 (absent insert + expired lookup)", st.Misses)
	}
	if st.Evictions != 0 {
		t.Errorf("evictions = %d, want 0 (TTL expiry is not a capped drop)", st.Evictions)
	}
}

// The periodic sweep removes entries nobody touched again; triggered
// directly here (the daemon ticks it at an internal cadence).
func TestStoreSweepExpiredRemovesStaleEntries(t *testing.T) {
	clock := newTestClock(time.Time{})
	s := newStore(4, 1, clock.Now, testLogger(&bytes.Buffer{}))

	update(t, s, "rule-one", "203.0.113.7", time.Minute, 1)
	update(t, s, "rule-one", "203.0.113.8", 0, 1) // no TTL
	clock.Advance(2 * time.Minute)
	s.SweepExpired()

	if st := s.Statistics(); st.Size != 1 {
		t.Errorf("size after sweep = %d, want 1 (expired entry removed)", st.Size)
	}
	if rec := update(t, s, "rule-one", "203.0.113.7", time.Minute, 1); rec.Value != 1 {
		t.Errorf("swept key = %v, want 1 (fresh accumulation)", rec.Value)
	}
	if rec := update(t, s, "rule-one", "203.0.113.8", 0, 1); rec.Value != 2 {
		t.Errorf("no-TTL key = %v, want 2 (kept by the sweep)", rec.Value)
	}
}

// The enrichment namespace shares the store without TTL (ttl == 0 =
// never expire) and survives sweeps and clock advances.
func TestStoreNoTTLEntrySurvivesSweeps(t *testing.T) {
	clock := newTestClock(time.Time{})
	s := newStore(4, 1, clock.Now, testLogger(&bytes.Buffer{}))

	update(t, s, "filesize", "/releases/24.04.iso", 0, 0.5)
	clock.Advance(48 * time.Hour)
	s.SweepExpired()
	s.SweepExpired()

	rec := update(t, s, "filesize", "/releases/24.04.iso", 0, 0.25)
	if rec.Value != 0.75 {
		t.Errorf("no-TTL record = %v, want 0.75 (never expired, never reset)", rec.Value)
	}
	if st := s.Statistics(); st.Size != 1 {
		t.Errorf("size = %d, want 1", st.Size)
	}
}

// The statistics counters: gets and sets count lookups and writes,
// misses count lookups without a live entry, evictions count capped
// drops, size counts entries (TTL removals are not evictions).
func TestStoreStatisticsCounters(t *testing.T) {
	clock := newTestClock(time.Time{})
	s := newStore(2, 1, clock.Now, testLogger(&bytes.Buffer{}))

	if st := s.Statistics(); st != (track.Statistics{}) {
		t.Fatalf("initial statistics = %+v, want zero", st)
	}

	update(t, s, "rule-one", "a", time.Hour, 1) // new entry
	if st := s.Statistics(); st != (track.Statistics{Gets: 1, Sets: 1, Misses: 1, Size: 1}) {
		t.Errorf("after 1st update = %+v, want {1 1 1 0 1}", st)
	}
	update(t, s, "rule-one", "a", time.Hour, 1) // live entry
	if st := s.Statistics(); st != (track.Statistics{Gets: 2, Sets: 2, Misses: 1, Size: 1}) {
		t.Errorf("after 2nd update = %+v, want {2 2 1 0 1}", st)
	}
	update(t, s, "rule-one", "b", time.Hour, 1) // new entry
	if st := s.Statistics(); st != (track.Statistics{Gets: 3, Sets: 3, Misses: 2, Size: 2}) {
		t.Errorf("after 3rd update = %+v, want {3 3 2 0 2}", st)
	}
	update(t, s, "rule-one", "c", time.Hour, 1) // new entry, caps out a
	if st := s.Statistics(); st != (track.Statistics{Gets: 4, Sets: 4, Misses: 3, Evictions: 1, Size: 2}) {
		t.Errorf("after 4th update = %+v, want {4 4 3 1 2}", st)
	}

	clock.Advance(2 * time.Hour)
	s.SweepExpired()
	if st := s.Statistics(); st != (track.Statistics{Gets: 4, Sets: 4, Misses: 3, Evictions: 1}) {
		t.Errorf("after sweep = %+v, want {4 4 3 1 0}", st)
	}
}

// The cap holds across all shards and namespaces: size never exceeds
// maxEntries, and every capped drop is logged (drop-log count ==
// eviction count).
func TestStoreCapEnforcedAcrossShardsAndNamespaces(t *testing.T) {
	buf := &bytes.Buffer{}
	s := New(10, newTestClock(time.Time{}).Now, testLogger(buf))

	for i := 0; i < 100; i++ {
		ns := fmt.Sprintf("rule-%d", i%3)
		update(t, s, ns, fmt.Sprintf("203.0.113.%d", i), time.Hour, 1)
	}

	st := s.Statistics()
	if st.Size != 10 {
		t.Errorf("size = %d, want 10 (cap enforced across shards)", st.Size)
	}
	if st.Evictions != 90 {
		t.Errorf("evictions = %d, want 90", st.Evictions)
	}
	if drops := strings.Count(buf.String(), "capped drop"); drops != 90 {
		t.Errorf("capped drop log lines = %d, want 90 (every drop logged)", drops)
	}
}
