package memory

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	bandage "github.com/HT4w5/bandage/internal/domain"
	"github.com/HT4w5/bandage/internal/domain/track"
)

// Tests at the store seam (the tracker-cache port's adapter): the entry
// cap and its per-shard LRU eviction, the eviction log line (logging IS
// the contract for evictions per the spec's Testing Decisions), lazy
// TTL expiry plus the periodic sweep seam, no-TTL enrichment survival,
// and the statistics counters. Time is driven through the injected
// clock and direct sweep triggers — never sleep.

type testClock struct{ t time.Time }

func newTestClock(t time.Time) *testClock { return &testClock{t: t} }

func (c *testClock) Now() time.Time { return c.t }

func (c *testClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

// testLogger writes console-style records to buf so tests can assert
// the log text where logging is the contract.
func testLogger(buf *bytes.Buffer) zerolog.Logger {
	return zerolog.New(zerolog.ConsoleWriter{Out: buf, NoColor: true})
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

	// a was touched last: its state survived the eviction.
	if rec := update(t, s, "rule-one", "a", time.Hour, 1); rec.Value != 3 {
		t.Errorf("a after drop = %v, want 3 (LRU order kept a)", rec.Value)
	}
	// The evicted bucket accumulates fresh state from zero on the next
	// event — never a crash, never a stale continuation.
	if rec := update(t, s, "rule-one", "b", time.Hour, 1); rec.Value != 1 {
		t.Errorf("b after eviction = %v, want 1 (fresh accumulation)", rec.Value)
	}
}

// Every eviction is logged with its tracker namespace and its key and
// counted in statistics (spec: evictions are the one place where log
// text IS the contract). The key is spelled out per namespace: tracker
// entries log the Target (and the path where the key has one), the
// filesize namespace is keyed by paths and logs the path.
func TestStoreEvictionLoggedWithNamespaceAndTarget(t *testing.T) {
	buf := &bytes.Buffer{}
	s := newStore(1, 1, newTestClock(time.Time{}).Now, testLogger(buf))

	update(t, s, "rule-one", "203.0.113.7", time.Hour, 1)
	update(t, s, "rule-two", "203.0.113.8", time.Hour, 1) // caps: drops rule-one's entry

	logs := buf.String()
	if !strings.Contains(logs, "namespace=rule-one") {
		t.Errorf("eviction log missing tracker namespace:\n%s", logs)
	}
	if !strings.Contains(logs, "target=203.0.113.7") {
		t.Errorf("eviction log missing Target:\n%s", logs)
	}
	if st := s.Statistics(); st.Evictions != 1 {
		t.Errorf("evictions = %d, want 1 (eviction counted)", st.Evictions)
	}
}

// The logged Target is the true Target split from the key convention —
// never the raw cache key — and per-(Target, path) keys carry their path
// as its own attribute (the record always carries the namespace and its
// key: Target and path here).
func TestStoreEvictionLogsTrueTargetAndPath(t *testing.T) {
	buf := &bytes.Buffer{}
	s := newStore(1, 1, newTestClock(time.Time{}).Now, testLogger(buf))

	update(t, s, "iso-replay", bandage.ReplayTrackerKey("203.0.113.7/32", "/big.iso"), time.Hour, 1)
	update(t, s, "iso-replay", bandage.ReplayTrackerKey("203.0.113.8/32", "/big.iso"), time.Hour, 1) // caps

	logs := buf.String()
	if !strings.Contains(logs, "namespace=iso-replay") {
		t.Errorf("eviction log missing tracker namespace:\n%s", logs)
	}
	if !strings.Contains(logs, "target=203.0.113.7/32") {
		t.Errorf("eviction log missing the true Target:\n%s", logs)
	}
	if !strings.Contains(logs, "path=/big.iso") {
		t.Errorf("eviction log missing the path:\n%s", logs)
	}
	if strings.Contains(logs, "203.0.113.7/32\x00/big.iso") {
		t.Errorf("eviction log leaks the raw composite key:\n%s", logs)
	}
}

// The filesize namespace is keyed by paths, so its evictions carry the
// path as the record's key and never invent a Target (the namespace is
// named either way).
func TestStoreEvictionFilesizeLogsPathOnly(t *testing.T) {
	buf := &bytes.Buffer{}
	s := newStore(1, 1, newTestClock(time.Time{}).Now, testLogger(buf))

	update(t, s, bandage.FilesizeNamespace, "/a", 0, 1)
	update(t, s, bandage.FilesizeNamespace, "/b", 0, 1) // caps

	logs := buf.String()
	if !strings.Contains(logs, "namespace=filesize") {
		t.Errorf("eviction log missing the filesize namespace:\n%s", logs)
	}
	if !strings.Contains(logs, "path=/a") {
		t.Errorf("eviction log missing the path:\n%s", logs)
	}
	if strings.Contains(logs, "target=") {
		t.Errorf("filesize eviction log invents a Target:\n%s", logs)
	}
}

// reenterWriter proves where the eviction record is emitted from: its
// Write re-enters the store (Statistics locks every shard). Re-entry
// succeeds only while the evicting Update holds no shard lock — if the
// record were rendered under the lock, the probe would deadlock against
// the very shard being evicted.
type reenterWriter struct {
	s *Store
}

func (w reenterWriter) Write(p []byte) (int, error) {
	w.s.Statistics()
	return len(p), nil
}

// The eviction record is emitted after the shard lock is released
// (PLAN house rule: no I/O under the store's lock) — a log sink is free
// to call back into the store while rendering the record.
func TestStoreEvictionLogEmittedAfterUnlock(t *testing.T) {
	w := &reenterWriter{}
	s := newStore(1, 1, newTestClock(time.Time{}).Now, zerolog.New(w))
	w.s = s

	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, k := range [][2]string{{"rule-one", "203.0.113.7"}, {"rule-two", "203.0.113.8"}} {
			if _, err := s.Update(context.Background(), k[0], k[1], time.Hour, func(r *track.Record) {
				r.Value++
			}); err != nil {
				t.Errorf("Update(%q, %q): %v", k[0], k[1], err)
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("eviction record rendering deadlocked against the shard lock")
	}
	if st := s.Statistics(); st.Evictions != 1 {
		t.Errorf("evictions = %d, want 1 (eviction logged and counted together)", st.Evictions)
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
		t.Errorf("evictions = %d, want 0 (TTL expiry is not an eviction)", st.Evictions)
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

	update(t, s, bandage.FilesizeNamespace, "/releases/24.04.iso", 0, 0.5)
	clock.Advance(48 * time.Hour)
	s.SweepExpired()
	s.SweepExpired()

	rec := update(t, s, bandage.FilesizeNamespace, "/releases/24.04.iso", 0, 0.25)
	if rec.Value != 0.75 {
		t.Errorf("no-TTL record = %v, want 0.75 (never expired, never reset)", rec.Value)
	}
	if st := s.Statistics(); st.Size != 1 {
		t.Errorf("size = %d, want 1", st.Size)
	}
}

// The statistics counters: gets and sets count lookups and writes,
// misses count lookups without a live entry, evictions count entries
// removed by the entry cap, size counts entries (TTL removals are not
// evictions), and the entry cap is reported with them.
func TestStoreStatisticsCounters(t *testing.T) {
	clock := newTestClock(time.Time{})
	s := newStore(2, 1, clock.Now, testLogger(&bytes.Buffer{}))

	if st := s.Statistics(); st != (track.Statistics{EntryCap: 2}) {
		t.Fatalf("initial statistics = %+v, want zero counters with entry cap 2", st)
	}

	update(t, s, "rule-one", "a", time.Hour, 1) // new entry
	if st := s.Statistics(); st != (track.Statistics{Gets: 1, Sets: 1, Misses: 1, Size: 1, EntryCap: 2}) {
		t.Errorf("after 1st update = %+v, want {1 1 1 0 1 2}", st)
	}
	update(t, s, "rule-one", "a", time.Hour, 1) // live entry
	if st := s.Statistics(); st != (track.Statistics{Gets: 2, Sets: 2, Misses: 1, Size: 1, EntryCap: 2}) {
		t.Errorf("after 2nd update = %+v, want {2 2 1 0 1 2}", st)
	}
	update(t, s, "rule-one", "b", time.Hour, 1) // new entry
	if st := s.Statistics(); st != (track.Statistics{Gets: 3, Sets: 3, Misses: 2, Size: 2, EntryCap: 2}) {
		t.Errorf("after 3rd update = %+v, want {3 3 2 0 2 2}", st)
	}
	update(t, s, "rule-one", "c", time.Hour, 1) // new entry, caps out a
	if st := s.Statistics(); st != (track.Statistics{Gets: 4, Sets: 4, Misses: 3, Evictions: 1, Size: 2, EntryCap: 2}) {
		t.Errorf("after 4th update = %+v, want {4 4 3 1 2 2}", st)
	}

	clock.Advance(2 * time.Hour)
	s.SweepExpired()
	if st := s.Statistics(); st != (track.Statistics{Gets: 4, Sets: 4, Misses: 3, Evictions: 1, EntryCap: 2}) {
		t.Errorf("after sweep = %+v, want {4 4 3 1 0 2}", st)
	}
}

// The cap holds across all shards and namespaces: size never exceeds
// maxEntries, and every eviction is logged (eviction-log count ==
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
	if evictions := strings.Count(buf.String(), "tracker cache eviction"); evictions != 90 {
		t.Errorf("eviction log lines = %d, want 90 (every eviction logged)", evictions)
	}
}
