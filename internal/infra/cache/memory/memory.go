// Package memory is the in-memory tracker cache adapter: a sharded map
// with per-key atomic updates and sliding TTL expiry (enforced lazily on
// access plus a periodic sweep), bounded by a global entry cap enforced
// by per-shard LRU eviction. Every capped drop is logged with its
// tracker namespace and the true Target (and path, where the key has
// one) decoded from the domain's key convention, and counted in
// statistics.
package memory

import (
	"container/list"
	"context"
	"errors"
	"hash/fnv"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	bandage "github.com/HT4w5/bandage/internal/domain"
	"github.com/HT4w5/bandage/internal/domain/track"
)

const defaultShards = 256

// Store is an in-memory tracker cache (the TrackerCache port declared
// beside its consumer in domain/evaluation is satisfied structurally)
// bounded to maxEntries across all shards and namespaces. It is safe for
// concurrent use.
//
// TTL expiry is enforced lazily on Update and by SweepExpired, which the
// owner runs periodically (the daemon ticks it at an internal cadence).
// An entry with ttl == 0 never expires (the filesize enrichment
// namespace shares this store without TTL).
type Store struct {
	shards   []shard
	perShard int
	now      func() time.Time
	logger   *slog.Logger

	gets, sets, misses, evictions atomic.Int64
}

type shard struct {
	mu sync.Mutex
	m  map[string]*list.Element // fullKey -> LRU element
	l  list.List                // LRU order: front = most recently used
}

type entry struct {
	fullKey string
	ns      string
	key     string
	rec     track.Record
	// expires is the sliding expiry; zero means no expiry.
	expires time.Time
}

// New returns an empty store bounded to maxEntries (clamped to at least
// 1) across all shards and namespaces. now is the wall clock expiry
// runs on; logger receives a warning for every capped drop.
func New(maxEntries int, now func() time.Time, logger *slog.Logger) *Store {
	return newStore(maxEntries, defaultShards, now, logger)
}

// newStore pins the shard count (tests use one shard to observe exact
// LRU order). The entry cap becomes a per-shard budget summing to at
// most maxEntries.
func newStore(maxEntries, shards int, now func() time.Time, logger *slog.Logger) *Store {
	if maxEntries < 1 {
		maxEntries = 1
	}
	if shards > maxEntries {
		shards = maxEntries
	}
	if shards < 1 {
		shards = 1
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &Store{
		shards:   make([]shard, shards),
		perShard: maxEntries / shards,
		now:      now,
		logger:   logger,
	}
	if s.perShard < 1 {
		s.perShard = 1
	}
	return s
}

// Update atomically applies fn to the record for (ns, key) and returns
// it. An expired entry is treated as absent (lazy expiry): the record
// restarts from zero. Inserting over the cap drops the shard's
// least-recently-used entry — a capped drop, logged with its tracker
// namespace and true Target (and path where present) and counted in
// statistics. fn runs under the shard lock and must not perform I/O or
// use ctx.
func (s *Store) Update(ctx context.Context, ns, key string, ttl time.Duration, fn func(*track.Record)) (track.Record, error) {
	if fn == nil {
		return track.Record{}, errors.New("memory: update fn must not be nil")
	}
	s.gets.Add(1)
	fullKey := ns + "\x00" + key
	sh := s.shardFor(fullKey)

	sh.mu.Lock()
	defer sh.mu.Unlock()
	now := s.now()

	if el, ok := sh.m[fullKey]; ok {
		e := el.Value.(*entry)
		if e.expires.IsZero() || now.Before(e.expires) {
			s.sets.Add(1)
			fn(&e.rec)
			e.expires = expiry(now, ttl)
			sh.l.MoveToFront(el)
			return e.rec, nil
		}
		// Lazy expiry: drop the entry, restart the bucket below.
		sh.remove(el)
	}

	s.misses.Add(1)
	s.sets.Add(1)
	e := &entry{fullKey: fullKey, ns: ns, key: key, expires: expiry(now, ttl)}
	fn(&e.rec)
	if sh.m == nil {
		sh.m = make(map[string]*list.Element)
	}
	sh.m[fullKey] = sh.l.PushFront(e)
	s.evictLocked(sh)
	return e.rec, nil
}

// SweepExpired removes every expired entry across all shards. Entries
// without a TTL never expire. TTL removals are not capped drops: nothing
// is logged or counted as an eviction for them.
func (s *Store) SweepExpired() {
	now := s.now()
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		for el := sh.l.Back(); el != nil; {
			prev := el.Prev()
			if e := el.Value.(*entry); !e.expires.IsZero() && !now.Before(e.expires) {
				sh.remove(el)
			}
			el = prev
		}
		sh.mu.Unlock()
	}
}

// Statistics returns the operational counters (flux's Statistics
// precedent): Gets and Sets count Update lookups and writes, Misses
// counts lookups that found no live entry (absent or TTL-expired),
// Evictions counts capped drops, and Size is the current entry count
// (expired entries count until lazily dropped or swept).
func (s *Store) Statistics() track.Statistics {
	var size int64
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		size += int64(sh.l.Len())
		sh.mu.Unlock()
	}
	return track.Statistics{
		Gets:      s.gets.Load(),
		Sets:      s.sets.Load(),
		Misses:    s.misses.Load(),
		Evictions: s.evictions.Load(),
		Size:      size,
	}
}

func (s *Store) shardFor(fullKey string) *shard {
	h := fnv.New32a()
	h.Write([]byte(fullKey))
	return &s.shards[h.Sum32()%uint32(len(s.shards))]
}

// evictLocked drops least-recently-used entries until the shard is
// within its budget of the entry cap. Every capped drop is logged with
// its tracker namespace and true Target (story 41: every capped drop is
// logged; ticket 07: with its tracker namespace and Target) and counted
// in statistics. Called under the shard lock.
func (s *Store) evictLocked(sh *shard) {
	for sh.l.Len() > s.perShard {
		el := sh.l.Back()
		e := el.Value.(*entry)
		sh.remove(el)
		s.evictions.Add(1)
		s.logger.Warn("tracker cache capped drop", dropAttrs(e)...)
	}
}

// dropAttrs renders a capped drop's identity per the domain's key
// convention: namespace plus the true Target decoded from the key —
// never the raw key — and the path for per-(Target, path) keys. The
// filesize namespace has no Target: its keys are paths and log as their
// own case.
func dropAttrs(e *entry) []any {
	if e.ns == bandage.FilesizeNamespace {
		return []any{"namespace", e.ns, "path", e.key}
	}
	target, path := bandage.SplitTrackerKey(e.key)
	attrs := []any{"namespace", e.ns, "target", target}
	if path != "" {
		attrs = append(attrs, "path", path)
	}
	return attrs
}

func (sh *shard) remove(el *list.Element) {
	e := el.Value.(*entry)
	sh.l.Remove(el)
	delete(sh.m, e.fullKey)
}

// expiry maps ttl to the sliding expiry time (zero = no expiry).
func expiry(now time.Time, ttl time.Duration) time.Time {
	if ttl > 0 {
		return now.Add(ttl)
	}
	return time.Time{}
}
