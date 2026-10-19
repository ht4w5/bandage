// Package memory is the in-memory tracker cache adapter: a sharded map with
// per-key atomic updates, sliding TTL expiry and per-shard LRU eviction.
package memory

import (
	"container/list"
	"context"
	"errors"
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"

	bandage "github.com/HT4w5/bandage/internal/domain"
	"github.com/HT4w5/bandage/internal/domain/track"
)

const defaultShards = 256

// Store is an in-memory tracker cache (the TrackerCache port is satisfied
// structurally) bounded to maxEntries; ttl == 0 never expires, concurrent-safe.
type Store struct {
	shards   []shard
	perShard int
	entryCap int64
	now      func() time.Time
	logger   zerolog.Logger

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

// New returns an empty store bounded to maxEntries (clamped to at least 1);
// now is the wall clock expiry runs on, logger receives a warning per eviction.
func New(maxEntries int, now func() time.Time, logger zerolog.Logger) *Store {
	return newStore(maxEntries, defaultShards, now, logger)
}

// newStore pins the shard count (tests use one shard to observe exact LRU
// order); the entry cap becomes a per-shard budget summing to at most maxEntries.
func newStore(maxEntries, shards int, now func() time.Time, logger zerolog.Logger) *Store {
	if maxEntries < 1 {
		maxEntries = 1
	}
	if shards > maxEntries {
		shards = maxEntries
	}
	if shards < 1 {
		shards = 1
	}
	s := &Store{
		shards:   make([]shard, shards),
		perShard: maxEntries / shards,
		entryCap: int64(maxEntries),
		now:      now,
		logger:   logger,
	}
	if s.perShard < 1 {
		s.perShard = 1
	}
	return s
}

// Update atomically applies fn to the record for (ns, key); expired entries restart
// from zero, over-cap inserts evict the shard's LRU (logged and counted; fn: no I/O).
func (s *Store) Update(ctx context.Context, ns, key string, ttl time.Duration, fn func(*track.Record)) (track.Record, error) {
	if fn == nil {
		return track.Record{}, errors.New("memory: update fn must not be nil")
	}
	s.gets.Add(1)
	fullKey := ns + "\x00" + key
	sh := s.shardFor(fullKey)

	rec, evicted := s.updateLocked(sh, fullKey, ns, key, ttl, fn)

	// Log and count evictions after the lock is released: no I/O under
	// the store's locks, since a log sink may call back into the store.
	for _, e := range evicted {
		s.evictions.Add(1)
		evictionAttrs(s.logger.Warn(), e).Msg("tracker cache eviction")
	}
	return rec, nil
}

// updateLocked applies fn under the shard lock, returning the record plus any
// entries evicted to make room (the caller logs and counts them outside the lock).
func (s *Store) updateLocked(sh *shard, fullKey, ns, key string, ttl time.Duration, fn func(*track.Record)) (track.Record, []*entry) {
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
	return e.rec, s.evictLocked(sh)
}

// Clear empties the record for (ns, key) (the Trigger reset) so later updates
// start from zero; absent records are a no-op. Counts in no statistics.
func (s *Store) Clear(_ context.Context, ns, key string) error {
	fullKey := ns + "\x00" + key
	sh := s.shardFor(fullKey)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if el, ok := sh.m[fullKey]; ok {
		sh.remove(el)
	}
	return nil
}

// SweepExpired removes every expired entry across all shards (no-TTL entries
// never expire). TTL removals are not evictions: nothing is logged or counted.
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

// Statistics returns the operational counters; Misses counts lookups that found
// no live entry, Size counts expired entries until removed or swept.
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
		EntryCap:  s.entryCap,
	}
}

func (s *Store) shardFor(fullKey string) *shard {
	h := fnv.New32a()
	h.Write([]byte(fullKey))
	return &s.shards[h.Sum32()%uint32(len(s.shards))]
}

// evictLocked drops least-recently-used entries until the shard is within its
// budget and returns them for the caller to log and count after unlocking.
func (s *Store) evictLocked(sh *shard) []*entry {
	var evicted []*entry
	for sh.l.Len() > s.perShard {
		el := sh.l.Back()
		e := el.Value.(*entry)
		sh.remove(el)
		evicted = append(evicted, e)
	}
	return evicted
}

// evictionAttrs renders an eviction's identity per the domain's key convention:
// tracker keys decode to the true Target (plus path), the filesize namespace logs its path.
func evictionAttrs(ev *zerolog.Event, ent *entry) *zerolog.Event {
	if ent.ns == bandage.FilesizeNamespace {
		return ev.Str("namespace", ent.ns).Str("path", ent.key)
	}
	target, path := bandage.SplitTrackerKey(ent.key)
	ev = ev.Str("namespace", ent.ns).Str("target", target)
	if path != "" {
		ev = ev.Str("path", path)
	}
	return ev
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
