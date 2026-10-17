// Package memory is the in-memory tracker cache adapter: a sharded map
// with per-key atomic updates and sliding TTL expiry. Bounded eviction is
// the bounded-tracker-cache ticket's job.
package memory

import (
	"context"
	"errors"
	"hash/fnv"
	"sync"
	"time"

	"github.com/HT4w5/bandage/internal/domain/track"
)

const numShards = 256

// Store is an in-memory track.TrackerCache. It is safe for concurrent use.
type Store struct {
	shards [numShards]shard
	now    func() time.Time
}

type shard struct {
	mu sync.Mutex
	m  map[string]entry
}

type entry struct {
	rec track.Record
	// expires is the sliding expiry; zero means no expiry.
	expires time.Time
}

// New returns an empty store. now is the wall clock TTL expiry runs on.
func New(now func() time.Time) *Store {
	return &Store{now: now}
}

// Update atomically applies fn to the record for (ns, key) and returns it.
// Expired entries are treated as absent. fn runs under the shard lock and
// must not perform I/O or use ctx.
func (s *Store) Update(ctx context.Context, ns, key string, ttl time.Duration, fn func(*track.Record)) (track.Record, error) {
	if fn == nil {
		return track.Record{}, errors.New("memory: update fn must not be nil")
	}
	fullKey := ns + "\x00" + key
	h := fnv.New32a()
	h.Write([]byte(fullKey))
	sh := &s.shards[h.Sum32()%numShards]

	sh.mu.Lock()
	defer sh.mu.Unlock()

	if sh.m == nil {
		sh.m = make(map[string]entry)
	}
	e, ok := sh.m[fullKey]
	if ok && !e.expires.IsZero() && !s.now().Before(e.expires) {
		ok = false // expired: restart the bucket
	}
	if !ok {
		e = entry{}
	}
	fn(&e.rec)
	if ttl > 0 {
		e.expires = s.now().Add(ttl)
	} else {
		e.expires = time.Time{}
	}
	sh.m[fullKey] = e
	return e.rec, nil
}
