package bandage

// Record is leaky-bucket state for one key (flux's CacheEntry): the
// shared value type PLAN §5 defines for tracker state, living in the
// domain core so every domain module can speak it.
//
// The math is ported from flux (.reference/flux/pkg/engine/bucket.go):
// for each contributing event, value += increment; then, if the event is
// newer than the last contributing event (Δt > 0 in unix seconds), value
// decays by leak·Δt floored at zero and LastUpdate moves to the event time.
// Out-of-order or equal-time events (Δt ≤ 0) increment without decay and
// leave LastUpdate unchanged. Overflow is checked after decay and is
// strictly above volume.
type Record struct {
	// Value is the amount accumulated since the last decay.
	Value float64
	// LastUpdate is the unix seconds of the last contributing event.
	// Zero means no event has contributed yet.
	LastUpdate int64
}

// Accumulate applies the leaky-bucket math for one contributing event at
// eventTime (unix seconds) with the given increment and leak (per second).
// Whether the record overflows is read off the record with Overflow.
func (r *Record) Accumulate(increment, leak float64, eventTime int64) {
	if r.LastUpdate == 0 {
		// First event for this key: no decay.
		r.Value += increment
		r.LastUpdate = eventTime
		return
	}
	dt := eventTime - r.LastUpdate
	r.Value += increment
	if dt > 0 {
		// Flux order: increment first, then decay, then floor at zero.
		if decayed := r.Value - leak*float64(dt); decayed > 0 {
			r.Value = decayed
		} else {
			r.Value = 0
		}
		r.LastUpdate = eventTime
	}
}

// Overflow reports whether the record's value is strictly above volume.
// It is checked after decay, i.e. on the record as returned by the cache.
func (r Record) Overflow(volume float64) bool {
	return r.Value > volume
}
