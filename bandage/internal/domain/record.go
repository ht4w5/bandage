package domain

// Record is leaky-bucket state for one key (flux's CacheEntry): value
// accumulates per event and decays by leak*dt floored at zero.
type Record struct {
	// Value is the amount accumulated since the last decay.
	Value float64
	// LastUpdate is the unix seconds of the last contributing event.
	// Zero means no event has contributed yet.
	LastUpdate int64
}

// Accumulate applies the leaky-bucket math for one event at eventTime
// (unix seconds); dt <= 0 increments without decay or LastUpdate change.
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
		// Flux order: increment, then decay.
		if decayed := r.Value - leak*float64(dt); decayed > 0 {
			r.Value = decayed
		} else {
			r.Value = 0
		}
		r.LastUpdate = eventTime
	}
}

// Overflow reports whether the record's value is strictly above volume
// (checked after decay).
func (r Record) Overflow(volume float64) bool {
	return r.Value > volume
}
