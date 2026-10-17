# Durable reports, volatile trackers

Report rows persist in sqlite; tracker (leaky-bucket) state is memory-only
and restart-cold. The asymmetry is deliberate: reports are the product
(operators query and delete them; they must survive restarts), while
tracker state is disposable — leaky buckets self-heal toward zero and
re-warm quickly. The `TrackerCache` port is the seam where a write-back
persistence layer can be added later without touching the trackers.

Consequences: a restart is a free pass for abusers (all buckets empty,
file-size EWMA re-warms after `minSamples` observations); accepted for v0.
