# /stats is human-facing; metrics would be Prometheus

`GET /stats` serves cumulative-since-start counters (pipeline, tracker
cache) and build identity as indented JSON, for human eyes only: it is
unversioned and explicitly not a stable machine contract, unlike the
versioned report document. If machine-readable metric gathering is ever
needed, it arrives as a separate Prometheus-format endpoint; nothing
promises that `/stats`'s shape survives field additions.

Consequences: this deliberately amends spec story 35 ("`GET /ping` … and
nothing else exposed") — `/stats` is a read-only ops endpoint on the same
unauthenticated listener as `/reports`. Scrapers built on it are
unsupported by design.
