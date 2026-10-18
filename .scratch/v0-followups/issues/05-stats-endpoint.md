# 05: Human-facing /stats with eviction counters

**What to build:** An operator can see the daemon's build identity and health in one read. `GET /stats` on the existing listener answers indented JSON with a generation timestamp, uptime, the build block (name, version, commit, build date, dirty, Go version, platform), the pipeline block (worker count, received, parsed, dropped) and the tracker cache block (gets, sets, misses, evictions, size, entry cap) — cumulative since start. It is explicitly human-facing and unversioned (per ADR 0006), the periodic statistics log keeps flowing, and everything an operator reads says *eviction*, matching the counter and the glossary.

**Blocked by:** 02 — Build identity and the pflag command line; 04 — Worker pool and daemon lifetime context

**Status:** resolved

- [x] `GET /stats` returns 200 with indented JSON carrying the generation timestamp, uptime, build block, pipeline block (worker count, received, parsed, dropped) and tracker cache block (gets, sets, misses, evictions, size, entry cap)
- [x] Counters are cumulative since start and agree with the periodic statistics log line (same drop accounting and cache statistics)
- [x] The document carries no format version, and the docs state it is human-facing and not a stable machine contract; metric gathering would be a separate Prometheus-format endpoint
- [x] The periodic statistics log line keeps its cadence and fields
- [x] Log messages, comments, tests and design docs say *eviction* — matching the glossary term and the counter — with "capped drop" surviving only in the glossary's avoid list
- [x] The API docs explain deletion plainly: deleting reports does not touch tracker state, so a Target that still overflows is reported again on the next trigger
- [x] The report API is unchanged (list with filters, delete by filter, ping); `/stats` is asserted at the HTTP seam without pinning its exact field-by-field shape

## Answer

Implemented on integration branch `feat/v0-followups` (merge commit
`d84908d`; cross-ticket code-review fixes through `a69fb58`).
`GET /stats` serves indented JSON (generation timestamp, uptime, build,
pipeline and tracker cache blocks) from `httpapi.StatsSource`, satisfied
structurally by `Daemon.Stats()`; the periodic statistics log renders
from the same snapshot; no format version; deletion semantics documented
plainly; the report API is untouched.

Context: spec `../spec.md`, `../../docs/adr/0006-human-facing-stats-prometheus-for-metrics.md`.

Notes:
- Uptime renders as a rounded Go duration string; `EntryCap` reports the
  configured `cache.max_entries`.
- Eviction records carry the namespace and its key: `target` for tracker
  entries, `path` for the path-keyed filesize namespace (story 28
  adjudicated — `path` is the honest field name there).
