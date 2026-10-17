# 05: Human-facing /stats with eviction counters

**What to build:** An operator can see the daemon's build identity and health in one read. `GET /stats` on the existing listener answers indented JSON with a generation timestamp, uptime, the build block (name, version, commit, build date, dirty, Go version, platform), the pipeline block (worker count, received, parsed, dropped) and the tracker cache block (gets, sets, misses, evictions, size, entry cap) — cumulative since start. It is explicitly human-facing and unversioned (per ADR 0006), the periodic statistics log keeps flowing, and everything an operator reads says *eviction*, matching the counter and the glossary.

**Blocked by:** 02 — Build identity and the pflag command line; 04 — Worker pool and daemon lifetime context

**Status:** ready-for-agent

- [ ] `GET /stats` returns 200 with indented JSON carrying the generation timestamp, uptime, build block, pipeline block (worker count, received, parsed, dropped) and tracker cache block (gets, sets, misses, evictions, size, entry cap)
- [ ] Counters are cumulative since start and agree with the periodic statistics log line (same drop accounting and cache statistics)
- [ ] The document carries no format version, and the docs state it is human-facing and not a stable machine contract; metric gathering would be a separate Prometheus-format endpoint
- [ ] The periodic statistics log line keeps its cadence and fields
- [ ] Log messages, comments, tests and design docs say *eviction* — matching the glossary term and the counter — with "capped drop" surviving only in the glossary's avoid list
- [ ] The API docs explain deletion plainly: deleting reports does not touch tracker state, so a Target that still overflows is reported again on the next trigger
- [ ] The report API is unchanged (list with filters, delete by filter, ping); `/stats` is asserted at the HTTP seam without pinning its exact field-by-field shape
