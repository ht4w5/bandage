# bandage — plan

A programmable **realtime** web log analyzer, written in Go (module
`github.com/HT4w5/bandage`), that consumes access logs over syslog as they
arrive, evaluates operator-defined rule chains, and stores **reports** in a
persistence repository served as JSON over HTTP.

All formats are **version 0** while the design settles (rules file
`version: 0`, report document `"version": 0`). No URL versioning.

Reference DNA:

| Source | What we take |
|---|---|
| **flux** | Chain-shaped YAML rules (chains → rules → match → action, with `goto`/`jump`/`stop` control flow); explicit leaky-**tracker** config (`leak`, `volume`); bucket math and overflow semantics; realtime pipeline (syslog → parser → workers); nginx JSON log format and parser |
| **webjail** | Domain-driven design (`internal/domain` + one subpackage per concern, tiny `Update(ctx, key, fn)` ports, derived `Event` fields); the **filter expression language** (`src 10.0.0.0/8 and path prefix "/api"`) including `Parse`/`ParseError{Line,Col}` style; the **file size enrichment** (per-path EWMA + `minSamples` gate → `event.SizeBytes`); the **ubiquitous language** (`Event`, `Filter`, `Enrich`, `Track`/tracker, `Evaluation`, `leak`, `volume`) |
| **A batch log analyzer** (YAML rules compiled to trusted SQL over a log warehouse, one-shot runs) | Rule `id` + `reason` provenance on findings. The YAML and JSON formats are **not** borrowed from it. |

## 1. DSL: flux chains + webjail filter syntax + explicit trackers

Rules are YAML chains like flux; filters use webjail's expression syntax;
a tracker (leaky bucket) is an explicit config block with flux's
`BYTE-BUCKET` / `FREQ-BUCKET` / `FILE-RATIO-BUCKET` semantics. A **tracker
is a condition**, not an action: a rule matches an event when its **filter
matches and its tracker overflows**; its actions then run.

**v0 constraint: at most one tracker per rule.** The report's singular
`tracker` field mirrors this. Compound multi-tracker AND-matching (flux's
semantics when a rule has several bucket expressions) is the natural
extension if real rules need it.

```yaml
version: 0

chains:
  - name: ingress
    rules:
      - id: skip-internal
        filter: 'src 10.0.0.0/8 or src 127.0.0.0/8'
        actions:
          - stop

  - name: download-abuse
    rules:
      - id: sustained-iso-egress
        filter: 'path suffix ".iso" and status 200'
        tracker:
          track: bandwidth
          leak: 1MB
          volume: 100GB
          target_prefix: {ipv4: 32, ipv6: 64}
        actions:
          - report:
              reason: iso-egress-overflow
              ttl: 7d

      - id: iso-replay
        filter: 'path suffix ".iso"'
        tracker:
          track: replay
          leak: 0.1
          target_prefix: {ipv4: 32, ipv6: 64}
          volume:
            method: clamped-linear   # constant | clamped-linear | inverse-square | step
            intercept: 5
            slope: -1
            min: 2
            max: 5
        actions:
          - report:
              reason: iso-replay-overflow
              ttl: 24h

  - name: routing
    rules:
      - id: route-downloads
        filter: 'path prefix "/releases"'
        actions:
          - jump: download-abuse
```

### Rule anatomy

- `id` — unique rule ID; also namespaces the rule's tracker state.
- `filter` — webjail expression, default `any`. **v0 primitive set (webjail's,
  unchanged):** `any`, `none`, `src (addr|prefix)`, `method word`,
  `path [prefix|suffix|keyword] string`, `agent [keyword] string`,
  `status (number | class number)`, `sent (>= | <=) size`, combined with
  `and` / `or` / `not` and parentheses. No regex, no host/duration filters
  in v0.
- `tracker` — optional single leaky-bucket tracker, explicit config:
  - `track`: `rate` | `bandwidth` | `replay` (webjail's tracker names;
    flux's `freq` | `byte` | `file-ratio` respectively)
  - `leak` / `volume`: human byte strings (`1MB`), rates (`10/s`, `1MB/s`),
    numbers. Volume methods (`constant`, `clamped-linear`, `inverse-square`,
    `step`) apply to `replay` only; `rate`/`bandwidth` use constant volume.
  - `target_prefix: {ipv4, ipv6}` — the tracker's target aggregation,
    declared per tracker (default `{32, 64}`; IPv6 never finer than /64).
    The target is the event's source address aggregated to this prefix;
    `replay` is keyed by `(target, path)` like webjail's ReplayTracker. No
    other target kinds in v0.
- `actions` — lowercase names; the full list always runs in order when the
  rule matches:
  - `report` — the **only write path** into the report table: upserts a
    report for the tracker's target. Requires `reason` (a slug matching
    `^[a-z0-9][a-z0-9_-]*$`; it populates the downstream ban rules and may
    be shared across rules — the rule ID is internal provenance) and `ttl`
    (expiry since the trigger; each `report` action sets its own). Rules
    carrying `report` must have a `tracker` — reports are always
    evidence-backed.
  - `log` — debug logging in flux's shape (`log: "debug,ROUTE:"`), logging
    the event and the rule's tracker reading at that point.
  - `goto` — run the target chain, then end this chain.
  - `jump` — run the target chain, then resume this chain.
  - `stop` — end traversal of this chain.
- **Terminality is per-rule**: if any of `report` / `goto` / `stop` is
  present, chain traversal ends after this rule (all its actions still run);
  other chains are still evaluated. The `goto`/`jump` graph must be
  **acyclic**, validated at rule build time; shared target chains are
  allowed (a DAG, not a forest).

Tracker semantics are flux's, unchanged: `value += inc`; on `Δt > 0`,
`value = max(0, value − leak·Δt)`; overflow when `value > volume`; in-memory
cache entries with TTL `volume/leak` (default 1h when leak is 0). `rate`
increments by 1, `bandwidth` by `sent`, `replay` by `min(sent/size, 1)` —
skipped when `event.SizeBytes` is `FilesizeUnknown`. Decay uses **event
time** (the log timestamp, flux parity); out-of-order events do not decay.
Rules without a tracker match on filter alone (flux `ALL` rule analogue)
and carry routing actions only — `report` requires a tracker.

## 2. Ingress event fields (v0)

Log format: one nginx JSON object per syslog message, using flux's log format
(`escape=json`, `$msec`/`$remote_addr`/`$request_method`/`$uri`/`$status`/
`$body_bytes_sent`/`$http_user_agent`…). The parser maps it onto webjail's
`Event` field names.

| JSON key | nginx variable | raw format | `Event` field | Go type | handling |
|---|---|---|---|---|---|
| `time` | `$msec` | string `"1734345934.123"` | `Time` | `time.Time` | Unix seconds + fraction, UTC; required |
| `client` | `$remote_addr` | IP literal | `RemoteAddr` | `netip.Addr` | required |
| `method` | `$request_method` | token | `Method` | `string` | required |
| `url` | `$uri` | string | `Path` | `string` | required |
| `status` | `$status` | number | `Status` | `int` | required, 100–599 |
| `sent` | `$body_bytes_sent` | number | `SentBytes` | `int64` | required, ≥ 0 |
| `agent` | `$http_user_agent` | string | `Agent` | `string` | optional, `""` when absent |
| — | — | — | `SizeBytes` | `int64` | derived (enrichment), `FilesizeUnknown` = 0 until warm |

- Reserved for later versions, accepted but ignored in v0: `host`
  (`$host`), `server` (`$server_addr`), `duration` (`$request_time`).
- Unknown JSON keys are ignored (log formats may carry extra fields).
- A malformed line or invalid required field drops the event; drops are
  counted and logged.

## 3. Domain model (webjail DDD, webjail language)

```
cmd/bandage/                run(args) seam: pflag CLI with shorthands
                            (-c config, -r rules, -t test, -l log level,
                            -w workers, -v version, -h help)
internal/domain/            package bandage: Event (§2), Report, Rule/Chain
                            value types
internal/domain/filter/     webjail filter language: Parse, Filter.Match(*Event),
                            ParseError{Line, Col} — ported as-is
internal/domain/enrichment/ FilesizeEnricher (EWMA, minSamples) + FilesizeCache
                            port — ported from webjail
internal/domain/track/      RateTracker, BandwidthTracker, ReplayTracker
                            (flux bucket math + replay volume methods) +
                            TrackerCache port
internal/domain/evaluation/ EvaluationService: prefilter → tracker update →
                            match (filter ∧ overflow) → action dispatch
internal/domain/report/     ReportService + ReportRepository port (persistence)
internal/app/               pipeline wiring, worker pool (flux engine style)
internal/identity/          build identity: linker-injected version, commit,
                            build date, dirty flag (-v output, startup log
                            record, --test plan header)
internal/adapters/          ingest drivers (v0: syslog) + parsers (v0: nginx
                            JSON, ported from flux); db drivers (v0: sqlite
                            report repository); in-memory tracker cache
                            (sharded, TTL + LRU); HTTP API (net/http)
configs/                    bandage.yml + rules.yml examples
```

House rules (webjail): ports are tiny interfaces declared beside their
consumer; `Update(ctx, key, fn)` callbacks run under a per-key lock and never
do I/O; `internal/domain*` depends on stdlib + `internal/domain` only.
Derived fields live on `Event` (`SizeBytes`).

### bandage.yml sketch

Driver-keyed blocks so other ingest sources and stores can be added without
format churn; sweep interval is an internal constant (not configurable).

```yaml
ingest:
  driver: syslog               # driver-keyed; more drivers later
  syslog:
    network: unixgram          # tcp | udp | unixgram
    listen: /run/bandage/log.sock
  parser: nginx                # nginx JSON (flux log format)

db:
  driver: sqlite               # driver-keyed; more stores later
  sqlite:
    path: /var/lib/bandage/reports.db

cache:
  max_entries: 65536           # total LRU cap across shards (default 65536)

api:
  listen: 127.0.0.1:8080
```

## 4. Pipeline

1. **Ingest** — ingest driver (v0: syslog over tcp/udp/unixgram) → raw
   messages.
2. **Parse** — parser driver (v0: nginx-JSON, ported from flux) →
   `domain.Event` per §2.
3. **Enrich** — `FilesizeEnricher` sets `event.SizeBytes` (per-path EWMA,
   warm-up gated by `minSamples`); `replay` trackers read it.
4. **Evaluate** — per event: traverse chains in order; a rule updates its
   tracker (only when its filter matches), checks overflow, and on match runs
   its actions.
5. **Report** — the `report` action upserts through the `ReportRepository`
   (keyed by (rule, target)): insert or overwrite the record with the current
   tracker reading and sample. Report time is **wall clock**: `created_at`
   is set once on insert; `updated_at` and `expires_at = now + ttl` are
   recomputed unconditionally on every trigger. This is the **only writer**
   to the table.
6. **Expire** — a periodic sweeper (internal cadence) deletes rows whose
   `expires_at` has passed; `GET /reports` also excludes expired rows as a
   safety net.
7. **Serve** — HTTP **only reads** reports from the repository on request
   (plus explicit deletion, §7). No on-demand compilation from live tracker
   state.

## 5. Tracker cache (in-memory, v0)

Tracker and enrichment state lives **entirely in memory**. A restart resets
buckets and file-size EWMA — accepted for v0 in exchange for simplicity.
The `TrackerCache` port below is the seam where a write-back persistence
layer can slot in later (hybrid memory + disk: dirty-set flush to the
reports sqlite DB, read-through on miss).

### Port (`Record` is a core value type in `internal/domain`; the tiny
### `TrackerCache` interfaces are declared beside each consumer —
### `internal/domain/track`, `internal/domain/evaluation` — and satisfied
### structurally by the store)

```go
// Record is leaked-bucket state for one key (flux's CacheEntry).
// Value is fractional to hold replay's transferred-fraction increments.
type Record struct {
    Value      float64 // accumulated since last decay
    LastUpdate int64   // unix seconds of the last contributing event
}

// TrackerCache stores records keyed by (ns, key); ns is the rule ID.
//
// Update atomically applies fn to the record for (ns, key) (a zero-valued
// record if none exists) and returns it afterwards. fn runs under the
// store's shard lock, so it must not perform I/O or use ctx.
type TrackerCache interface {
    Update(ctx context.Context, ns, key string, ttl time.Duration, fn func(*Record)) (Record, error)
}
```

`internal/domain/enrichment.FilesizeCache` keeps webjail's shape
(`Update(ctx, path, fn)`) and is served by the same store (ns `filesize`,
no TTL). TTL is flux's `volume/leak`, passed by the tracker on each update
(0 = no expiry).

### Store (v0: in-memory)

- **Sharded map** — per-shard mutex, `map[string]entry` (record +
  expiry); `Update` hashes the key to a shard and runs `fn` under the lock
  (`fn` stays O(1), no I/O — webjail's contract).
- **TTL** — flux's `volume/leak`, passed per update (0 = no expiry, e.g.
  the `filesize` namespace; a positive `volume/leak` clamps to a 1s
  minimum so it always yields a real expiry); enforced lazily on access
  plus a periodic sweep with an internal cadence.
- **Memory bound** — `cache.max_entries` (default 65536) across all
  shards/namespaces, enforced by per-shard LRU under pressure (flux's ccache
  `MaxSize` precedent, hand-rolled to keep deps small). Dropping an entry
  resets that key's bucket, so **every capped drop is logged** (ns, key)
  and counted in stats.
- **Statistics** — gets/sets/misses/evictions and current size, logged
  periodically via slog (flux's `Statistics` precedent; no debug
  endpoints).

### Consequence of no persistence

- A restart is a free pass for abusers: all buckets start empty, and every
  path's file-size EWMA re-warms after `minSamples` observations (`replay`
  trackers are blind until then). Reports are unaffected — they live in
  sqlite.

## 6. Reports

### Repository port (declared in `internal/domain/report`)

```go
type Repository interface {
    Upsert(ctx context.Context, rec Report) error
    List(ctx context.Context, q Query) ([]Report, error)
    Delete(ctx context.Context, q Query) (int, error)
    DeleteExpired(ctx context.Context, now time.Time) (int, error)
}
```

`Query` filters by rule and/or target. Only `report` actions write
(`Upsert`); the API reads (`List`) and deletes (`Delete`); the sweeper calls
`DeleteExpired`. sqlite adapter in `internal/adapters` (persistence survives
restarts; tracker state does not — that is accepted). Schema: one row per
(rule, target) with indexed columns `rule`, `target`, `expires_at` and a JSON
column for the record body.

### Report record

The record is deliberately small: provenance, expiry, the tracker reading
that justified it, and the triggering sample. No history counters.

```json
{
  "version": 0,
  "generated_at": "2025-10-17T18:30:00Z",
  "reports": [
    {
      "rule": "sustained-iso-egress",
      "chain": "download-abuse",
      "reason": "iso-egress-overflow",
      "target": "203.0.113.0/24",
      "created_at": "2025-10-17T10:02:11Z",
      "updated_at": "2025-10-17T18:29:40Z",
      "expires_at": "2025-10-24T18:29:40Z",
      "tracker": {
        "track": "bandwidth",
        "value": 102400000,
        "leak": 1000000,
        "volume": 100000000
      },
      "sample": {
        "time": "2025-10-17T18:29:40Z",
        "path": "/releases/24.04.iso",
        "agent": "Wget/1.21",
        "status": 200,
        "sent": 123456,
        "size": 1234567890
      }
    }
  ]
}
```

One entry per (rule, target). `tracker` and `sample` are the snapshot from
the last trigger; timestamps RFC 3339 UTC. `created_at` is fixed at the
trigger that created the row; `updated_at` and `expires_at` (`now + ttl`,
recomputed regardless of any previous value) reflect the latest trigger.
Reports are sorted by `created_at` descending.

## 7. HTTP API

- `GET /reports` — the report list (§6), read-only. Query params:
  `?rule=`, `?target=`. Expired rows are never returned.
- `DELETE /reports` — explicit deletion; requires `?rule=` and/or `?target=`
  (no accidental delete-all); returns the number of deleted rows. This is
  *dismiss*, not *silence*: tracker state is untouched, so a report whose
  condition persists returns on the next trigger.
- `GET /ping` — liveness.

No `/v1` prefix, no debug endpoints. The API never writes reports; only
`report` actions do.

## 8. Validation & tooling

- Strict config decode: unknown keys and invalid values rejected before any
  socket opens (`cache.max_entries` must be positive).
- Load-time rule validation: more than one tracker per rule, unknown
  `track`/volume methods, volume methods on non-replay trackers, unparseable
  filters (with `ParseError` line/col), dangling `goto`/`jump` targets,
  cyclic `goto`/`jump` graphs (the chain graph must be acyclic), duplicate
  rule IDs, `report` actions missing `reason`/`ttl`, `reason` not a slug
  (`^[a-z0-9][a-z0-9_-]*$`), non-positive `ttl`, `report` on a tracker-less
  rule, out-of-range `target_prefix` (ipv4 ≤ 32, ipv6 ≤ 64).
- No hot reload in v0: config and rules changes take effect on restart.
- `bandage -t` (`--test`) prints the validated chain plan, headed by the
  build identity header, and exits without ingesting. Command-line
  overrides follow flag > config > default precedence (`-l` log level,
  `-w` workers); an unknown flag prints the error plus usage and exits 2.

## 9. Milestones

- **M0** — Skeleton: domain types, strict config load, flags, `--test` stub.
- **M1** — Filter port + rule validation + chain/action model; golden tests
  over `configs/rules.yml`.
- **M2** — Realtime core: syslog ingest + nginx parser (ported from flux),
  `FilesizeEnricher` (ported tests from webjail), trackers with flux bucket
  math (ported tests from flux `testdata/bucket.yaml`), evaluation service,
  in-memory store behind the `TrackerCache` port.
- **M3** — ReportService + sqlite repository + `GET /reports`,
  `DELETE /reports`, `GET /ping`.
- **M4** — Hardening: worker pool, backpressure, tracker cache eviction,
  drop counters, replay-based integration tests, docs.

## 10. Open items

None — v0 scope is closed. Decided along the way: `cache.max_entries` is
configurable (default 65536) with capped drops logged; restart-cold tracker
and file-size state is accepted for v0.
