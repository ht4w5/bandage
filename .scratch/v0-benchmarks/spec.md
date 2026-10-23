# Spec: v0 benchmarks — measure the hot paths, identify the bottlenecks

Status: ready-for-agent

## Problem Statement

bandage is a realtime pipeline: every access-log line goes through ingest,
parsing, enrichment, evaluation and (on match) report persistence
(`internal/app/daemon.go` `runPipeline`). We have no performance numbers —
no benchmarks, no profiles, no throughput baseline — yet the service is
expected to keep up with busy web servers and its per-line path contains
several plausible costs: JSON parsing into a generic map, string-built cache
keys, per-call hashing and allocation in the tracker cache, a globally
serialized per-line progress counter, and single-connection sqlite upserts.
Without measurements we cannot say which of these actually matters, at what
traffic level the daemon falls behind, or whether a future change regressed
throughput.

## Solution

A measurement-only effort: build a reproducible benchmark suite over the
hot paths, run end-to-end throughput and worker-scaling experiments,
attribute cost with pprof profiles, and record the findings as a ranked
bottleneck list with evidence. **No optimizations in this effort** — the
output is numbers and a diagnosis; fixes become separate follow-up issues
written from the findings.

## Hot-path inventory (what gets benchmarked)

Per raw line, in order (`daemon.go` `runPipeline`, N workers):

1. **Ingest** — `internal/infra/ingest/syslog`: one forwarding worker over
   go-syslog, `parts` buffered at 256, forwarding onto `d.lines`
   (unbuffered `chan string`).
2. **Parse** — `internal/infra/parse/nginx` `Parser.Parse`:
   `json.Unmarshal` into `map[string]json.RawMessage`, then per-field
   re-parsing (time, IP, method, path, status, sent, agent).
3. **Enrich** — `internal/bandage/enrichment` `FilesizeEnricher.Enrich` →
   `internal/infra/cache/memory` `Store.Update` (shared tracker store,
   filesize namespace): key concat, `fnv.New32a()` hashing, shard mutex,
   LRU list ops.
4. **Evaluate** — `internal/bandage/evaluation` `Service.Evaluate`: every
   rule of every chain runs `Filter.Match` (interface tree over
   `internal/bandage/filter`), then for filter-matching rules with a
   tracker, `TargetString` + `TrackerKey` string building and another
   `Store.Update` (leaky-bucket `Record.Accumulate` under the shard lock).
5. **Report write (on match)** — `internal/bandage/report` `Trigger` →
   `internal/infra/persistence/sqlite` `Upsert`: explicit transaction
   (SELECT created_at + upsert) + JSON body marshal, on a single
   connection (`SetMaxOpenConns(1)`, ADR 0007).
6. **Per-line bookkeeping** — `d.received`/`d.parsed`/`d.dropped` atomics
   and `progress.bump()`: a global mutex plus `close(ch)`/`make(chan)` per
   processed line, across all workers.
7. **Read path (secondary)** — `internal/infra/httpapi` `GET /reports`
   (JSON body decode per row) and the minute cadence of `SweepExpired` /
   `DeleteExpired` / `Statistics()`.

## Hypotheses to confirm or refute (ranked by expected cost)

- **H1 — Parser allocation dominates.** The generic
  `map[string]json.RawMessage` unmarshal plus per-field re-parsing
  allocates several objects per line; GC pressure caps throughput.
- **H2 — `progress.bump()` serializes workers.** One mutex + one channel
  allocation/close per line is a global critical section; worker scaling
  flattens because of it.
- **H3 — `memory.Store.Update` per-call overhead and hot-key contention.**
  `fullKey := ns + "\x00" + key` and `fnv.New32a()` allocate per update;
  hot targets collide in one shard and serialize on its mutex.
- **H4 — sqlite report upserts serialize the match path.** One connection,
  one transaction per trigger; when rules fire often, workers block on the
  write.
- **H5 — Unbuffered `lines` channel couples ingest to workers.** Per-line
  handoff wakeups; ingest becomes the ceiling before the pipeline does.
- **H6 — O(rules) filter evaluation per event.** Interface dispatch and
   string/CIDR leaf ops per rule per event; cost grows linearly with rule
   count.

## Benchmark design

### Phase 0 — Harness and fixtures

- Deterministic nginx-JSON line corpus as `testing` fixtures: line shapes
  (minimal required fields vs. full line with agent/host/server) and key
  distributions (uniform; Zipfian paths and client IPs to model hot
  targets; a hot-path/hot-IP pair to force single-shard contention).
- Shared bench helpers in `_test.go` beside each package; benchmarks use
  `testing.B.Loop()`, report `b.ReportMetric` lines/sec where meaningful,
  and run with `-benchmem`.
- `make bench` (whole suite) and `make bench-pkg PKG=...` targets; runs
  documented with `-count=10` + benchstat for comparisons.

### Phase 1 — Component microbenchmarks

| Benchmark | Package | Measures |
|---|---|---|
| `BenchmarkParse` | `infra/parse/nginx` | ns/op, B/op, allocs/op per line shape (H1) |
| `BenchmarkFilterMatch` | `domain/filter` | leaf filters and realistic chains of 1/10/100 rules, match and no-match (H6) |
| `BenchmarkStoreUpdate`, `BenchmarkStoreUpdateParallel` | `infra/cache/memory` | sequential and `RunParallel`; uniform vs Zipfian vs hot-key (H3) |
| `BenchmarkEvaluate` | `domain/evaluation` | full chain evaluation over pre-parsed events: memory store + in-memory sink (isolates domain path) and sqlite sink (H4, H6) |
| `BenchmarkReportUpsert` | `infra/persistence/sqlite` | insert vs update-over-existing, `:memory:` vs file (H4) |
| `BenchmarkReportsList` | `infra/httpapi` | read path at 10/1k/10k rows |
| `BenchmarkProgressBump` (parallel) | `app` | per-line bookkeeping contention alone (H2) |

### Phase 2 — Pipeline throughput and scaling

- In-package end-to-end harness driving the real `runPipeline` chain with
  a pre-generated corpus (no network): sustained lines/sec at
  `pipeline.workers` = 1/2/4/8, with the store sized to avoid evictions
  and with a deliberately evicting run as a second scenario.
- Ingest-inclusive variant over a real loopback syslog socket (tcp and
  unixgram) to capture go-syslog + channel handoff cost (H5).
- Report-trigger scenario: rules that fire on every event vs. rules that
  never fire, isolating the match/write path (H4).
- Record alongside throughput: allocs/op, GC fraction
  (`runtime/memstats` / `-benchmem`), and the daemon's own `/stats`
  counters as a sanity cross-check.

### Phase 3 — Profiling and attribution

- `-cpuprofile`, `-memprofile`, `-mutexprofile`, `-blockprofile` on the
  pipeline benchmark (Go 1.27 toolchain); top-frame attribution against
  H1–H6.
- Worker-scaling curve with per-stage attribution: where does the curve
  flatten, and which profile frames explain the flatten point?
- Method hygiene: benchstat with `-count=10`, fixed `GOMAXPROCS` noted,
  quiet machine, Go version recorded.

### Phase 4 — Findings

`findings.md` in this directory:

- Ranked bottleneck table: measured cost per stage (ns/op, B/op,
  allocs/op, % of pipeline time), scaled to "lines/sec/core".
- Verdict per hypothesis (confirmed / refuted / partial) with profile
  evidence.
- Recommended fixes as follow-up issues (this tracker or `v0-followups`),
  ordered by measured impact — created only from evidence.
- Committed baseline (benchstat output) for future regression comparison.

## Success Criteria

1. Every stage in the hot-path inventory has a benchmark with ns/op,
   B/op and allocs/op recorded.
2. A worker-scaling curve (1/2/4/8) exists for the end-to-end pipeline,
   with the saturation point named and backed by profile evidence.
3. `findings.md` ranks the bottlenecks with numbers and gives each
   hypothesis a verdict; baselines are committed.

## Out of Scope

- Implementing any optimization (follow-up issues only).
- Prometheus metrics (ADR 0006) and any new config surface.
- Changing rule, filter or tracker semantics.
