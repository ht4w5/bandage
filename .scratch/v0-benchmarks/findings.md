# Findings — profiling, attribution and bottleneck report (spec Phases 3–4)

Measurement-only output of ticket 04. No production code changed; every
recommended fix is a follow-up issue (§ "Recommended fixes"). Evidence
base: the committed benchmark baseline (tickets 01–03 harnesses) and
the pprof profiles collected here (extracts committed under
`profiles/`).

## Method and environment

- **Machine**: Intel Core Ultra 9 185H, 22 logical CPUs (16 cores / 2
  threads per core), Linux 7.2.10-200.fc44.x86_64. Single machine, idle
  but not load-isolated.
- **Toolchain**: go1.27.0 linux/amd64. benchstat
  (golang.org/x/perf v0.0.0-20261009192801).
- **GOMAXPROCS=22** pinned explicitly via the environment for every run
  (matches Go's container-aware default on this box; pinned so the
  value cannot drift with the machine's cgroup limits).
- **Baseline** (benchstat hygiene, `-count=10`):
  `GOMAXPROCS=22 go test -run=^$ -bench=. -benchmem -count=10 -p=1 ./...`
  — default benchtime (1s), packages serial (`-p=1`) so package test
  binaries never contend. Raw output: `baseline/bench-count10.txt`
  (regenerated wholesale after the v0-hot-path semantics — see
  § "Baseline for future regression comparison"); benchstat summary of
  the same run: `baseline/benchstat.txt`. All "±" below are benchstat's
  spread over the 10 runs.
- **Profiles** (one benchmark selected per run with anchored `-bench`
  patterns, `./internal/app`):
  - CPU + mem (low overhead): `-benchtime=5s -cpuprofile cpu.out
    -memprofile mem.out`.
  - mutex + block (separate runs, full-rate instrumentation distorts
    absolute timing — used for shares and delays only):
    `-benchtime=2s -mutexprofile -mutexprofilefraction=1 -blockprofile
    -blockprofilerate=1`.
  - Selections: `Pipeline/match-never/workers=1` (mn1),
    `Pipeline/match-never/workers=8` (mn8), `Pipeline/match-every/
    workers=1` (me1), `Pipeline/match-every/workers=8` (me8),
    `PipelineIngest/tcp/match-never/workers=8` (tcpmn8).
- **Interpretation rule**: profiles include benchmark calibration
  phases and instrumentation overhead, so verdicts quote profile
  **shares** ("x% of pipeline CPU") and benchstat **absolutes**
  (ns/op, B/op, allocs/op) side by side, never per-op absolutes from a
  profile.
- **Code-review pass**: the recorded numbers were refreshed where the
  review pass changed a benchmark's name, semantics or results — the
  `match-every`/`match-never` evaluate fixtures (renamed from
  `fires`/`never-fires`, GLOSSARY: Match/Trigger), the throughput
  harness (its timed region now includes the final drain, so lines/s
  never counts lines processed after the timer stopped — previously
  up-to-1024 socket-buffered tail lines), and the GC metric
  (`gc-cpu-frac` replaces `gc-pause-frac`: the GC's share of total CPU
  capacity from `runtime/metrics` `/cpu/classes` deltas, marking,
  assist and scavenge included — a genuine in-process GC CPU share was
  measurable, so the STW-pause-only substitution was dropped).
  Benchmarks whose names, semantics and results were untouched
  (Parse, FilterMatch, StoreUpdate, ReportUpsert, ReportsList,
  ProgressBump) keep their original recorded values.

## Benchmark coverage map (spec → implementation)

Explicit spec → benchmark mapping (code-review pass). (The v0-hot-path
round re-modeled the evaluate and throughput scenarios and added the
`writes/op` metric — see § "Addendum — v0-hot-path" for the old → new
name mapping.) The domain
import lint (`internal/bandage/deps_test.go`: domain modules import
only the domain core and stdlib) forces the domain/app split marked
below: the in-domain variants run over stub ports, the real
store/sink variants live in `internal/app`.

| spec Phase 1 row | actual benchmark (package) | notes |
|---|---|---|
| `BenchmarkParse` | `BenchmarkParse/{minimal,full}` (`internal/infra/parse/nginx`) | one per line shape |
| `BenchmarkFilterMatch` | `BenchmarkFilterMatch/leaf/…`, `/chain/{1,10,100}-rules/{match,no-match}` (`internal/bandage/filter`) | zero-alloc leaves and chains |
| `BenchmarkStoreUpdate`, `BenchmarkStoreUpdateParallel` | same names (`internal/infra/cache/memory`) | `{uniform,zipf,hot,evicting}` key distributions |
| `BenchmarkEvaluate` | **lint split**: `BenchmarkEvaluate/{match-every,match-never}` (`internal/bandage/evaluation`, stub TrackerCache/ReportSink ports) + `BenchmarkEvaluateMemory/…` (`internal/app`, real memory store + in-mem sink) + `BenchmarkEvaluateSQLite/…` (`internal/app`, real memory store + sqlite sink) | spec asked for memory-store and sqlite variants; the lint bars those adapters from the domain package |
| `BenchmarkReportUpsert` | `BenchmarkReportUpsert/{memory,file}/{insert,update}` (`internal/infra/persistence/sqlite`) | |
| `BenchmarkReportsList` | `BenchmarkReportsList/{10-rows,1k-rows,10k-rows}` (`internal/infra/httpapi`) | read path |
| `BenchmarkProgressBump` | `BenchmarkProgressBump/{serial,parallel}` (`internal/app`) | |

Success criterion 1 asks per-stage coverage (hot-path inventory);
`BenchmarkPipeline*` covers the assembled chain, and the code-review
pass added the three stage benches that had no isolated benchmark
(numbers are single runs with `-benchmem`, ns/op · B/op · allocs/op —
the committed `-count=10` baseline carries them too):

| inventory stage | benchmark (package) | ns/op | B/op | allocs/op |
|---|---|---|---|---|
| 1 Ingest (Source run loop, no evaluation) | `BenchmarkIngestForward/{tcp,unixgram}` (`internal/infra/ingest/syslog`) | 1600 / 1847 | 3205 / 1909 | 17 / 14 |
| 2 Parse | `BenchmarkParse` (above) | 1,804 / 3,019 | 696 / 1.51Ki | 23 / 32 |
| 3 Enrich (FilesizeEnricher.Enrich) | **lint split**: `BenchmarkEnrich` (`internal/bandage/enrichment`, stub cache) + `BenchmarkEnrichMemory` (`internal/app`, real memory store); the store's own call is `BenchmarkStoreUpdate` | 74.8 / 180 | 168 / 200 | 3 / 4 |
| 4 Evaluate | `BenchmarkEvaluate{,Memory,SQLite}` (above) | 396–114,536 | — | — |
| 5 Report write (on match) | `BenchmarkReportUpsert` + `BenchmarkEvaluateSQLite/match-every` (above) | 31,370 (`:memory:`) | 2.73Ki | 53–54 |
| 6 Bookkeeping | `BenchmarkProgressBump` (above) | 48.4 / 107.5 | 112 | 1 |
| 7 Read path + sweep cadence | `BenchmarkReportsList` (above) + `BenchmarkStoreSweepExpired/{live,expiring}`, `BenchmarkStoreStatistics`, `BenchmarkReportDeleteExpired/{live,expiring}` (`internal/infra/cache/memory`, `internal/infra/persistence/sqlite`) | 2,453/2,751 (sweep), 1,950 (stats), 3,241/63,435 (delete) | 0 / 0 / 136 | 0 / 0 / 6 |

## Pipeline baselines (benchstat medians of 10)

lines/s, pipeline-only (no network in the path):

| scenario | workers=1 | workers=2 | workers=4 | workers=8 |
|---|---|---|---|---|
| match-every | 23.34k | 21.83k | 22.23k | 21.73k |
| match-never | 206.9k | 226.3k | 276.6k | 404.5k |
| match-never-evicting | 203.1k | 217.5k | 267.8k | 389.3k |

lines/s, ingest-inclusive (real loopback syslog socket):

| scenario | workers=1 | workers=2 | workers=4 | workers=8 |
|---|---|---|---|---|
| tcp/match-never | 150.9k | 176.7k | 214.8k | 224.5k |
| unixgram/match-never | 172.9k | 190.5k | 242.4k | 360.8k |
| tcp/match-every | 20.44k | 19.60k | 19.50k | 19.38k |

Per-line bookkeeping of the same runs: match-never 41 allocs/op,
2.14KiB/op; match-every 111–114 allocs/op, 5.75–5.92KiB/op;
gc-cpu-frac (the GC's share of total CPU capacity, runtime/metrics
`/cpu/classes` deltas) grows **1.9% → 6.0%** for match-never as
workers go 1 → 8 (match-every stays flat ~1.0%).

## Ranked bottlenecks

Ranked by measured per-line impact. `% of pipeline` is the CPU-profile
share of `runPipeline`'s cumulative samples (fast path =
`Pipeline/match-never/workers=1`, 4.833µs/line wall; write path =
`Pipeline/match-every/workers=1`, 42.84µs/line wall). `lines/sec/core`
is the single-core capacity of the stage: 1e9/ns/op for serial stages
and throughput ÷ workers for pipeline rows. Rows marked (kept) come
from benchmarks the code-review pass left untouched and keep their
ticket-04 values; renamed/new benchmarks are refreshed.

| # | Stage (hot-path inventory) | ns/op | B/op | allocs/op | % pipeline fast path | % pipeline write path | lines/sec/core |
|---|---|---|---|---|---|---|---|
| 1 | **Report write (on match)** — `sqlite.Upsert` incl. body marshal (kept) | 31,370 (`:memory:` insert) / 75,940 (file insert) | 2.73Ki | 53–54 | n/a (no writes) | **82%** (72% of *all* CPU samples) | 31.9k (`:memory:`) / 13.2k (file) |
| 2 | **Parse** — `nginx.Parser.Parse` (kept) | 3,019 (full) / 1,804 (minimal) | 1.51Ki / 696 | 32 / 23 | **83%** (70% of all samples) | 12–13% | 331k (full) / 555k (minimal) |
| 3 | **Ingest** (adds on top of everything; tcp) | ≈ +1,800 vs no-ingest (w1: 6.63µs vs 4.83µs); isolated Source forwarding 1.60µ (tcp) / 1.75µ (unixgram) | +2.7Ki (tcp) | +17 | n/a (no socket) | n/a | ceiling 224.5k (single scanner); isolated 625k/572k |
| 4 | **Evaluate** — chain + tracker update | 725 (match-never) / 1,485 (match-every; memory store + in-mem sink) | 461 / 1.01Ki | 13 / 25 | 5–6% | ~2% (excluding the write) | 1.38M / 673k |
| 5 | **Enrich** — `FilesizeEnricher.Enrich` + `Store.Update` | 192 (`BenchmarkEnrichMemory`, real store; 76.7 stub-cache domain variant) | 200 | 4 | 3.8–4.1% | ~1% | 5.2M |
| 6 | **Bookkeeping** — `progress.bump` (kept) | 48.4 serial / 107.5 parallel | 112 | 1 | 1.7–2.6% CPU, **25.5% of mutex contention** | same | 20.7M serial; 9.3M at 22 goroutines (0.42M/core) |
| — | Read path (secondary) — `GET /reports` (kept) | 78,840 (10 rows) / 7.05ms (1k) | 51Ki / 5.13Mi | 304 / 26.1k | off hot path | off hot path | ~7.2µs + 26 allocs per row |
| — | Sweep cadence (secondary) — `Store.SweepExpired` / `Store.Statistics` / `ReportRepository.DeleteExpired` | 2,453 / 1,915 / 3,221 (live); expiring variant 2,829 / — / 62,320 | 0 / 0 / 136 | 0 / 0 / 6 | off hot path | off hot path | minute cadence, ~7.6µs + 6 allocs per tick combined |

Filter evaluation (H6) is deliberately unranked: leaves cost 1–6ns
zero-alloc, chains ~12.5ns/rule (15.7ns @ 1 rule, 129.8ns @ 10, 1.247µs
@ 100) — real O(rules) growth, but below one percent of per-line time
at the benchmark's rule counts (see H6 verdict).

**GC pressure is cross-cutting, not a stage**: it is the tail of the
allocation columns above. gcBgMarkWorker is 6.3% of all CPU samples at
workers=1 and 8.2% at workers=8; gc-cpu-frac 1.9% → 6.0% with worker
count; the write path adds ~70 allocs and ~3.6KiB per line on top of
the fast path (sqlite/`database/sql`/JSON-marshal churn). Fixing
ranks 1, 2, 5 and 6 fixes the GC curve.

## Worker-scaling attribution (ticket 03's flatten points)

- **match-every saturates at workers = 1** (23.3k → 21.7k) — explained
  entirely by the single-connection sqlite upsert (H4). CPU profile
  (me8): `sqlite.Upsert` = 5.00s of runPipeline's 5.97s = **83.8% of
  pipeline CPU**. Block profile (me8, 2s instrumented run):
  `database/sql.(*DB).BeginTx → DB.conn` accounts for **16.07s of
  25.61s total blocking delay (62.7%)** ≈ 8 workers × 2s — i.e. the
  whole worker fleet spends essentially all its time queued on the one
  connection (`SetMaxOpenConns(1)`, ADR 0007). Workers never scale;
  they just queue.
- **match-never is sublinear (207k → 405k, 1.96× at 8 workers) and
  still rising** — the process only sustains ~3.4 busy cores at
  workers = 8 (`Total samples = 20.6s` over 6.03s wall). The workers'
  dominant block is waiting for input: `chanrecv2` on `d.lines`
  (`for line := range d.lines`) = 2.87s of 10.43s block delay vs 0.65s
  of feeder-send back-pressure — the single feeder + unbuffered
  handoff feeds 8 workers only so fast. GC degrades with scale
  (gc-cpu-frac 1.9% → 6.0%, gcBgMark 6.3% → 8.2%) and lock spinning
  becomes visible (`runtime.futex` 0.47s + `runtime.procyieldAsm`
  0.49s = 4.7% of samples at workers=8), but `progress.bump`'s mutex
  and the cache shards together are under 30% of the (small) mutex
  delay — the flatten shape is **feed handoff + GC**, not a lock.
- **tcp/match-never flattens at workers = 4** (215k → 225k) — the
  ingest path is a serial stage before the workers (H5). CPU profile
  (tcpmn8): go-syslog `Server.scan` (bufio.Scanner + rfc3164 parser +
  format.detect + Dump) = 21.5% of all samples, `Source.run` + line
  channel send ≈ 3.2%, versus 35% for the entire worker pipeline; one
  scanner goroutine per connection means ingest caps at ~225k lines/s
  while the same pipeline with no socket reaches 405k at workers = 8
  (−44% tcp, −11% unixgram).

## Hypothesis verdicts

### H1 — Parser allocation dominates — **CONFIRMED**

The generic `map[string]json.RawMessage` unmarshal plus per-field
re-parsing dominates the fast path and the allocation profile.

- CPU (mn1): `nginx.(*Parser).Parse` = 5.00s of runPipeline's 6.02s =
  **83% of pipeline CPU** (70% of all samples); `encoding/json.
  v2.Unmarshal` alone is 4.33s = **87% of Parse**, with the per-field
  re-parsing (`parseString` 1.03s, `parseTime` 0.54s) on top.
- Memory (mn1): the Parse subtree is **37.70M of 49.99M alloc objects
  (75.2%)**; `reflect.mapassign_faststr0` (generic map inserts) alone
  is **49% of the 2.8GB allocated**; `Value.UnmarshalJSON` 23.5%,
  `parseString` 19.2%, `parseTime` 13.2% of objects.
- Microbenchmarks: 23 allocs/696B (minimal) and 32 allocs/1.5KiB
  (full) per line — 2–3 lines/sec/core cheaper for the minimal shape.
- The predicted GC pressure is real: gc-cpu-frac 1.9% → 6.0% as
  workers scale, gcBgMarkWorker 6.3–8.2% of CPU.

Caveat: "dominates" holds on the fast path only. When rules match on
every event the write path (H4) reduces parse to 12–13% of per-line
CPU.

### H2 — `progress.bump()` serializes workers — **PARTIAL**

The cost is real, global and per-line, but it is **not the saturation
point** at today's throughputs.

- Microbenchmarks: 48.4ns + 112B + 1 alloc per line serial (20.7M
  lines/s alone); parallel throughput **falls** to 9.3M lines/s at 22
  goroutines (107.5ns) — below the serial rate, exactly the shape H2
  predicts for a global critical section.
- Mutex profile (mn8): `progress.bump` is the **largest single
  attributed site of contended-mutex delay — 138.87ms of 541.42ms
  (25.5%)**; its per-line `make(chan)`/`close` churn is 1.36M allocs
  (2.7% of objects) and 145MB (5.2% of allocated space).
- But the absolute critical section is ~50ns ⇒ a serialization ceiling
  near 20M lines/s, orders of magnitude above the observed 207–405k
  lines/s. The measured flatten is fed by the handoff/GC evidence in
  § Worker-scaling: workers idle on `d.lines` (2.87s block delay),
  GC CPU share grows with worker count, and bump's mutex waits are only
  130.65ms (1.25%) of block delay.

So: fix it (it is pure per-line waste and a cross-worker
serialization), but it does not explain ticket 03's curve.

### H3 — `memory.Store.Update` per-call overhead and hot-key contention — **PARTIAL**

Per-call overhead confirmed (and small); the hot-key contention claim
is refuted at pipeline scale.

- Per call: exactly **1 alloc of 32B** — the `ns + "\x00" + key` concat
  (`runtime.concatstrings` 3.5% + `concatstring2` 2.7% of mn1 CPU;
  `hash/fnv` 1.0%). Two calls per line (filesize + tracker) = 7.6% of
  alloc objects. ~59–79ns sequential per call.
- Contention: the microbench shows H3's shape — hot-key parallel update
  is **215ns vs 59ns serial (3.6×)**, zipf 98ns, uniform 83ns. But in
  the pipeline the mutex profile attributes only **3.87ms of 541.42ms
  (0.7%)** of contended-mutex delay to `Store.Update`, even though the
  DistZipf corpus sends ~16% of events to one tracker key: 256 shards
  absorb the rest. Forced eviction costs 0–4% throughput (173ns/call,
  3 allocs).
- Conclusion: the per-call overhead is minor bookkeeping (~140ns,
  2 allocs per line); single-shard collision would matter only for
  far hotter key distributions than this corpus produces.

### H4 — sqlite report upserts serialize the match path — **CONFIRMED (dominant)**

The single-connection upsert (ADR 0007) is ~7/8 of the match path and
its saturation ceiling.

- CPU: `sqlite.(*ReportRepository).Upsert` = **81.9% of pipeline CPU at
  workers=1** (me1, 4.94s of 6.03s) and **83.8% at workers=8** (me8);
  the report-body `json.Marshal` inside it is another 6.1–7.5%.
- Block profile (me8): `DB.BeginTx → DB.conn` = **62.7% of all blocking
  delay (16.07s ≈ 8 workers × 2s)** — the entire worker fleet queued
  on the single connection. Mutex profile adds `BeginTx`/`Tx.Commit`
  contention on top.
- Microbenchmarks: 31.4µs per upsert (`:memory:`), 75.9µs (file);
  sqlite-sink evaluation is 118.4µs/event when every rule matches vs
  749ns when none does (239 vs 13 allocs).
- Pipeline: the two scenarios differ only in leaky-bucket volume, yet
  match-every (42.84µs/line) costs **8.9× match-never (4.83µs/line)**
  and never scales (23.3k → 21.7k lines/s from 1 → 8 workers).

### H5 — Unbuffered `lines` channel couples ingest to workers — **PARTIAL**

The predicted effect ("ingest becomes the ceiling before the pipeline
does") is confirmed for tcp; the predicted mechanism (per-line handoff
wakeups) is a minor contributor.

- Confirmed for tcp: the curve flattens at workers = 4 (215k → 225k,
  +4.5% for a doubling) while the no-ingest pipeline still climbs to
  405k; −44% at workers = 8. The ingest chain in the CPU profile
  (tcpmn8): go-syslog `Server.scan` **21.5% of all samples**
  (bufio.Scanner.Scan 13.6%, rfc3164 `parser` 7.3%, `format.detect`
  1.65%, `Dump` 1.53%) + `Source.run` 1.9% + line-channel send 1.3%.
  One scanner goroutine per connection makes this a serial stage.
- Marginal for unixgram (−11% at workers = 8) and minor for the channel
  handoff itself: the identical unbuffered handoff carries the
  pipeline-only run to 405k lines/s, the feeder's send-blocking is
  0.65s of 10.43s (6.2%), and handoff CPU is ~1–3%. The cost is in
  go-syslog's tcp framing/format-detect/dump path, not in `<-d.lines`.
- The code-review pass's isolated ingest benchmark (`BenchmarkIngestForward`:
  go-syslog + `Source.run` forwarding to a counting consumer, no
  evaluation) pins the serial chain's own cost at 1.60µs/line (tcp,
  625k lines/s) / 1.75µs (unixgram, 572k) — consistent with the
  ≈ +1.8µs/line it adds to the pipeline and the ~225k combined ceiling
  ((2.47+1.8)µs ≈ 235k lines/s), and confirming the cost is the
  framing path, not `<-d.lines`.
- Note: the benchmark's socket *feeder* (`conn.Write`, 19.8% of tcpmn8
  samples) is harness-side and excluded from this verdict.

### H6 — O(rules) filter evaluation per event — **PARTIAL** (mechanism confirmed; not a bottleneck at realistic rule counts)

- Growth is clean and linear: 15.7ns @ 1 rule, 129.8ns @ 10, 1.247µs @
  100 ≈ **12.5ns/rule**, zero allocations, match and no-match alike
  (leaves 1–6ns).
- But `filter.Match` does not register in the pipeline profiles at the
  benchmark's 1-rule chains, and even 10 rules/chain (129.8ns) would be
  ~2.6% of the fast path. It becomes material only at ≥100 rules/chain
  (≈1.25µs/line ≈ 25% of fast-path time) — documented as a threshold,
  not a fix (no follow-up filed).

## Recommended follow-ups (ordered by measured impact)

Candidates for the next planning round — deliberately **not ticketed
yet**; they will be scoped with `/to-spec` and `/to-tickets` after
further discussion:

1. **Batch report persistence** (H4): batch/decouple the
   single-connection report upsert — 38µs/line and 62.7% of worker
   blocking when rules match; the only fix that moves the write path's
   saturation point.
2. **Cut parse allocations** (H1): parse without the generic map +
   per-field re-parse — 3µs and 32 allocs/line, 75% of all allocated
   objects, owner of the GC curve.
3. **Ingest tcp framing cost** (H5): go-syslog tcp framing — ~1.9µs/line
   and the workers=4 ceiling for tcp deployments.
4. **De-globalize per-line bookkeeping** (H2): 48ns + 112B/line, 25.5%
   of mutex contention, parallel rate below serial.
5. **Alloc-free tracker-cache keys** (H3): 2×32B/line and 7.6% of
   allocated objects.

No candidate for H6 (threshold documented above) nor for the read path
(`GET /reports`) — it is off the hot path at v0 scale (7.2µs + 26
allocs/row), worth revisiting only with row-count requirements.

## Baseline for future regression comparison

- `baseline/bench-count10.txt` — raw `go test` output, 10 runs of the
  whole suite (all metrics: sec/op, lines/s, writes/op, B/op,
  allocs/op, evictions/op, gc-cpu-frac). Regenerated wholesale by the
  v0-hot-path round (ticket 07 — episode scenario re-modeling on top
  of the Trigger semantics of tickets 01–05): the benchmark set, its
  scenario names and the write path itself all changed, so every
  earlier run is invalid for comparison. **Provenance**: generated
  2026-10-18 at commit `61d1423` (feat/v0-hot-path with tickets 01–05
  merged), go1.27.0 linux/amd64, `GOMAXPROCS=22` pinned, Intel Core
  Ultra 9 185H (machine and toolchain as in § "Method and
  environment"; same command and hygiene as every prior baseline).
- `baseline/benchstat.txt` — benchstat summary of that run (medians +
  spread per benchmark per metric).
- Compare a future change with:
  `go test -run=^$ -bench=. -benchmem -count=10 -p=1 ./... > new.txt`
  then `benchstat baseline/bench-count10.txt new.txt`, on this class of
  machine at GOMAXPROCS=22. Real-socket benchmarks
  (`PipelineIngest/*`) carry 1–10% run-to-run variance by construction.

## Reproduce the profiles

```sh
# CPU + mem (per selection; sel ∈ {mn1,mn8,me1,me8,tcpmn8}, pattern per selection)
GOMAXPROCS=22 go test -run=^$ -bench='^BenchmarkPipeline$/^match-never$/^workers=8$' \
  -benchmem -benchtime=5s -cpuprofile=cpu.out -memprofile=mem.out ./internal/app

# mutex + block (separate run: full-rate instrumentation distorts timing)
GOMAXPROCS=22 go test -run=^$ -bench='^BenchmarkPipeline$/^match-never$/^workers=8$' \
  -benchmem -benchtime=2s -mutexprofile=mutex.out -mutexprofilefraction=1 \
  -blockprofile=block.out -blockprofilerate=1 ./internal/app

go tool pprof -top -cum -nodecount=25 cpu.out
go tool pprof -sample_index=alloc_objects -top mem.out
go tool pprof -top mutex.out      # contended delay by call site
go tool pprof -top block.out; go tool pprof -traces 'chanrecv2|chansend1' block.out
```

Extracts of exactly these outputs are committed in `profiles/`
(`cpu-*.txt`, `mem-*.txt`, `mutex-*.txt`, `block-*.txt`; mn1/mn8 =
match-never workers=1/8, me1/me8 = match-every workers=1/8, tcpmn8 =
tcp ingest match-never workers=8). The set covers every selection ×
every profile kind (20 extracts): the ticket-04 pass collected
`cpu-*` (all five), `mem-{mn1,mn8,me8}`, `mutex-{mn8,me8}` and
`block-{mn8,me8}`; the code-review pass completed it with
`mem-{me1,tcpmn8}`, `mutex-{mn1,me1,tcpmn8}` and
`block-{mn1,me1,tcpmn8}` (raw profiles stay uncommitted; the added
extracts come from fresh runs of the same commands and carry
run-to-run timing differences in absolute delay values).

## Dispositions (discussion round — inputs for `/to-spec`)

The follow-up candidates above were decided in a grilling session after
this report landed; the decisions are recorded in `GLOSSARY.md`
(**Trigger**) and `docs/adr/0008`/`0009`. Fate of each candidate:

1. **Batch report persistence** — *shelved*. Write-behind is not built;
   report writes stay synchronous (ADR 0008 records the accepted
   deferral window as policy only). The cheap synchronous levers remain
   work: WAL + split read path (ADR 0009), drop the pre-SELECT in
   `Upsert`, prepared statements.
2. **Cut parse allocations** — *reshaped*: rewrite the parser on
   `encoding/json/v2` (stdlib in Go 1.27), keeping the Event mapping and
   `FieldError` validation identical.
3. **Ingest tcp framing** — *docs-only*: deployments feed over udp or
   unixgram; document the guidance (unixgram preferred at high rate;
   note UDP kernel-buffer drops) instead of changing framing code.
4. **De-globalize progress bump** and 5. **alloc-free store keys** —
   unchanged small cleanups; the new Trigger semantics below lower their
   urgency further.

New work decided (to be specced first — it is the largest lever and it
re-models the benchmarks):

- **Trigger semantics** (ADR 0008): a Trigger (a match that ran the
  rule's report action) empties the rule's tracker for the Target; while
  a report for (rule, Target) is alive, further Triggers write nothing —
  the rule keeps matching and its other actions keep running. The
  live-report set is derived from the report table (rebuilt at startup,
  maintained on Trigger, delete and expiry). Supersedes candidate 1's
  churn rationale: re-Trigger churn disappears by construction (one write
  per report lifetime).
- **Tracker-less tripwire pattern** (`agent keyword "…"` + report, no
  tracker) is a supported shape worth documenting alongside the rules
  docs.

Carry-over design notes for `/to-spec` and `/to-tickets`:

- Benchmark fixtures must be re-modeled: `match-every`'s `volume: 0.5`
  overflow-every-event trick breaks under reset + skip semantics; new
  scenarios are first-Trigger vs re-arm-after-delete/expiry.
- Skip-set placement is open (in-memory cache in front of the report
  repository is the obvious shape; correctness source is the report
  table).
- The split sqlite connections need `:memory:` handling in tests
  (shared-cache URI or single-connection fallback) — ADR 0009.
- Suppression precision (settled): only the report write is suppressed
  while a report is alive — the rule matches and all its actions run;
  the tracker resets on every Trigger (write or suppressed), so action
  cadence stays one run per accumulation episode.

## Addendum — v0-hot-path: episode scenarios and the regenerated baseline

Ticket 07 of the v0-hot-path round (`.scratch/v0-hot-path/`, spec
stories 30–31) changed what the benchmarks model. The Trigger
semantics of tickets 01–05 — a Trigger empties the tracker, one report
write per (rule, Target) per report lifetime, delete/expiry re-arm —
retired the overflow-every-event trick (volume below the per-event
increment; a report write per event) as a model of the world. The
sections above stay as the v0-benchmarks round wrote them: their
numbers describe the pre-hot-path code and its `match-every` scenario.
This addendum is the re-modeled suite's record; the baseline of record
is the regenerated one (§ "Baseline for future regression
comparison").

### Scenario re-modeling (old → new)

| old | new | what it measures now |
|---|---|---|
| `Evaluate{,Memory,SQLite}/match-every` (write per event) | `Evaluate{Memory,SQLite}/{first-trigger,rearm-delete,rearm-expiry}` — episode fixture, `volume: 3` (a Trigger per `benchEpisodeLen` = 4 events per Target) | report episodes (spec stories 9–10): one write per (rule, Target) per report lifetime — the first Trigger writes, later Triggers in the lifetime are suppressed; delete / expiry re-arm |
| `Pipeline*/match-every{,-evicting}` | `Pipeline*/first-trigger{,-evicting}`, `Pipeline*/rearm-delete` | the same episode vocabulary at the assembled seam; `rearm-delete` re-arms at every drain boundary (the operator's delete, timed like the rest of the workload) |
| `Evaluate/match-every` (`domain/evaluation`) | `Evaluate/trigger-every` | the trick **renamed to what it now measures**: the Trigger path at one-event episodes (report action + Trigger call + tracker reset per event) — the write it used to model is suppressed above this seam |
| `match-never{,-evicting}` | unchanged names | the fast-path floor |

Scenario contracts are pinned by correctness tests in the suite's
style: `TestEvaluateBenchScenarios` and
`TestBenchPipelineScenariosMatchTheirNames` compare the run against
`episodeOracle` — the documented episode semantics simulated from the
fixture events alone (accumulate +1/event, Trigger every
`benchEpisodeLen`-th event, tracker-record TTL resets, one write per
(rule, Target) per report lifetime), so it can disagree with the code
under test — and assert the write contract per (rule, Target,
lifetime) cell; `TestBenchChainsMatchTheirNames` pins the renamed
stub-port fixture's Trigger cadence. The regenerated baseline carries
the write rate as `writes/op` beside `lines/s`.

Method unchanged (§ "Method and environment"): `GOMAXPROCS=22 go test
-run=^$ -bench=. -benchmem -count=10 -p=1 ./...`, go1.27.0 linux/amd64,
benchstat medians of 10. (The evaluate harness's injected clock became
lock-free in this round — it is read per event in the measured path.)

### The spec's performance claim: per-event → per-episode write cost

Pipeline throughput (lines/s, medians of 10; the retired `match-every`
row is the pre-hot-path baseline's per-event write world):

| scenario | writes/op | w=1 | w=2 | w=4 | w=8 |
|---|---|---|---|---|---|
| ~~match-every~~ (retired: write per event) | ≈1 | 23.3k | 21.8k | 22.2k | 21.7k |
| first-trigger (write per report lifetime) | 661µ | 365.7k | 370.1k | 443.4k | 624.0k |
| first-trigger-evicting | 232µ | 353.4k | 367.2k | 425.0k | 602.8k |
| rearm-delete (write per episode) | 109m | 237.8k | 265.3k | 315.5k | 411.0k |
| match-never (floor) | 0 | 396.4k | 408.4k | 478.8k | 668.4k |

The write cost moved from every line to every report lifetime
(`first-trigger`: one write per ~1,500–2,600 lines) or every re-armed
episode (`rearm-delete`: one write per ~9 lines) — and both **scale
with workers** where the per-event write world sat flat at the ≈23k
write-bound ceiling. `first-trigger` runs within ~7% of the
match-never floor at w=8.

Evaluate seam (sec/op, the write path isolated):

| benchmark | pre-hot-path | now |
|---|---|---|
| `EvaluateSQLite` write-per-event → `first-trigger` / `rearm-delete` / `rearm-expiry` | 118.4µ | 1.214µ / 5.994µ / 4.833µ |
| `EvaluateMemory` write-per-event → `first-trigger` / `rearm-delete` / `rearm-expiry` | 1.485µ | 1.198µ / 1.429µ / 1.331µ |
| `Evaluate{Memory,SQLite}/match-never` | 725.4n / 748.6n | 799.5n / 789.2n |

writes/op on the same runs: 747–754µ (first-trigger), 434m
(rearm-delete/rearm-expiry), 0 (match-never) — vs ≈1.0 in the retired
world. Ingest-inclusive (lines/s, w=1/2/4/8): tcp `first-trigger`
227.3k / 230.6k / 230.7k / 229.0k and `rearm-delete` 174.3k → 236.5k
(retired tcp `match-every`: 20.4k → 19.4k); unixgram `first-trigger`
291.4k → 451.6k and `rearm-delete` 189.2k → 367.1k (retired: 22.3k →
19.7k). tcp now sits flat at its ≈230k framing ceiling at every worker
count — the pipeline is no longer the bottleneck there.

### Fast-path floors (before → after)

`lines/s`, pre-hot-path baseline → regenerated baseline:

| floor | w=1 | w=2 | w=4 | w=8 |
|---|---|---|---|---|
| Pipeline/match-never | 206.9k → 396.4k | 226.3k → 408.4k | 276.6k → 478.8k | 404.5k → 668.4k |
| Pipeline/match-never-evicting | 203.1k → 371.8k | 217.5k → 386.3k | 267.8k → 451.2k | 389.3k → 629.6k |
| Ingest/unixgram/match-never | 172.9k → 314.4k | 190.5k → 336.3k | 242.4k → 409.8k | 360.8k → 460.2k |
| Ingest/tcp/match-never | 150.9k → 233.9k | 176.7k → 234.2k | 214.8k → 232.4k | 224.5k → 230.4k |

Improved across the board (tickets 04–05's cheap upserts and parser
rewrite sit in these paths too); tcp saturates its ≈230k framing
ceiling at every worker count now. The stub-port micro floors moved
only with the run environment: a same-day A/B of the old and new
fixtures on identical semantics (commit `61d1423`) reads
`EvaluateMemory/match-never` 734n → 738n and `Evaluate/match-never`
401n → 404n medians — unchanged within ~1%. The few-percent absolute
differences between the two committed baselines' micro rows are
run-environment drift: compare future changes against **this**
baseline, never across rounds. (`Evaluate/trigger-every` ≈ 857ns vs
the pre-hot-path `Evaluate/match-every` 659ns is the tracker reset
ticket 02 added to the Trigger path — exactly what the renamed
scenario now measures; the same-day old fixture on the new semantics
reads 860ns.)

### Upsert cost, before → after (ticket 04, folded in)

The write the episode scenarios amortize also got much cheaper in
ticket 04 (raw before/after runs at `/tmp/bench-before-raw.txt` and
`/tmp/bench-after-raw.txt`, median of 5, `GOMAXPROCS=22 go test
-bench='BenchmarkReportUpsert|BenchmarkReportsList' -benchmem -count=5
-p=1`; full table in that ticket's answer):

| upsert | ns/op before → after | allocs/op |
|---|---|---|
| ReportUpsert/memory/insert | 31,756 → 9,986 (−69%) | 53 → 22 |
| ReportUpsert/memory/update | 25,259 → 4,525 (−82%) | 54 → 22 |
| ReportUpsert/file/insert | 76,420 → 18,240 (−76%) | 53 → 22 |
| ReportUpsert/file/update | 63,394 → 8,653 (−86%) | 54 → 22 |

### Reading the new baseline

`baseline/benchstat.txt` sections of interest: `lines/s` (throughput
curves), `writes/op` (the episode write rate — the "one write per
(rule, Target) per report lifetime" evidence as a metric), `sec/op`,
`evictions/op`, `gc-cpu-frac`. Real-socket benchmarks
(`PipelineIngest/*`) keep their 1–10% run-to-run variance.
