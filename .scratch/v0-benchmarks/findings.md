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
  (~21 min); benchstat summary of the same run:
  `baseline/benchstat.txt`. All "±" below are benchstat's spread over
  the 10 runs.
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

## Pipeline baselines (benchstat medians of 10)

lines/s, pipeline-only (no network in the path):

| scenario | workers=1 | workers=2 | workers=4 | workers=8 |
|---|---|---|---|---|
| match-every | 23.60k | 21.82k | 21.99k | 21.91k |
| match-never | 204.1k | 224.2k | 271.6k | 396.4k |
| match-never-evicting | 199.6k | 217.0k | 263.8k | 385.3k |

lines/s, ingest-inclusive (real loopback syslog socket):

| scenario | workers=1 | workers=2 | workers=4 | workers=8 |
|---|---|---|---|---|
| tcp/match-never | 147.8k | 171.9k | 212.1k | 222.6k |
| unixgram/match-never | 167.0k | 185.4k | 238.5k | 355.5k |
| tcp/match-every | 20.94k | 19.67k | 19.65k | 19.55k |

Per-line bookkeeping of the same runs: match-never 41 allocs/op,
2.14KiB/op; match-every 111–114 allocs/op, 5.75–5.92KiB/op;
gc-pause-frac (share of measured wall time in STW pauses) grows
**1.2% → 4.7%** for match-never as workers go 1 → 8 (match-every stays
flat ~0.8%).

## Ranked bottlenecks

Ranked by measured per-line impact. `% of pipeline` is the CPU-profile
share of `runPipeline`'s cumulative samples (fast path =
`Pipeline/match-never/workers=1`, 4.901µs/line wall; write path =
`Pipeline/match-every/workers=1`, 42.37µs/line wall). `lines/sec/core`
is the single-core capacity of the stage: 1e9/ns/op for serial stages
and throughput ÷ workers for pipeline rows.

| # | Stage (hot-path inventory) | ns/op | B/op | allocs/op | % pipeline fast path | % pipeline write path | lines/sec/core |
|---|---|---|---|---|---|---|---|
| 1 | **Report write (on match)** — `sqlite.Upsert` incl. body marshal | 31,370 (`:memory:` insert) / 75,940 (file insert) | 2.73Ki | 53–54 | n/a (no writes) | **82%** (72% of *all* CPU samples) | 31.9k (`:memory:`) / 13.2k (file) |
| 2 | **Parse** — `nginx.Parser.Parse` | 3,019 (full) / 1,804 (minimal) | 1.51Ki / 696 | 32 / 23 | **83%** (70% of all samples) | 12–13% | 331k (full) / 555k (minimal) |
| 3 | **Ingest** (adds on top of everything; tcp) | ≈ +1,870 vs no-ingest (w1: 6.768µs vs 4.901µs) | +2.9Ki (tcp) | +17 | n/a (no socket) | n/a | ceiling 222.6k (single scanner) |
| 4 | **Evaluate** — chain + tracker update | 739 (never fires) / 1,505 (fires; memory store + in-mem sink) | 461 / 1.01Ki | 13 / 25 | 5–6% | ~2% (excluding the write) | 1.35M / 665k |
| 5 | **Enrich** — filesize + 2× `Store.Update` | ≈ 230 (2 × 59–79 store + enrich overhead) | 64 | 2 | 3.8–4.1% | ~1% | ≈ 4.3M |
| 6 | **Bookkeeping** — `progress.bump` | 48.4 serial / 107.5 parallel | 112 | 1 | 1.7–2.6% CPU, **25.5% of mutex contention** | same | 20.7M serial; 9.3M at 22 goroutines (0.42M/core) |
| — | Read path (secondary) — `GET /reports` | 78,840 (10 rows) / 7.05ms (1k) | 51Ki / 5.13Mi | 304 / 26.1k | off hot path | off hot path | ~7.2µs + 26 allocs per row |

Filter evaluation (H6) is deliberately unranked: leaves cost 1–6ns
zero-alloc, chains ~12.5ns/rule (15.7ns @ 1 rule, 129.8ns @ 10, 1.247µs
@ 100) — real O(rules) growth, but below one percent of per-line time
at the benchmark's rule counts (see H6 verdict).

**GC pressure is cross-cutting, not a stage**: it is the tail of the
allocation columns above. gcBgMarkWorker is 6.3% of all CPU samples at
workers=1 and 8.2% at workers=8; gc-pause-frac 1.2% → 4.7% with worker
count; the write path adds ~70 allocs and ~3.6KiB per line on top of
the fast path (sqlite/`database/sql`/JSON-marshal churn). Fixing
ranks 1, 2, 5 and 6 fixes the GC curve.

## Worker-scaling attribution (ticket 03's flatten points)

- **match-every saturates at workers = 1** (23.6k → 21.9k) — explained
  entirely by the single-connection sqlite upsert (H4). CPU profile
  (me8): `sqlite.Upsert` = 5.00s of runPipeline's 5.97s = **83.8% of
  pipeline CPU**. Block profile (me8, 2s instrumented run):
  `database/sql.(*DB).BeginTx → DB.conn` accounts for **16.07s of
  25.61s total blocking delay (62.7%)** ≈ 8 workers × 2s — i.e. the
  whole worker fleet spends essentially all its time queued on the one
  connection (`SetMaxOpenConns(1)`, ADR 0007). Workers never scale;
  they just queue.
- **match-never is sublinear (204k → 396k, 1.94× at 8 workers) and
  still rising** — the process only sustains ~3.4 busy cores at
  workers = 8 (`Total samples = 20.6s` over 6.03s wall). The workers'
  dominant block is waiting for input: `chanrecv2` on `d.lines`
  (`for line := range d.lines`) = 2.87s of 10.43s block delay vs 0.65s
  of feeder-send back-pressure — the single feeder + unbuffered
  handoff feeds 8 workers only so fast. GC degrades with scale
  (gc-pause-frac 1.2% → 4.7%, gcBgMark 6.3% → 8.2%) and lock spinning
  becomes visible (`runtime.futex` 0.47s + `runtime.procyieldAsm`
  0.49s = 4.7% of samples at workers=8), but `progress.bump`'s mutex
  and the cache shards together are under 30% of the (small) mutex
  delay — the flatten shape is **feed handoff + GC**, not a lock.
- **tcp/match-never flattens at workers = 4** (212k → 223k) — the
  ingest path is a serial stage before the workers (H5). CPU profile
  (tcpmn8): go-syslog `Server.scan` (bufio.Scanner + rfc3164 parser +
  format.detect + Dump) = 21.5% of all samples, `Source.run` + line
  channel send ≈ 3.2%, versus 35% for the entire worker pipeline; one
  scanner goroutine per connection means ingest caps at ~223k lines/s
  while the same pipeline with no socket reaches 396k at workers = 8
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
- The predicted GC pressure is real: gc-pause-frac 1.2% → 4.7% as
  workers scale, gcBgMarkWorker 6.3–8.2% of CPU.

Caveat: "dominates" holds on the fast path only. When rules fire on
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
  near 20M lines/s, orders of magnitude above the observed 204–396k
  lines/s. The measured flatten is fed by the handoff/GC evidence in
  § Worker-scaling: workers idle on `d.lines` (2.87s block delay),
  GC pauses grow with worker count, and bump's mutex waits are only
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
  sqlite-sink evaluation is 118.9µs/event when rules fire vs 754ns
  when they never fire (239 vs 13 allocs).
- Pipeline: the two scenarios differ only in leaky-bucket volume, yet
  match-every (42.37µs/line) costs **8.6× match-never (4.90µs/line)**
  and never scales (23.6k → 21.9k lines/s from 1 → 8 workers).

### H5 — Unbuffered `lines` channel couples ingest to workers — **PARTIAL**

The predicted effect ("ingest becomes the ceiling before the pipeline
does") is confirmed for tcp; the predicted mechanism (per-line handoff
wakeups) is a minor contributor.

- Confirmed for tcp: the curve flattens at workers = 4 (212k → 223k,
  +3.6% for a doubling) while the no-ingest pipeline still climbs to
  396k; −44% at workers = 8. The ingest chain in the CPU profile
  (tcpmn8): go-syslog `Server.scan` **21.5% of all samples**
  (bufio.Scanner.Scan 13.6%, rfc3164 `parser` 7.3%, `format.detect`
  1.65%, `Dump` 1.53%) + `Source.run` 1.9% + line-channel send 1.3%.
  One scanner goroutine per connection makes this a serial stage.
- Marginal for unixgram (−11% at workers = 8) and minor for the channel
  handoff itself: the identical unbuffered handoff carries the
  pipeline-only run to 396k lines/s, the feeder's send-blocking is
  0.65s of 10.43s (6.2%), and handoff CPU is ~1–3%. The cost is in
  go-syslog's tcp framing/format-detect/dump path, not in `<-d.lines`.
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

## Recommended fixes (follow-up issues, ordered by measured impact)

Filed in the standing follow-ups tracker
`.scratch/v0-followups/issues/`, numbered after that tracker's existing
01–05 (the earlier ops-polish effort), evidence-linked from each issue
back to this file:

1. [`06-batch-report-persistence.md`](../v0-followups/issues/06-batch-report-persistence.md)
   — batch/decouple the single-connection report upsert (H4): 38µs/line
   and 62.7% of worker blocking when rules fire; the only fix that
   moves the write path's saturation point.
2. [`07-cut-parse-allocations.md`](../v0-followups/issues/07-cut-parse-allocations.md)
   — parse without the generic map + per-field re-parse (H1): 3µs and
   32 allocs/line, 75% of all allocated objects, owner of the GC curve.
3. [`08-ingest-tcp-framing-cost.md`](../v0-followups/issues/08-ingest-tcp-framing-cost.md)
   — go-syslog tcp framing cost (H5): ~1.9µs/line and the workers=4
   ceiling for tcp deployments.
4. [`09-deglobalize-progress-bump.md`](../v0-followups/issues/09-deglobalize-progress-bump.md)
   — per-line bookkeeping (H2): 48ns + 112B/line, 25.5% of mutex
   contention, parallel rate below serial.
5. [`10-alloc-free-store-keys.md`](../v0-followups/issues/10-alloc-free-store-keys.md)
   — tracker-cache key building (H3): 2×32B/line and 7.6% of allocated
   objects.

No issue filed for H6 (threshold documented above); none filed for the
read path (`GET /reports`) — it is off the hot path at v0 scale
(7.2µs + 26 allocs/row), worth revisiting only with row-count
requirements.

## Baseline for future regression comparison

- `baseline/bench-count10.txt` — raw `go test` output, 10 runs of the
  whole suite (all metrics: sec/op, lines/s, B/op, allocs/op,
  evictions/op, gc-pause-frac).
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
tcp ingest match-never workers=8).
