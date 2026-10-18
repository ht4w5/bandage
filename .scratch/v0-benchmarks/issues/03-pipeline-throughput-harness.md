# 03 — Pipeline throughput and worker scaling (spec Phase 2)

Type: task
Status: ready-for-agent
Depends on: 01

Measure the assembled pipeline, not the parts: sustained lines/sec and
where it saturates.

## Scope

- In-package end-to-end harness driving the real `runPipeline` chain
  with a pre-generated corpus (no network in the timed path): workers =
  1/2/4/8; tracker cache sized to avoid evictions, plus a second run
  with an evicting cap.
- Ingest-inclusive variant over a real loopback syslog socket (tcp and
  unixgram) to capture go-syslog and channel-handoff cost. H5.
- Match-path scenarios: rules that fire on every event vs. rules that
  never fire, isolating report-write cost. H4.
- Record allocs/op, GC fraction and the daemon `/stats` counters beside
  throughput.

## Done when

- A lines/sec number per worker count per scenario exists, the scaling
  curve's flatten point is named, and raw results are recorded under
  `## Answer` in this file.

## Answer

Built `internal/app/throughput_bench_test.go` (in-package, stdlib-only,
benchmarks do not run under `make test`):

- **Harness** — `startBenchPipeline` assembles the real daemon
  (`New`: rules → nginx parser → filesize enricher → evaluation →
  sqlite `:memory:` report repository → tracker cache) and starts the
  real `runPipeline` workers on the daemon's unbuffered line channel,
  with no socket anywhere in the path. `runPipelineBench` feeds
  `corpus.Line(i)` inside `b.Loop()`; the feed is back-pressured by the
  channel, and a `waitProcessed` drain every 1024 lines bounds the
  in-flight tail the stopped timer can miss. `startBenchIngest` is the
  ingest-inclusive variant: full `Start()` wiring (go-syslog source,
  sweeper, HTTP API) fed over a real loopback socket — tcp (probed
  ephemeral port, newline framing) and unixgram (temp-dir socket, one
  datagram per line), with the wire bytes pre-rendered before the loop.
- **Scenarios** — match-path pair differing only in the leaky-bucket
  volume: `match-every` (`rate, leak: 0, volume: 0.5` — overflows from
  the first event, so every event Matches and Triggers a report upsert)
  vs `match-never` (`volume: 1000000000000` — identical filter and
  tracker-update path, never overflows, never writes). The delta
  isolates the match/write path (H4). Each runs at a roomy cache cap
  (65536, no evictions at the corpus's 508 distinct keys) and a
  deliberately evicting cap (256).
- **Determinism** — fixed `bench.Seed` corpus
  (`bench.NewCorpus(bench.Seed, bench.ShapeFull, bench.DistZipf, 4096)`)
  pre-generated before `b.Loop()` and cycled; frozen wall clock via
  `WithClock` (report timestamps, cache expiry and `/stats` all see
  `benchWall`); nop logger so no record rendering sits in the measured
  path. The real-socket variant cannot be made fully deterministic
  inside `go test`; its variance is recorded below.
- **Bookkeeping beside throughput** — `bench.ReportLinesPerSec` (one op
  = one raw line), `-benchmem` ns/op, B/op, allocs/op, plus
  `evictions/op` and `gc-pause-frac` (Δ`PauseTotalNs`/elapsed; MemStats
  carries no delta-able GC CPU fraction) and the full `/stats` snapshot
  via `b.Logf`.
- **Correctness test** — `TestBenchPipelineScenariosMatchTheirNames`
  (table over the four scenarios) pins the scenario contracts: match-every
  writes exactly one report per event Target and match-never none (the
  expected count derived from the fixture events alone), received =
  parsed with no drops, the roomy cap never evicts and the evicting cap
  does.

### Method and environment

go1.27.0 linux/amd64, Intel Core Ultra 9 185H (22 CPUs visible),
GOMAXPROCS=22 (Go's container-aware default, unpinned), sqlite
`:memory:`, `-benchtime=1s`, `-count=3` consecutive runs, single
machine (not load-isolated). `lines/s` is the mean of the three runs
with min–max spread; all other columns are the mean.

### Results — pipeline only (no network in the path), lines/s

| scenario | workers=1 | workers=2 | workers=4 | workers=8 |
|---|---|---|---|---|
| match-every | 23,234 | 21,771 | 21,995 | 21,901 |
| match-every-evicting | 23,317 | 21,789 | 21,756 | 21,401 |
| match-never | 200,812 | 221,426 | 280,285 | 405,308 |
| match-never-evicting | 201,242 | 218,337 | 266,569 | 389,176 |

### Results — ingest-inclusive (real loopback syslog socket), lines/s

| scenario | workers=1 | workers=2 | workers=4 | workers=8 |
|---|---|---|---|---|
| tcp/match-every | 20,710 | 19,941 | 19,858 | 19,661 |
| tcp/match-every-evicting | 20,411 | 19,541 | 19,275 | 19,724 |
| tcp/match-never | 147,541 | 173,389 | 212,707 | 220,281 |
| tcp/match-never-evicting | 144,862 | 168,993 | 206,553 | 218,379 |
| unixgram/match-every | 22,052 | 20,014 | 20,132 | 20,023 |
| unixgram/match-every-evicting | 21,649 | 19,998 | 20,040 | 19,560 |
| unixgram/match-never | 168,532 | 186,448 | 230,223 | 358,724 |
| unixgram/match-never-evicting | 158,946 | 181,572 | 232,512 | 345,134 |

### Raw results (means of 3 runs; spread = min–max of lines/s)

| benchmark | lines/s | min | max | ns/op | allocs/op | B/op | evictions/op | gc-pause-frac |
|---|---|---|---|---|---|---|---|---|
| Pipeline/match-every/workers=1 | 23234 | 23061 | 23568 | 43045 | 111 | 5902 | 0.000 | 0.0089 |
| Pipeline/match-every/workers=2 | 21771 | 21616 | 21908 | 45934 | 114 | 6064 | 0.000 | 0.0086 |
| Pipeline/match-every/workers=4 | 21995 | 21654 | 22355 | 45472 | 114 | 6068 | 0.000 | 0.0084 |
| Pipeline/match-every/workers=8 | 21901 | 21763 | 22062 | 45662 | 114 | 6071 | 0.000 | 0.0084 |
| Pipeline/match-every-evicting/workers=1 | 23317 | 22924 | 23656 | 42895 | 112 | 5956 | 0.481 | 0.0095 |
| Pipeline/match-every-evicting/workers=2 | 21789 | 21396 | 21987 | 45902 | 115 | 6125 | 0.481 | 0.0085 |
| Pipeline/match-every-evicting/workers=4 | 21756 | 21572 | 21909 | 45967 | 116 | 6130 | 0.482 | 0.0082 |
| Pipeline/match-every-evicting/workers=8 | 21401 | 21287 | 21580 | 46729 | 116 | 6141 | 0.480 | 0.0090 |
| Pipeline/match-never/workers=1 | 200812 | 195947 | 204354 | 4981 | 41 | 2192 | 0.000 | 0.0133 |
| Pipeline/match-never/workers=2 | 221426 | 216737 | 225710 | 4517 | 41 | 2202 | 0.000 | 0.0206 |
| Pipeline/match-never/workers=4 | 280285 | 277376 | 282668 | 3568 | 41 | 2211 | 0.000 | 0.0315 |
| Pipeline/match-never/workers=8 | 405308 | 404752 | 406120 | 2467 | 41 | 2224 | 0.000 | 0.0506 |
| Pipeline/match-never-evicting/workers=1 | 201242 | 199004 | 202587 | 4969 | 43 | 2269 | 0.507 | 0.0137 |
| Pipeline/match-never-evicting/workers=2 | 218337 | 213178 | 222036 | 4582 | 43 | 2282 | 0.507 | 0.0222 |
| Pipeline/match-never-evicting/workers=4 | 266569 | 265842 | 267954 | 3752 | 43 | 2293 | 0.507 | 0.0339 |
| Pipeline/match-never-evicting/workers=8 | 389176 | 387396 | 391328 | 2569 | 43 | 2305 | 0.507 | 0.0536 |
| PipelineIngest/tcp/match-every/workers=1 | 20710 | 20311 | 20932 | 48295 | 127 | 8836 | 0.000 | 0.0144 |
| PipelineIngest/tcp/match-every/workers=2 | 19941 | 19849 | 20014 | 50149 | 129 | 8987 | 0.000 | 0.0145 |
| PipelineIngest/tcp/match-every/workers=4 | 19858 | 19671 | 20196 | 50366 | 128 | 8938 | 0.000 | 0.0145 |
| PipelineIngest/tcp/match-every/workers=8 | 19661 | 19374 | 20008 | 50871 | 130 | 9079 | 0.000 | 0.0138 |
| PipelineIngest/tcp/match-every-evicting/workers=1 | 20411 | 20132 | 20884 | 49006 | 127 | 8813 | 0.481 | 0.0143 |
| PipelineIngest/tcp/match-every-evicting/workers=2 | 19541 | 19262 | 19827 | 51181 | 130 | 9029 | 0.481 | 0.0148 |
| PipelineIngest/tcp/match-every-evicting/workers=4 | 19275 | 18991 | 19559 | 51887 | 131 | 9122 | 0.481 | 0.0146 |
| PipelineIngest/tcp/match-every-evicting/workers=8 | 19724 | 19719 | 19731 | 50701 | 131 | 9128 | 0.480 | 0.0145 |
| PipelineIngest/tcp/match-never/workers=1 | 147541 | 145591 | 149563 | 6779 | 58 | 5004 | 0.000 | 0.0332 |
| PipelineIngest/tcp/match-never/workers=2 | 173389 | 171141 | 175002 | 5768 | 58 | 4943 | 0.000 | 0.0481 |
| PipelineIngest/tcp/match-never/workers=4 | 212707 | 210794 | 213987 | 4701 | 58 | 4891 | 0.000 | 0.0611 |
| PipelineIngest/tcp/match-never/workers=8 | 220281 | 219095 | 221492 | 4540 | 58 | 4932 | 0.000 | 0.0632 |
| PipelineIngest/tcp/match-never-evicting/workers=1 | 144862 | 144042 | 146365 | 6903 | 60 | 5053 | 0.507 | 0.0346 |
| PipelineIngest/tcp/match-never-evicting/workers=2 | 168993 | 168112 | 169686 | 5917 | 60 | 5012 | 0.507 | 0.0512 |
| PipelineIngest/tcp/match-never-evicting/workers=4 | 206553 | 206201 | 206778 | 4841 | 60 | 4974 | 0.507 | 0.0645 |
| PipelineIngest/tcp/match-never-evicting/workers=8 | 218379 | 216697 | 221055 | 4580 | 60 | 5062 | 0.507 | 0.0692 |
| PipelineIngest/unixgram/match-every/workers=1 | 22052 | 21805 | 22442 | 45355 | 125 | 7986 | 0.000 | 0.0084 |
| PipelineIngest/unixgram/match-every/workers=2 | 20014 | 19663 | 20315 | 49973 | 127 | 8079 | 0.000 | 0.0082 |
| PipelineIngest/unixgram/match-every/workers=4 | 20132 | 19854 | 20394 | 49677 | 127 | 8090 | 0.000 | 0.0078 |
| PipelineIngest/unixgram/match-every/workers=8 | 20023 | 19903 | 20151 | 49945 | 126 | 8076 | 0.000 | 0.0079 |
| PipelineIngest/unixgram/match-every-evicting/workers=1 | 21649 | 21600 | 21693 | 46191 | 126 | 8027 | 0.482 | 0.0090 |
| PipelineIngest/unixgram/match-every-evicting/workers=2 | 19998 | 19285 | 20408 | 50037 | 128 | 8120 | 0.481 | 0.0085 |
| PipelineIngest/unixgram/match-every-evicting/workers=4 | 20040 | 19813 | 20291 | 49904 | 128 | 8137 | 0.481 | 0.0086 |
| PipelineIngest/unixgram/match-every-evicting/workers=8 | 19560 | 19345 | 19684 | 51127 | 129 | 8224 | 0.481 | 0.0088 |
| PipelineIngest/unixgram/match-never/workers=1 | 168532 | 165865 | 173516 | 5936 | 55 | 4115 | 0.000 | 0.0236 |
| PipelineIngest/unixgram/match-never/workers=2 | 186448 | 185530 | 187925 | 5364 | 55 | 4161 | 0.000 | 0.0299 |
| PipelineIngest/unixgram/match-never/workers=4 | 230223 | 216941 | 240130 | 4352 | 55 | 4210 | 0.000 | 0.0448 |
| PipelineIngest/unixgram/match-never/workers=8 | 358724 | 357511 | 360141 | 2788 | 56 | 4303 | 0.000 | 0.0663 |
| PipelineIngest/unixgram/match-never-evicting/workers=1 | 158946 | 156110 | 162012 | 6293 | 57 | 4194 | 0.507 | 0.0231 |
| PipelineIngest/unixgram/match-never-evicting/workers=2 | 181572 | 180775 | 182181 | 5508 | 57 | 4240 | 0.507 | 0.0308 |
| PipelineIngest/unixgram/match-never-evicting/workers=4 | 232512 | 231690 | 234006 | 4301 | 57 | 4308 | 0.507 | 0.0442 |
| PipelineIngest/unixgram/match-never-evicting/workers=8 | 345134 | 343271 | 346447 | 2897 | 57 | 4408 | 0.507 | 0.0697 |

### Flatten points (named)

- **match-every saturates at workers = 1**: 23.2k lines/s at one
  worker, 21.9k at eight (−6% — workers never help). Identical under
  both cache caps and both ingest modes (~20–23k everywhere).
- **match-never has no flatten point within 1–8 workers** (still
  climbing at workers = 8: 405k, 2.0× the one-worker rate) but scales
  strongly sublinearly — eight workers buy 2×, and workers = 2 adds
  only 10%.
- **tcp/match-never flattens at workers = 4** (212.7k → 220.3k, +3.6%
  for a doubling): the tcp ingest path becomes the ceiling.
- unixgram/match-never mirrors the no-ingest curve ~10–15% lower (359k
  at workers = 8), still rising at 8.

### Allocs, GC and eviction notes

- allocs/op: 41–43 (match-never) vs 111–116 (match-every): the
  Trigger/report path adds ~70 allocs and ~3.8 KB per line (sqlite
  upsert + JSON body marshal). Ingest adds 14–18 allocs and 2–3 KB per
  line (tcp 127–133, unixgram 125–129 in match-every).
- gc-pause-frac (share of measured time in stop-the-world pauses):
  0.008–0.010 in the write-bound match-every runs; 0.013 → 0.051 in
  match-never as workers go 1 → 8 (534–728 GCs per ~1 s measurement at
  workers = 8), reaching 0.069 in tcp/match-never-evicting/workers=8.
  GC pressure rises with worker count within one scenario.
- Evicting cap churns ~0.48–0.51 evictions per line (≈ one eviction per
  two cache updates) yet costs only 0–4% throughput vs the roomy cap —
  eviction is cheap in this corpus; the tracker state, not the cache,
  is what the write path dominates.

### `/stats` cross-check (recorded run, workers = 8)

- match-every: received = parsed = 25,310, dropped = 0, cache gets =
  50,620 (= 2/line: filesize + tracker), misses = 508, evictions = 0,
  size = 508.
- match-never: received = parsed = 480,844, dropped = 0, gets =
  961,688 (= 2/line), size = 508 of cap 65,536, evictions = 0.
- match-never-evicting: 470,895 lines, gets = 941,790, misses =
  238,978, evictions = 238,752 (0.507/line), size = 226 of cap 256.
- In every one of the 48 recorded runs: received == parsed == lines
  fed, dropped == 0.

### Variance

Pipeline-only runs (fixed corpus, frozen clock): spread (max−min)/mean
≤ 4.2% over 3 runs. Real-socket runs: ≤ 5.6% except
unixgram/match-never/workers=4 (10.1%, 217k–240k). The socket path's
timing noise cannot be removed inside `go test`; these numbers are
reported as measurements, never asserted.

### Observations on H2/H4/H5 (verdicts are ticket 04's)

- **H2 (`progress.bump` serializes workers)** — match-never's curve is
  consistent with a global per-line cost workers cannot overlap (8
  workers buy only 2.0× on the no-network path), but two shared
  suspects rise in lockstep: gc-pause-frac grows 0.013 → 0.051 with
  workers, and the DistZipf corpus sends ~16% of events to one
  tracker-cache key (and one filesize key) per line — hot-shard
  contention (H3's shape) at the same time. No attribution here; the
  profiles in ticket 04 should separate bump vs GC vs shard mutex.
- **H4 (sqlite upserts serialize the match path)** — strongly
  consistent: match-every is completely flat across workers while the
  identical-shape match-never scales 2×, and the per-line delta
  between the two at workers = 1 is ~38 µs of the ~43 µs/op (~88%) —
  the single-connection upsert (ADR 0007) is essentially the entire
  match-path cost and its saturation ceiling. Verdict left to ticket 04.
- **H5 (unbuffered `lines` channel couples ingest to workers)** —
  ingest-inclusive throughput never exceeds the no-ingest pair at the
  same scenario/workers. The gap is small when the pipeline is
  write-bound (match-every: ~20–22k vs 22–23k) but large in the fast
  path (tcp/match-never/workers=8: 220k vs 405k, −46%; unixgram 359k,
  −11%), and tcp/match-never flattens at workers = 4 where the
  no-ingest curve is still climbing — ingest (go-syslog framing +
  channel handoff) becomes the ceiling before the pipeline does.
  Verdict left to ticket 04.

Reproduce: `go test -run '^$' -bench 'BenchmarkPipeline' -benchmem
-count=3 ./internal/app` (or `make bench-pkg PKG=./internal/app` for
the whole package including ticket 02's microbenchmarks).
