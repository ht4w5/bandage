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
  channel, and a `waitProcessed` drain every 1024 lines keeps the
  backlog bounded. The final drain runs inside the timed region (the
  timer is restarted around it after `b.Loop()` returns), so every
  line counted in lines/s, ns/op and allocs/op is fully processed
  before the timer stops — the code-review pass fixed the earlier
  accounting, which counted up-to-1024 socket-buffered tail lines
  whose processing finished after the timer stopped. `startBenchIngest`
  is the ingest-inclusive variant: full `Start()` wiring (go-syslog
  source, sweeper, HTTP API) fed over a real loopback socket — tcp
  (probed ephemeral port, newline framing) and unixgram (temp-dir
  socket, one datagram per line), with the wire bytes pre-rendered
  before the loop.
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
  `evictions/op` and `gc-cpu-frac` (Δ`/cpu/classes/gc/total` ÷
  Δ`/cpu/classes/total`, runtime/metrics — the GC's share of total CPU
  capacity, marking/assist/scavenge included). The code-review pass
  replaced the earlier `gc-pause-frac` (Δ`PauseTotalNs`/elapsed — only
  the STW share) with this genuine GC CPU share. The full `/stats`
  snapshot is recorded via `b.Logf`.
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
with min–max spread; all other columns are the mean. Every number
below is from the code-review pass re-run (same method) after the
honest-counting fix and the gc-cpu-frac metric swap; the earlier
run's numbers are superseded wholesale.

### Results — pipeline only (no network in the path), lines/s

| scenario | workers=1 | workers=2 | workers=4 | workers=8 |
|---|---|---|---|---|
| match-every | 23533 | 22021 | 22180 | 21797 |
| match-every-evicting | 23137 | 21745 | 21738 | 21766 |
| match-never | 206394 | 223569 | 278119 | 399678 |
| match-never-evicting | 198983 | 212887 | 263770 | 387993 |

### Results — ingest-inclusive (real loopback syslog socket), lines/s

| scenario | workers=1 | workers=2 | workers=4 | workers=8 |
|---|---|---|---|---|
| tcp/match-every | 20447 | 19151 | 19025 | 19150 |
| tcp/match-every-evicting | 20309 | 18972 | 19079 | 18999 |
| tcp/match-never | 150084 | 174339 | 213610 | 222615 |
| tcp/match-never-evicting | 144402 | 167622 | 208602 | 215464 |
| unixgram/match-every | 22236 | 20120 | 19718 | 19452 |
| unixgram/match-every-evicting | 22031 | 19857 | 19509 | 19802 |
| unixgram/match-never | 169263 | 188596 | 242357 | 359897 |
| unixgram/match-never-evicting | 167792 | 182678 | 236715 | 346913 |

### Raw results (means of 3 runs; spread = min–max of lines/s)

| benchmark | lines/s | min | max | ns/op | allocs/op | B/op | evictions/op | gc-cpu-frac |
|---|---|---|---|---|---|---|---|---|
| BenchmarkPipeline/match-every/workers=1 | 23533 | 23207 | 23815 | 42498 | 111 | 5901 | 0.000 | 0.0106 |
| BenchmarkPipeline/match-every/workers=2 | 22021 | 21907 | 22235 | 45413 | 114 | 6063 | 0.000 | 0.0097 |
| BenchmarkPipeline/match-every/workers=4 | 22180 | 22064 | 22389 | 45087 | 114 | 6066 | 0.000 | 0.0102 |
| BenchmarkPipeline/match-every/workers=8 | 21797 | 21676 | 21873 | 45878 | 114 | 6074 | 0.000 | 0.0100 |
| BenchmarkPipeline/match-every-evicting/workers=1 | 23137 | 22568 | 23695 | 43239 | 112 | 5958 | 0.482 | 0.0110 |
| BenchmarkPipeline/match-every-evicting/workers=2 | 21745 | 21297 | 22113 | 45998 | 115 | 6125 | 0.481 | 0.0105 |
| BenchmarkPipeline/match-every-evicting/workers=4 | 21738 | 21696 | 21810 | 46002 | 116 | 6132 | 0.481 | 0.0106 |
| BenchmarkPipeline/match-every-evicting/workers=8 | 21766 | 21493 | 22211 | 45953 | 116 | 6138 | 0.481 | 0.0106 |
| BenchmarkPipeline/match-never/workers=1 | 206394 | 204484 | 207926 | 4845 | 41 | 2192 | 0.000 | 0.0199 |
| BenchmarkPipeline/match-never/workers=2 | 223569 | 220289 | 225375 | 4473 | 41 | 2202 | 0.000 | 0.0274 |
| BenchmarkPipeline/match-never/workers=4 | 278119 | 274771 | 283304 | 3596 | 41 | 2211 | 0.000 | 0.0391 |
| BenchmarkPipeline/match-never/workers=8 | 399678 | 397192 | 401095 | 2502 | 41 | 2224 | 0.000 | 0.0618 |
| BenchmarkPipeline/match-never-evicting/workers=1 | 198983 | 191626 | 204331 | 5029 | 43 | 2270 | 0.507 | 0.0196 |
| BenchmarkPipeline/match-never-evicting/workers=2 | 212887 | 210885 | 214346 | 4697 | 43 | 2281 | 0.507 | 0.0276 |
| BenchmarkPipeline/match-never-evicting/workers=4 | 263770 | 260609 | 269689 | 3792 | 43 | 2294 | 0.507 | 0.0406 |
| BenchmarkPipeline/match-never-evicting/workers=8 | 387993 | 385632 | 390136 | 2577 | 43 | 2306 | 0.507 | 0.0644 |
| BenchmarkPipelineIngest/tcp/match-every/workers=1 | 20447 | 20181 | 20711 | 48912 | 129 | 8971 | 0.000 | 0.0177 |
| BenchmarkPipelineIngest/tcp/match-every/workers=2 | 19151 | 18989 | 19354 | 52221 | 132 | 9163 | 0.000 | 0.0172 |
| BenchmarkPipelineIngest/tcp/match-every/workers=4 | 19025 | 18745 | 19259 | 52568 | 132 | 9179 | 0.000 | 0.0166 |
| BenchmarkPipelineIngest/tcp/match-every/workers=8 | 19150 | 18996 | 19255 | 52221 | 132 | 9181 | 0.000 | 0.0177 |
| BenchmarkPipelineIngest/tcp/match-every-evicting/workers=1 | 20309 | 19908 | 20819 | 49257 | 130 | 9044 | 0.481 | 0.0171 |
| BenchmarkPipelineIngest/tcp/match-every-evicting/workers=2 | 18972 | 18574 | 19462 | 52728 | 133 | 9236 | 0.481 | 0.0177 |
| BenchmarkPipelineIngest/tcp/match-every-evicting/workers=4 | 19079 | 18980 | 19232 | 52415 | 133 | 9243 | 0.481 | 0.0172 |
| BenchmarkPipelineIngest/tcp/match-every-evicting/workers=8 | 18999 | 18743 | 19343 | 52643 | 133 | 9262 | 0.481 | 0.0179 |
| BenchmarkPipelineIngest/tcp/match-never/workers=1 | 150084 | 148477 | 151922 | 6663 | 58 | 4990 | 0.000 | 0.0475 |
| BenchmarkPipelineIngest/tcp/match-never/workers=2 | 174339 | 171998 | 175734 | 5736 | 58 | 4940 | 0.000 | 0.0617 |
| BenchmarkPipelineIngest/tcp/match-never/workers=4 | 213610 | 212244 | 215520 | 4682 | 58 | 4927 | 0.000 | 0.0731 |
| BenchmarkPipelineIngest/tcp/match-never/workers=8 | 222615 | 218601 | 224689 | 4493 | 59 | 4957 | 0.000 | 0.0788 |
| BenchmarkPipelineIngest/tcp/match-never-evicting/workers=1 | 144402 | 142828 | 146138 | 6926 | 60 | 5080 | 0.507 | 0.0465 |
| BenchmarkPipelineIngest/tcp/match-never-evicting/workers=2 | 167622 | 166521 | 169482 | 5966 | 60 | 4992 | 0.507 | 0.0616 |
| BenchmarkPipelineIngest/tcp/match-never-evicting/workers=4 | 208602 | 207439 | 210476 | 4794 | 60 | 5009 | 0.507 | 0.0750 |
| BenchmarkPipelineIngest/tcp/match-never-evicting/workers=8 | 215464 | 209055 | 219905 | 4643 | 60 | 5053 | 0.507 | 0.0823 |
| BenchmarkPipelineIngest/unixgram/match-every/workers=1 | 22236 | 22052 | 22493 | 44976 | 125 | 8002 | 0.000 | 0.0115 |
| BenchmarkPipelineIngest/unixgram/match-every/workers=2 | 20120 | 19932 | 20287 | 49705 | 128 | 8136 | 0.000 | 0.0105 |
| BenchmarkPipelineIngest/unixgram/match-every/workers=4 | 19718 | 19340 | 20270 | 50736 | 128 | 8153 | 0.000 | 0.0103 |
| BenchmarkPipelineIngest/unixgram/match-every/workers=8 | 19452 | 19259 | 19649 | 51411 | 128 | 8170 | 0.000 | 0.0110 |
| BenchmarkPipelineIngest/unixgram/match-every-evicting/workers=1 | 22031 | 21927 | 22122 | 45392 | 127 | 8060 | 0.481 | 0.0112 |
| BenchmarkPipelineIngest/unixgram/match-every-evicting/workers=2 | 19857 | 19568 | 20238 | 50370 | 130 | 8189 | 0.481 | 0.0103 |
| BenchmarkPipelineIngest/unixgram/match-every-evicting/workers=4 | 19509 | 19292 | 19705 | 51263 | 130 | 8247 | 0.481 | 0.0107 |
| BenchmarkPipelineIngest/unixgram/match-every-evicting/workers=8 | 19802 | 19798 | 19809 | 50500 | 130 | 8236 | 0.481 | 0.0111 |
| BenchmarkPipelineIngest/unixgram/match-never/workers=1 | 169263 | 166883 | 170947 | 5909 | 55 | 4119 | 0.000 | 0.0324 |
| BenchmarkPipelineIngest/unixgram/match-never/workers=2 | 188596 | 187098 | 189526 | 5302 | 55 | 4156 | 0.000 | 0.0397 |
| BenchmarkPipelineIngest/unixgram/match-never/workers=4 | 242357 | 241692 | 243241 | 4126 | 55 | 4203 | 0.000 | 0.0545 |
| BenchmarkPipelineIngest/unixgram/match-never/workers=8 | 359897 | 355835 | 362547 | 2779 | 56 | 4304 | 0.000 | 0.0841 |
| BenchmarkPipelineIngest/unixgram/match-never-evicting/workers=1 | 167792 | 166207 | 170263 | 5960 | 57 | 4203 | 0.507 | 0.0320 |
| BenchmarkPipelineIngest/unixgram/match-never-evicting/workers=2 | 182678 | 181065 | 184704 | 5475 | 57 | 4251 | 0.507 | 0.0407 |
| BenchmarkPipelineIngest/unixgram/match-never-evicting/workers=4 | 236715 | 235436 | 237506 | 4224 | 57 | 4306 | 0.507 | 0.0551 |
| BenchmarkPipelineIngest/unixgram/match-never-evicting/workers=8 | 346913 | 345918 | 348268 | 2883 | 57 | 4405 | 0.507 | 0.0841 |

### Flatten points (named)

- **match-every saturates at workers = 1**: 23.5k lines/s at one
  worker, 21.8k at eight (−7% — workers never help). Identical under
  both cache caps and both ingest modes (~19–23.5k everywhere).
- **match-never has no flatten point within 1–8 workers** (still
  climbing at workers = 8: 399.7k, 1.9× the one-worker rate) but
  scales strongly sublinearly — eight workers buy 1.9×, and workers = 2
  adds only 8%.
- **tcp/match-never flattens at workers = 4** (213.6k → 222.6k, +4.2%
  for a doubling): the tcp ingest path becomes the ceiling.
- unixgram/match-never mirrors the no-ingest curve ~10% lower (359.9k
  at workers = 8), still rising at 8.

### Allocs, GC and eviction notes

- allocs/op: 41–43 (match-never) vs 111–116 (match-every): the
  Trigger/report path adds ~70 allocs and ~3.7 KB per line (sqlite
  upsert + JSON body marshal). Ingest adds 14–18 allocs and 2–3 KB per
  line (tcp 129–133, unixgram 125–130 in match-every).
- gc-cpu-frac (the GC's share of total CPU capacity,
  Δ`/cpu/classes/gc/total` ÷ Δ`/cpu/classes/total`): 0.010–0.011 in
  the write-bound match-every runs; 0.020 → 0.062 in match-never as
  workers go 1 → 8 (78–83 GC cycles per ~1 s measurement at workers =
  1, 476–528 at workers = 8), reaching 0.084 in
  unixgram/match-never{,-evicting}/workers=8. GC CPU share rises with
  worker count within one scenario. (The code-review pass replaced the
  earlier gc-pause-frac — STW-only share of wall time — with this
  genuine GC CPU share.)
- Evicting cap churns ~0.48–0.51 evictions per line (≈ one eviction per
  two cache updates) yet costs only 0–4% throughput vs the roomy cap —
  eviction is cheap in this corpus; the tracker state, not the cache,
  is what the write path dominates.

### `/stats` cross-check (recorded run, workers = 8)

- match-every: received = parsed = 26,475, dropped = 0, cache gets =
  52,950 (= 2/line: filesize + tracker), misses = 508, evictions = 0,
  size = 508.
- match-never: received = parsed = 475,478, dropped = 0, gets =
  950,956 (= 2/line), size = 508 of cap 65,536, evictions = 0.
- match-never-evicting: 467,581 lines, gets = 935,162, misses =
  237,380, evictions = 237,154 (0.507/line), size = 226 of cap 256.
- In every one of the 48 recorded runs: received == parsed == lines
  fed, dropped == 0.

### Variance

Pipeline-only runs (fixed corpus, frozen clock): spread (max−min)/mean
≤ 6.4% over 3 runs (median 2.0%). Real-socket runs: ≤ 5.0% (median
2.0%) — the socket path's timing noise cannot be removed inside
`go test`; these numbers are reported as measurements, never asserted.

### Observations on H2/H4/H5 (verdicts are ticket 04's)

- **H2 (`progress.bump` serializes workers)** — match-never's curve is
  consistent with a global per-line cost workers cannot overlap (8
  workers buy only 1.9× on the no-network path), but two shared
  suspects rise in lockstep: gc-cpu-frac grows 0.020 → 0.062 with
  workers, and the DistZipf corpus sends ~16% of events to one
  tracker-cache key (and one filesize key) per line — hot-shard
  contention (H3's shape) at the same time. No attribution here; the
  profiles in ticket 04 should separate bump vs GC vs shard mutex.
- **H4 (sqlite upserts serialize the match path)** — strongly
  consistent: match-every is completely flat across workers while the
  identical-shape match-never scales 1.9×, and the per-line delta
  between the two at workers = 1 is ~38 µs of the ~42 µs/op (~89%) —
  the single-connection upsert (ADR 0007) is essentially the entire
  match-path cost and its saturation ceiling. Verdict left to ticket 04.
- **H5 (unbuffered `lines` channel couples ingest to workers)** —
  ingest-inclusive throughput never exceeds the no-ingest pair at the
  same scenario/workers. The gap is small when the pipeline is
  write-bound (match-every: ~19–22k vs 21.8–23.5k) but large in the
  fast path (tcp/match-never/workers=8: 222.6k vs 399.7k, −44%;
  unixgram 359.9k, −10%), and tcp/match-never flattens at workers = 4
  where the no-ingest curve is still climbing — ingest (go-syslog
  framing + channel handoff) becomes the ceiling before the pipeline
  does. Verdict left to ticket 04.

Reproduce: `go test -run '^$' -bench 'BenchmarkPipeline' -benchmem
-count=3 ./internal/app` (or `make bench-pkg PKG=./internal/app` for
the whole package including ticket 02's microbenchmarks).
