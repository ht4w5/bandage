# 09 — De-globalize per-line progress bookkeeping (`progress.bump`)

Type: task
Status: needs-triage
Evidence: `.scratch/v0-benchmarks/findings.md` § Ranked bottlenecks #6,
H2 verdict (partial).

`progress.bump()` costs 48.4ns + 112B + 1 alloc per line behind one
global mutex (`close(ch)` + `make(chan)` per line). Parallel
`BenchmarkProgressBump` throughput *falls* below serial (9.3M vs
20.7M lines/s at 22 goroutines), it is the largest single attributed
site of contended-mutex delay at workers = 8 (25.5%), and its channel
churn is 2.7% of allocated objects / 5.2% of allocated space. It is
not today's saturation ceiling (~20M lines/s serialization limit vs
~400k observed) but it is pure per-line waste on every path.

## Scope

- Replace the per-line channel broadcast with a cheaper wake
  mechanism (e.g. atomic counter + `sync.Cond`, or amortized wakeups)
  while preserving semantics: `waitProcessed(ctx, n)` returns once n
  lines are processed and never polls or sleeps; `/stats` counters are
  unaffected.
- The production hot path must no longer allocate per line for
  bookkeeping.

## Done when

- `BenchmarkProgressBump/*` shows no per-line allocation and a
  parallel rate at or above the serial rate; mutex/block profiles no
  longer attribute meaningful delay to `progress.bump`.
- `benchstat .scratch/v0-benchmarks/baseline/bench-count10.txt new.txt`
  for `ProgressBump/*` and `Pipeline/*` recorded in the PR/answer;
  `make test` green (with -race), including the workerpool shutdown
  and drain tests.
