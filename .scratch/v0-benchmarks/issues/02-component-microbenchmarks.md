# 02 — Component microbenchmarks (spec Phase 1)

Type: task
Status: ready-for-agent
Depends on: 01

Benchmark each hot-path stage in isolation, beside its code in
`_test.go` files (spec: Phase 1 table).

## Scope

- `BenchmarkParse` (`infra/parse/nginx`): ns/op, B/op, allocs/op for
  each line shape. Hypothesis H1.
- `BenchmarkFilterMatch` (`domain/filter`): leaf filter types plus
  realistic chains of 1/10/100 rules, match and no-match paths. H6.
- `BenchmarkStoreUpdate` / `BenchmarkStoreUpdateParallel`
  (`infra/cache/memory`): sequential and `RunParallel`, uniform vs
  Zipfian vs hot-key distributions, cap sized so evictions do not skew
  the steady state (plus one deliberately evicting variant). H3.
- `BenchmarkEvaluate` (`domain/evaluation`): full chain evaluation over
  pre-parsed events with the memory store and an in-memory report sink,
  and a variant with the sqlite sink to expose write-path cost. H4, H6.
- `BenchmarkReportUpsert` (`infra/persistence/sqlite`): insert vs
  update-over-existing, `:memory:` vs file. H4.
- `BenchmarkReportsList` (`infra/httpapi`): 10/1k/10k rows. Read path.
- `BenchmarkProgressBump` parallel (`app`): the per-line bookkeeping
  contention alone. H2.

## Done when

- All benchmarks run under `make bench`, each reports ns/op with
  `-benchmem` numbers, and results for the spec table are recorded in
  this file under `## Answer`.

## Answer

All Phase 1 benchmarks ship beside their code as `*_bench_test.go`
files. Per the domain lint, the in-package `BenchmarkEvaluate`
(`domain/evaluation`) runs over its own stub TrackerCache/ReportSink
ports, and the variants with the real memory store and the sqlite sink
live in `internal/app/evaluate_bench_test.go`; `BenchmarkProgressBump`
is in `internal/app/bookkeeping_bench_test.go`. Fixture decisions
affecting interpretation: fixed wall clock everywhere, zerolog.Nop()
for the store (eviction log rendering excluded), evaluation event times
advance one second per op (cycled timestamps freeze the leaky bucket's
LastUpdate and would let the match-never fixtures creep into
overflow — pinned by `TestBenchChainsMatchTheirNames` and
`TestEvaluateBenchScenarios`), report-rule fixtures are single-rule
chains (a report rule is terminal), and the sqlite insert variant hands
out pre-generated distinct targets with the timer stopped.

Measured with `make bench` (go1.27.0, linux/amd64, Intel Core Ultra 9
185H, default GOMAXPROCS=22, default benchtime, single run — the
-count=10 benchstat hygiene is ticket 04's).

### Measured (ns/op, B/op, allocs/op)

```
BenchmarkParse/minimal-22          1831 ns/op     696 B/op   23 allocs/op   546231 lines/s
BenchmarkParse/full-22             2931 ns/op    1544 B/op   32 allocs/op   341227 lines/s
```

```
BenchmarkFilterMatch/leaf/remote-addr/match-22      4.366 ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/leaf/remote-addr/no-match-22   4.194 ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/leaf/method/match-22           3.270 ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/leaf/method/no-match-22        1.334 ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/leaf/path/match-22             3.493 ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/leaf/path/no-match-22          2.977 ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/leaf/path-prefix/match-22      2.626 ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/leaf/path-prefix/no-match-22   3.178 ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/leaf/path-suffix/match-22      3.672 ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/leaf/path-suffix/no-match-22   3.672 ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/leaf/path-keyword/match-22     4.500 ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/leaf/path-keyword/no-match-22  5.579 ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/leaf/agent/match-22            2.665 ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/leaf/agent/no-match-22         1.363 ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/leaf/agent-keyword/match-22    3.769 ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/leaf/agent-keyword/no-match-22 6.362 ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/leaf/status/match-22           0.951 ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/leaf/status/no-match-22        1.007 ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/leaf/status-class/match-22     1.254 ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/leaf/status-class/no-match-22  1.287 ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/leaf/sent-at-least/match-22    1.028 ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/leaf/sent-at-least/no-match-22 1.069 ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/leaf/sent-at-most/match-22     1.034 ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/leaf/sent-at-most/no-match-22  1.083 ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/chain/1-rules/match-22         15.00 ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/chain/1-rules/no-match-22      13.19 ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/chain/10-rules/match-22       128.5  ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/chain/10-rules/no-match-22    121.1  ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/chain/100-rules/match-22     1213    ns/op   0 B/op   0 allocs/op
BenchmarkFilterMatch/chain/100-rules/no-match-22  1144    ns/op   0 B/op   0 allocs/op
```

```
BenchmarkStoreUpdate/uniform-22                 79.57 ns/op    32 B/op   1 allocs/op
BenchmarkStoreUpdate/zipf-22                    69.07 ns/op    32 B/op   1 allocs/op
BenchmarkStoreUpdate/hot-22                     59.60 ns/op    32 B/op   1 allocs/op
BenchmarkStoreUpdate/evicting-22               170.8  ns/op   171 B/op   3 allocs/op
BenchmarkStoreUpdateParallel/uniform-22         82.00 ns/op    32 B/op   1 allocs/op
BenchmarkStoreUpdateParallel/zipf-22            97.68 ns/op    32 B/op   1 allocs/op
BenchmarkStoreUpdateParallel/hot-22            211.8  ns/op    32 B/op   1 allocs/op
BenchmarkStoreUpdateParallel/evicting-22       163.0  ns/op   172 B/op   3 allocs/op
```

```
BenchmarkEvaluate/match-every-22           (domain, stub ports)         661.8 ns/op    796 B/op   19 allocs/op   1511087 lines/s
BenchmarkEvaluate/match-never-22           (domain, stub ports)         396.3 ns/op    446 B/op   13 allocs/op   2523127 lines/s
BenchmarkEvaluateMemory/match-every-22     (memory store, in-mem sink)  1437   ns/op   1034 B/op   25 allocs/op    696135 lines/s
BenchmarkEvaluateMemory/match-never-22                                 717.0 ns/op    461 B/op   13 allocs/op   1394614 lines/s
BenchmarkEvaluateSQLite/match-every-22     (memory store, sqlite sink) 114536 ns/op  12349 B/op  239 allocs/op      8731 lines/s
BenchmarkEvaluateSQLite/match-never-22                                 730.3 ns/op    461 B/op   13 allocs/op   1369310 lines/s
```

```
BenchmarkReportUpsert/memory/insert-22   30240 ns/op   2799 B/op   53 allocs/op
BenchmarkReportUpsert/memory/update-22   24587 ns/op   2796 B/op   54 allocs/op
BenchmarkReportUpsert/file/insert-22     74660 ns/op   2788 B/op   53 allocs/op
BenchmarkReportUpsert/file/update-22     60797 ns/op   2797 B/op   54 allocs/op
```

```
BenchmarkReportsList/10-rows-22      80377 ns/op     52329 B/op     304 allocs/op
BenchmarkReportsList/1k-rows-22    6981978 ns/op   5378150 B/op   26139 allocs/op
BenchmarkReportsList/10k-rows-22  64198207 ns/op  59130448 B/op  260207 allocs/op
```

```
BenchmarkProgressBump/serial-22      49.06 ns/op   112 B/op   1 allocs/op   20384935 lines/s
BenchmarkProgressBump/parallel-22  106.9  ns/op   112 B/op   1 allocs/op    9354212 lines/s
```

### Reading (observations only — verdicts belong to ticket 04)

The numbers speak to every hypothesis except H5 (ingest handoff,
ticket 03's), most sharply to H4 and H2: a single sqlite report upsert
costs 25µs (`:memory:`) to 75µs (file), so with rules matching on every
event the sqlite-sink evaluation runs 114.5µs/event against 0.73µs when
no rule ever matches — the write path is two to three orders of
magnitude above every other per-line stage combined. `progress.bump` costs 49ns
and one channel allocation per line serial, and parallel throughput
(9.4M lines/s) lands *below* the serial rate (20.4M lines/s) as all
workers serialize on the global mutex and per-line channel churn — the
shape H2 predicts for a flattening worker-scaling curve. H1's
allocation claim is confirmed outright: parse allocates 23–32 objects
and 0.7–1.5KB per line (1.8µs minimal / 2.9µs full, ~60% more for the
full line shape), and `Store.Update` allocates exactly one 32B object
per call (the `ns+"\x00"+key` concat). H3 shows in the contention
numbers: hot-key parallel update is 3.5× its serial cost (single-shard
mutex plus the shared stats atomic — even uniform keys gain nothing
from 22 goroutines), and forced eviction roughly doubles the per-call
cost with two more allocations. H6's O(rules) growth is clean (chains
cost ~12ns/rule, 1.2µs at 100 rules; leaves 1–6ns with zero
allocations) but negligible next to parse and store costs at realistic
rule counts. The read path scales at ~6–8µs and ~26 allocs per row
(10 rows ≈ 80µs, 10k rows ≈ 64ms).

**Code-review pass note** — the Evaluate sub-benchmarks were renamed
(`fires`/`never-fires` → `match-every`/`match-never`, GLOSSARY:
Match/Trigger) and their numbers above were refreshed by the
code-review pass; every other recorded block is unchanged (those
benchmarks kept their names, semantics and results). The pass also
completed the stage coverage this table left open — measured the same
way (single run, `-benchmem`, ns/op · B/op · allocs/op):
`BenchmarkIngestForward/{tcp,unixgram}` (syslog Source run loop, no
evaluation) 1600 · 3205 · 17 and 1847 · 1909 · 14;
`BenchmarkEnrich` (domain, stub cache) 74.77 · 168 · 3 and
`BenchmarkEnrichMemory` (real memory store) 180.3 · 200 · 4; the sweep
cadence `BenchmarkStoreSweepExpired/{live,expiring}` 2453 · 0 · 0 and
2751 · 0 · 0, `BenchmarkStoreStatistics` 1950 · 0 · 0,
`BenchmarkReportDeleteExpired/{live,expiring}` 3241 · 136 · 6 and
63435 · 136 · 6. See `findings.md`'s coverage map for the stage →
benchmark mapping.
