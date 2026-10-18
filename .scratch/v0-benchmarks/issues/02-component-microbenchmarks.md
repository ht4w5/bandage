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
