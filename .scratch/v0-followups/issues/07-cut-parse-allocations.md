# 07 — Cut parser allocations (generic map + per-field re-parse)

Type: task
Status: needs-triage
Evidence: `.scratch/v0-benchmarks/findings.md` § Ranked bottlenecks #2,
H1 verdict (confirmed).

`nginx.Parser.Parse` is 83% of fast-path per-line CPU and 75% of all
allocated objects. `encoding/json` into `map[string]json.RawMessage`
is 87% of Parse; `reflect.mapassign_faststr0` alone is 49% of the
2.8GB/1M-lines allocated. 32 allocs and 1.5KiB per full line (23 /
696B minimal), and the resulting GC pressure grows with worker count
(gc-pause-frac 1.2% → 4.7% from 1 → 8 workers).

## Scope

- Replace the generic-map decode + per-field re-parse (time, IP,
  method, path, status, sent, agent) with a lower-allocation decode:
  struct-based `json.Unmarshal`, `json.RawMessage` field lookup without
  map growth/reflect, or an equivalent zero-mid-layer scan.
- Preserve parse semantics exactly: same accept/drop conditions, same
  `Event` values (including the optional agent and the $msec time
  fraction), same error behavior. The fixture contract is pinned by
  `TestCorpusLinesParseToTheirEvents` and the nginx package tests.

## Done when

- `BenchmarkParse/*` shows a measured drop in ns/op, B/op and
  allocs/op (benchstat vs the committed baseline), with no test
  behavior change.
- `benchstat .scratch/v0-benchmarks/baseline/bench-count10.txt new.txt`
  for `Parse/*` and `Pipeline/match-never/*` recorded in the
  PR/answer.
