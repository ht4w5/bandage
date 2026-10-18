# 10 — Alloc-free tracker-cache key building (`memory.Store.Update`)

Type: task
Status: needs-triage
Evidence: `.scratch/v0-benchmarks/findings.md` § Ranked bottlenecks #5,
H3 verdict (partial).

Every `Store.Update` allocates one 32B string — the
`ns + "\x00" + key` concat — before hashing it with `fnv.New32a()`.
With two updates per line (filesize + tracker) that is 2 allocs of
64B/line and 7.6% of all allocated objects; the concat is 6% of
fast-path CPU (`runtime.concatstrings` family). Hot-key contention is
already absorbed by the 256 shards (0.7% of mutex delay in the
pipeline; only the forced-single-shard microbench shows 3.6×
slowdown), so the allocation is the part worth fixing.

## Scope

- Compute the shard hash and lookup without materializing `fullKey`
  (hash the namespace and key separately with a combining scheme, or
  use a stack buffer), keeping collision/shard distribution behavior
  equivalent.
- Keep the key space semantics exactly (namespace/key separation must
  remain unambiguous); `Test*` key-sharding tests stay valid.

## Done when

- `BenchmarkStoreUpdate*` reports 0 allocs/op with unchanged ns/op,
  and `Pipeline/match-never/*` B/op/allocs/op drop correspondingly
  (benchstat vs the committed baseline, recorded in the PR/answer);
  `make test` green (with -race).
