# 01 — Benchmark harness and fixtures

Type: task
Status: resolved

Build the shared scaffolding every benchmark in this effort stands on.

## Scope

- Deterministic nginx-JSON line corpus as `_test.go` fixtures (shared
  helper file per package that needs it, or one small exported-in-test
  helper set in `bandage/internal/app`):
  - line shapes: minimal (required fields only) vs. full (agent, host,
    server, unknown fields present);
  - key distributions: uniform, Zipfian paths and client IPs, and a
    hot-path/hot-IP pair that forces single-shard cache contention;
  - parseable-by-construction (no accidental drops).
- Bench helpers: fixed seed, `testing.B.Loop()` usage, `b.ReportMetric`
  for lines/sec where meaningful, no per-iteration fixture rebuilding
  outside the timer.
- `make bench` (whole suite with `-benchmem`) and `make bench-pkg
  PKG=...` targets; a short `docs`-free note in the Makefile on running
  `-count=10` + benchstat.

## Done when

- `make bench` runs green over the (initially small) suite on a clean
  checkout, and fixtures are reused by all later tickets.

## Answer

Built the shared benchmark harness in `bandage/internal/bench` (imported only
by tests/benchmarks, never by production code):

- **Fixture corpus** (`bandage/internal/bench/corpus.go`): `bench.NewCorpus(seed,
  shape, dist, n)` pre-generates `n` raw nginx-JSON access-log lines and
  the `domain.Event`s they parse to. Line shapes: `ShapeMinimal`
  (required fields only; event has no agent) vs `ShapeFull` (agent,
  host, server, duration plus an unknown field). Key distributions over
  256-entry path and client-IP pools: `DistUniform`, `DistZipf` (weight
  1/(rank+1) via inverse-transform over a fixed CDF), and `DistHot`
  (every line carries the `HotPath`/`HotIP` pair — one tracker-cache
  key, hence single-shard contention; the pair is also the Zipfian
  head). Generation is deterministic by construction: a self-contained
  splitmix64 PRNG, so the same seed yields byte-identical corpora on
  every Go version and platform.
- **Parseable-by-construction**: each fixture event content renders
  both the raw line and its Event;
  `TestCorpusLinesParseToTheirEvents` pins that
  `nginx.Parser.Parse(Line(i)) == Event(i)` for every shape ×
  distribution, so no fixture line can drop and the two renderings
  cannot drift.
- **Bench helpers** (`bandage/internal/bench/helpers.go`): fixed `bench.Seed`;
  `Line`/`Event` cycle any non-negative index so benchmarks build the
  corpus once before their `b.Loop()` loop and never rebuild fixtures
  inside the timed region; `bench.ReportLinesPerSec(b, lines)` reports
  `lines/s` through `b.ReportMetric` (where one op = one raw line).
- **Correctness tests** (`bandage/internal/bench/*_test.go`): splitmix64
  reference vectors, determinism per seed (and divergence across
  seeds), index cycling, minimal/full JSON key sets, documented
  uniform/Zipf/hot distribution behavior, hot-pair → single tracker
  key, `linesPerSec` math, and the stable sub-name strings. One
  harness benchmark (`BenchmarkCorpusBuild`) keeps `make bench`
  non-empty until tickets 02–04 add the real suite.
- **Make targets**: `make bench` runs the whole suite with `-benchmem`;
  `make bench-pkg PKG=...` runs one package (usage error when PKG is
  unset). The Makefile carries the short note on `-count=10` + benchstat
  comparisons. Note the recipes escape the dollar as `^$$` so make
  passes `-run=^$` through to `go test`.

Verified: `make test` (with `-race`) green, `go test -run=^$ -bench=.
-benchtime=1x ./...` smoke green, `make bench` and `make bench-pkg`
run green over the initial harness benchmark.

For later tickets: construct fixtures with
`bench.NewCorpus(bench.Seed, bench.ShapeFull, bench.DistZipf, n)` and
cycle `corpus.Line(i)` / `corpus.Event(i)` with a monotone counter
inside `b.Loop()`; report `bench.ReportLinesPerSec` where one op is one
log line.

Implemented on integration branch `feat/v0-benchmarks` (merge commit
`50215b8`; cross-ticket code-review fixes through `f6e31bd`). Context:
spec `../spec.md`.
