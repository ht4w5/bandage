# 01 — Benchmark harness and fixtures

Type: task
Status: ready-for-agent

Build the shared scaffolding every benchmark in this effort stands on.

## Scope

- Deterministic nginx-JSON line corpus as `_test.go` fixtures (shared
  helper file per package that needs it, or one small exported-in-test
  helper set in `internal/app`):
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
