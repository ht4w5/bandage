# 06 — Batch/decouple report persistence (single-connection upsert)

Type: task
Status: needs-triage
Evidence: `.scratch/v0-benchmarks/findings.md` § Ranked bottlenecks #1,
§ Worker-scaling attribution, H4 verdict (confirmed, dominant).

When rules fire, the single-connection sqlite upsert
(`SetMaxOpenConns(1)`, ADR 0007) is 82–84% of per-line CPU and 62.7%
of all worker blocking time (16.07s ≈ workers × runtime queued on
`DB.conn`). Each trigger costs 31.4µs (`:memory:`) to 75.9µs (file)
plus 53–54 allocs; match-every runs 42.4µs/line vs 4.9µs for the
otherwise identical match-never, and never scales past one worker
(23.6k → 21.9k lines/s from 1 → 8 workers).

## Scope

- Keep ADR 0007's single-connection safety but stop paying one
  transaction per trigger on the worker path: e.g. queue triggered
  reports and flush them in batches from one writer goroutine (batched
  transactions), or otherwise decouple worker threads from the write.
- Preserve report semantics: every Trigger eventually persists exactly
  once; `GET /reports` and the sweeper see consistent data; shutdown
  drains the queue (no lost reports).
- No rule/filter/tracker semantics changes; no new config surface
  beyond what batching genuinely needs (defaults preferred).

## Done when

- match-every pipeline throughput scales with workers (or is bounded
  by a documented new ceiling), and the per-line delta between
  match-every and match-never shrinks by the measured 38µs write cost.
- `make test` green (with -race) including report-exactly-once and
  shutdown-drain tests.
- `benchstat .scratch/v0-benchmarks/baseline/bench-count10.txt new.txt`
  comparison for `Pipeline/match-every/*` and `ReportUpsert` recorded
  in the PR/answer.
