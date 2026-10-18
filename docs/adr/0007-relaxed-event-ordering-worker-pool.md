# Relaxed event ordering under the worker pool

Events are parsed, enriched and evaluated by N worker goroutines
(`pipeline.workers`, `-w/--workers` override, default `runtime.NumCPU()`)
and leave arrival order behind. Per-key tracker updates stay atomic (the
cache's per-key update callback) and `Record.Accumulate` never decays
backwards, so out-of-order events are tolerated; two concurrently
overflowing events can both trigger `report`, but the write path upserts
per (rule, target), so a duplicate trigger just refreshes the same row.
Spec story 27 is amended accordingly: replaying a log *in order*
reproduces results.

Consequences: `pipeline.workers: 1` is the strict-arrival-order escape
hatch for reproducible runs; live and replayed runs with N workers may
differ marginally in accumulated tracker values.

Amended by ADR 0008: a duplicate trigger is suppressed while the report
is alive — it no longer refreshes the row.
