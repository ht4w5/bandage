# 04: Report store — cheap upserts, WAL, split read path

**What to build:** The report store stops wasting work per Trigger and
stops letting reads fight writes. Upserts no longer read the row before
writing it (the upsert statement itself preserves created_at; statements
are prepared once and reused), file databases run in `journal_mode=WAL`
with `synchronous=NORMAL` — commits survive process crashes, losing only
the final moments on power failure (ADR 0009) — writes keep flowing
through the single write connection so ordering stays deterministic
(ADR 0007), and `GET /reports` is served on its own connections so
queries never queue behind upserts.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] Upsert preserves a report's created_at on update without reading
      the row first, and reuses prepared statements
- [ ] File databases open in WAL with synchronous=NORMAL; a written
      report survives a process restart (verified by reopening the
      database)
- [ ] Writes keep the single write connection; write-ordering
      determinism is unchanged
- [ ] API reads run on separate connections: a report query served
      during an in-flight write does not wait for it (and the write does
      not wait for the query), demonstrable at the daemon seam
- [ ] Test databases (in-memory) keep working under the split
      connections (shared-cache URI or single-connection fallback)
- [ ] Upsert and query costs recorded from the benchmark suite
      (ns/op, B/op, allocs/op before/after)
- [ ] Full suite green under the race detector
