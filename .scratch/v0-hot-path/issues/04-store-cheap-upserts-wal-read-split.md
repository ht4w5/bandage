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

**Status:** resolved

- [x] Upsert preserves a report's created_at on update without reading
      the row first, and reuses prepared statements
- [x] File databases open in WAL with synchronous=NORMAL; a written
      report survives a process restart (verified by reopening the
      database)
- [x] Writes keep the single write connection; write-ordering
      determinism is unchanged
- [x] API reads run on separate connections: a report query served
      during an in-flight write does not wait for it (and the write does
      not wait for the query), demonstrable at the daemon seam
- [x] Test databases (in-memory) keep working under the split
      connections (shared-cache URI or single-connection fallback)
- [x] Upsert and query costs recorded from the benchmark suite
      (ns/op, B/op, allocs/op before/after)
- [x] Full suite green under the race detector

## Answer

**What changed** (`34dc1ee`, `internal/infra/persistence/sqlite/sqlite.go`
rewritten; tests in `sqlite_test.go`, `internal/app/readpath_test.go`):

- **Cheap upserts**: `Upsert` is now one prepared statement
  (`upsertSQL`, prepared once in `Open`, reused via `*sql.Stmt`) — the
  pre-read `SELECT created_at` and the surrounding transaction are
  gone; created_at is preserved by its absence from the `ON CONFLICT …
  DO UPDATE` set. Guard: `TestUpsertPreservesCreatedAtOnUpdate`.
- **WAL**: file databases run `PRAGMA journal_mode=WAL` +
  `PRAGMA synchronous=NORMAL` on the write connection (ADR 0009).
  Guards: `TestFileDatabaseRunsInWALSynchronousNormal`,
  `TestWrittenReportSurvivesReopen` (close + reopen the database).
- **Split read path**: `ReportRepository{write, read, upsert}` — writes
  (Upsert/Delete/DeleteExpired) keep `write` with `SetMaxOpenConns(1)`
  (ADR 0007; `TestConcurrentUpsertsAreDeterministic` unchanged and
  green), `List` runs on `read`, its own pool. `:memory:` uses the
  single-connection fallback (`read == write`) since each connection
  there is a private database (`TestMemoryDatabaseWorksAcrossSplitPaths`;
  the whole daemon e2e suite runs on `:memory:`).

**Benchmark record** (median of 5; `GOMAXPROCS=22 go test -run='^$'
-bench='BenchmarkReportUpsert|BenchmarkReportsList' -benchmem -count=5
-p=1` on go1.27.0 linux/amd64, Core Ultra 9 185H; raw runs at
`/tmp/bench-before-raw.txt`, `/tmp/bench-after-raw.txt`, summaries via
benchstat):

| Benchmark | ns/op before → after | B/op | allocs/op |
|---|---|---|---|
| ReportUpsert/memory/insert | 31,756 → 9,986 (−69%) | 2,790 → 1,585 | 53 → 22 |
| ReportUpsert/memory/update | 25,259 → 4,525 (−82%) | 2,797 → 1,586 | 54 → 22 |
| ReportUpsert/file/insert | 76,420 → 18,240 (−76%) | 2,788 → 1,586 | 53 → 22 |
| ReportUpsert/file/update | 63,394 → 8,653 (−86%) | 2,796 → 1,586 | 54 → 22 |
| ReportsList/10-rows | 83,080 → 79,850 (−4%) | 52,323 → 52,321 | 304 → 304 |
| ReportsList/1k-rows | 7,240,000 → 6,608,000 (−9%) | 5,379k → 5,377k | 26,143 → 26,137 |
| ReportsList/10k-rows | 68,290,000 → 64,970,000 (−5%) | 59.18M → 59.16M | 260,218 → 260,210 |

File cases gain most (WAL + `synchronous=NORMAL` turns the per-commit
fsync into a WAL append); `ReportsList` runs its
`BenchmarkReportsList` on `:memory:` (fallback), so it measures the
read path itself and is unchanged in shape, as expected.

**Key facts**

- Read/write non-interference at the daemon seam (test-harness.md
  `blockingStore` prior art): `internal/app/readpath_test.go`
  `TestQueryDuringInflightWriteDoesNotWait` (write wedged at the store,
  `GET /reports` answers before it lands) and
  `TestWriteDuringInflightQueryDoesNotWait` (query wedged at the store,
  the Trigger's upsert lands regardless). These demonstrate the end-to-end
  property; the discriminating connection-level proof is the repository
  contract pair `TestQueryDoesNotWaitBehindInflightWrite` /
  `TestWriteDoesNotWaitBehindInflightQuery` (`sqlite_test.go`), which
  hold the write/read connection and fail on the old single-connection
  wiring.
- The pre-read removal is externally behavior-identical (the statement
  preserves created_at exactly as the pre-read did), so "cheap" is
  evidenced by the allocs/op and ns/op table above, not a behavior
  test — per spec Testing Decisions ("performance claims verified by
  the benchmark suite itself, not by ad-hoc timing in tests").
- `synchronous` is per connection; only `write` commits, and
  `journal_mode=WAL` is a property of the database file, so the read
  pool needs no pragmas (`sqlite.go` `Open`).
