# 01: Prefactor — one report lifecycle module

**What to build:** Every report mutation — the Trigger write, report
deletion through the API, and the periodic expiry sweep — flows through
one module (the report service) instead of the write path and the
delete/sweep paths reaching into the report repository independently.
Nothing operator-visible changes: the report document, deletion
semantics and expiry semantics are exactly as before. This is the seam
the live-report state of ticket 03 hangs on ("make the change easy,
then make the easy change").

**Blocked by:** None (can start immediately)

**Status:** resolved

- [x] Every write, delete and expiry deletion of reports passes through
      the report service; no caller mutates report rows around it
- [x] The report service's interface coherently covers the Trigger
      write, delete-by-filter and delete-expired; the API and the
      sweeper call it, not the repository directly
- [x] The report repository adapter keeps its own contract intact
- [x] No behavior change anywhere: the full suite — including the daemon
      end-to-end tests and the repository contract tests — is green
      under the race detector

## Answer

**Done:** report mutation now has one funnel — `report.Service` exposes
`Trigger`, `List`, `Delete(ctx, Query) (int, error)` and
`DeleteExpired(ctx, now) (int, error)` (`internal/domain/report/report.go`),
and every production mutation goes through it:

- Trigger write: unchanged (`evaluation → ReportSink.Trigger →
  Service.Trigger`), still the only write path.
- API delete-by-filter: `Daemon.New` passes the service, not the raw
  repository, to `httpapi.New` (`internal/app/daemon.go`); the API's
  reads and deletes go through `Service.List`/`Service.Delete`.
- Sweeper: `Daemon.sweepOnce` calls `Service.DeleteExpired`
  (`internal/app/daemon.go`), keeping its `(int, error)` shape so the
  e2e tests' direct `d.sweepOnce(ctx)` driving is untouched.

Key facts:

- `Delete`/`DeleteExpired` return the repository's counts and errors
  **unwrapped** — `ErrUnfiltered` and the adapter's error strings are
  operator-visible (sweeper logs them) and must stay identical.
  `Trigger` keeps its existing `"trigger report: %w"` wrap.
- The `Repository` port and the sqlite adapter are byte-identical; the
  repository's own contract tests/benches keep direct repository and
  raw-SQL access (that *is* the repository's contract surface), and the
  substituted-store seam (`withStore`/`blockingStore`) still wedges
  writes because the service wraps whatever store is injected.
- `Daemon.repo` stays as the raw store for `Close()` and the direct
  reads in tests/benches (`d.repo.List`); `httpapi_bench_test.go`
  fixture seeding now writes through `report.NewService(repo).Trigger`
  so nothing outside the repository's own tests mutates rows around the
  service.
- New prior art the notes flagged as missing (test-harness.md §3):
  `internal/domain/report/report_test.go` — the report service over a
  plain stub repository (table tests, no framework), pinning the
  delegation contract ticket 03's re-arm hooks hang on.
- Zero operator-visible change: report document, deletion counts,
  `ErrUnfiltered`, expiry semantics identical. `make test`
  (`go test -race -count=1 ./...`) green, including the daemon e2e and
  repository contract suites.

Context: spec `.scratch/v0-hot-path/spec.md` (Implementation Decisions:
"the delete paths and the periodic sweeper must inform the live-report
set"); exploration notes `/tmp/bandage-v0-hot-path-notes/report-lifecycle.md`
§"What ticket 01 must change"; the seam is exactly where ticket 03's
live-report set attaches (`Trigger`, `Delete`, `DeleteExpired`).
