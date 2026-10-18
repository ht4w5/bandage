# 03: Suppress the report write while a report is alive

**What to build:** One report write per (rule, Target) per report
lifetime. While a report for (rule, Target) is alive, further Triggers
for it write nothing — the rule keeps matching and all its actions keep
running, and the tracker still empties — but the report is not written
again (ADR 0008). Deleting or expiring the report re-arms writing: the
next Trigger writes (immediately for tracker-less rules, after a fresh
episode for tracker rules). Reasons keep accruing across rules, and
flagged Targets' events keep enriching and feeding other trackers —
analysis stays complete, bandage stays an analyzer.

**Blocked by:** 01 (Prefactor — one report lifecycle module)

**Status:** resolved

- [x] While a report for (rule, Target) is alive, further Triggers for
      it write nothing; the rule matches and its actions run
- [x] Each such Trigger still empties the rule's tracker (episode
      cadence preserved while the write is silent)
- [x] A tracker-less report rule writes at most one report per
      (rule, Target) while it is alive
- [x] Suppression is per (rule, Target): one rule's report never
      suppresses another rule's write, so reasons accrue across rules
- [x] Deleting a report re-arms writing for that (rule, Target)
- [x] Expiry (the sweeper) re-arms writing identically
- [x] A live report's Sample and update time are unchanged
- [x] Flagged Targets' events still enrich Filesize and feed other
      rules' trackers; no event is dropped from analysis
- [x] After a restart, suppression state is rebuilt from the report
      table: alive reports suppress, deleted or expired ones do not
- [x] Concurrent workers produce at most one write per live report
- [x] The report document served by the API keeps its exact shape
- [x] Full suite green under the race detector

## Answer

While a report for (rule, Target) is alive its write is suppressed — one
write per (rule, Target) per report lifetime — and deleting or expiring
the report re-arms writing. Changed:

- `internal/domain/report/report.go`: the Service owns the live-report
  set (in-memory map keyed (rule, Target) → expiry; the report table is
  the correctness source). `Trigger` suppresses the write while the
  report is alive and returns nil — the report action completed, so the
  tracker still empties (ticket 02's hand-off; ADR 0008: reset on every
  Trigger). The key is reserved before the write, so concurrent Triggers
  for one (rule, Target) produce at most one write (spec story 14); a
  failed write releases the reservation and the next Trigger retries
  (story 5). Aliveness is `expires_at >` the Trigger's wall time
  (`rec.UpdatedAt`): a report is alive until expiry or deletion
  (GLOSSARY **Report**), so an expired report stops suppressing even
  before the sweeper runs — restart re-derivation and steady state agree.
  `Delete`/`DeleteExpired` drop the matching keys (re-arm, stories 9/10);
  `Rebuild(ctx, now)` supplants the set from `List` at startup (story
  13).
- `internal/app/daemon.go`: `Start` rebuilds before the workers start.
- `internal/app/rules.go`: tracker-less `report` actions are legal (the
  "report requires a tracker" gate removed — the spec decides tracker-
  less rules stay legal, stories 12/29); suppression alone bounds their
  writes. The evaluation traversal is untouched beyond this.
- `internal/infra/httpapi/httpapi.go`: the delete-promise doc names the
  re-arm nuance. The report document shape is unchanged.

Tests: `internal/domain/report/report_test.go` (suppression and re-arm
rules over the stub repository: per-(rule, Target) grain, expiry, the
delete/expiry re-arms, failed-write retry, Rebuild derivation);
`internal/app/suppress_test.go` (daemon seam: frozen Sample/update time
while actions keep running, tracker emptied on suppressed Triggers,
tracker-less tripwire per Target, per-rule grain with reasons accruing,
delete/expiry re-arm, expiry alone re-arming pre-sweep, restart rebuild
(alive suppress; deleted and expired do not), 16 concurrent events under
4 workers landing exactly one Upsert (counting store), a flagged Target
still enriching Filesize and feeding another rule's tracker with nothing
dropped, replay rule at (rule, Target) grain). Re-modeled, intent kept:
`TestE2EReportUpsertIdentity`, `TestE2EExpiresAtRecomputedOnWrite` (was
`…RefreshedUnconditionally` — a live report is never refreshed now),
`TestE2EEvictedBucketAccumulatesFresh`, `TestE2EFilterGatesTracker`,
`TestE2ETriggerOncePerVolumeOfTraffic`,
`TestE2EConcurrentTriggersLeaveClearedBucket`,
`TestWorkerPoolConcurrentEventsOneTarget`, and rules_test's "report
without tracker rejected" case → accepted.

Key facts: writes stay synchronous; suppression lives in report.Service
(domain-purity lint green — stdlib only). A write over an
expired-but-stored row keeps the row's created_at (upsert identity
unchanged — ticket 04's contract). The Trigger's wall time is
`rec.UpdatedAt`, so unit callers must set it on the report.

Context pointers: GLOSSARY **Trigger** and **Report** ("alive until
expiry or deletion"); ADR 0008 (suppression gates only the write —
reset on every Trigger), ADR 0007 (relaxed-ordering pool); spec
Implementation Decisions "Suppression lives in the report write path" +
stories 2–6, 9–15, 17; notes /tmp/bandage-v0-hot-path-notes/
(report-lifecycle.md, test-harness.md).

Implemented on integration branch `feat/v0-hot-path` (merge commit
`61d1423`; cross-ticket code-review fixes through `78386ca` — contention
handoff so stories 4/5/14 all hold). Context: spec `../spec.md`,
foundations `01-prefactor-report-lifecycle.md` /
`02-trigger-empties-tracker.md`.
