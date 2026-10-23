# 02: Trigger empties the rule's tracker

**What to build:** A Trigger (a match that ran the rule's report action)
empties the matched rule's tracker for that Target, so a flagged Target
must accumulate a full volume of abuse again before it can Trigger
again — actions run once per accumulation episode instead of per event
while a Target keeps overflowing. A failed report write leaves the
tracker intact, so the next matching event retries the report instead
of losing the detection. (Semantics of record: GLOSSARY **Trigger**, ADR
0008.)

**Blocked by:** None (can start immediately)

**Status:** resolved

- [x] A Trigger clears the matched rule's tracker record for the
      match's key — the Target, per (Target, path) for replay trackers —
      once the report action completes without error
- [x] A failed report write leaves the tracker record untouched, and
      the next matching event retries the report
- [x] A match whose actions contain no report action never clears the
      tracker (log/goto/stop-only rules accumulate as before)
- [x] Tracker-less rules are unaffected (nothing to clear)
- [x] Actions see the Trigger-time tracker reading (pre-reset)
- [x] Under the relaxed-ordering worker pool (ADR 0007), concurrently
      overflowing events leave the tracker consistent with a cleared
      bucket; live and replayed runs may differ only as ADR 0007 allows
- [x] Demonstrated end to end at the daemon seam: a continuously
      abusive Target Triggers once per volume of traffic, not per event
- [x] Full suite green under the race detector

## Answer

A Trigger now empties the matched rule's tracker record for the match's
key, once the report write completes without error. Changed:

- `internal/bandage/evaluation/evaluation.go`: `trigger` (the report
  action) clears the record after `ReportSink.Trigger` returns nil —
  the one traversal change (matching, action dispatch and terminality
  untouched). Key derivation is unified in `matchKey` (Target; per
  (Target, path) for replay) shared by `updateTracker` and the reset.
  A failed write returns before the reset, so the record survives and
  the next matching event retries; tracker-less rules skip the reset.
  Actions keep the pre-reset reading — `matchContext.reading` is
  captured before dispatch.
- The `TrackerCache` port gains `Clear(ctx, ns, key)` beside `Update`
  (documented as the Trigger reset, no-op for absent records),
  implemented in `internal/infra/cache/memory` atomically under the
  shard lock; a clear is not a get/set and never an eviction.
- Tests: eval seam (reset cadence incl. replay per-(Target, path),
  failed-write retry, no-report matches, tracker-less rules, pre-reset
  action reading); memory-store `Clear` contract; daemon seam
  (`internal/app/trigger_test.go`: once per volume of traffic vs per
  event; 24 concurrent overflowing events under 4 workers leaving a
  cleared bucket — the probe of exactly the volume cannot overflow over
  a cleared bucket, per ADR 0007). Tests encoding the old
  accumulate-forever semantics re-modeled to episode semantics keeping
  their intent (`TestE2EReportUpsertIdentity`,
  `TestE2EDeleteDoesNotTouchTrackerState`,
  `TestE2EEvictedBucketAccumulatesFresh`,
  `TestE2EChainFileOrderAndFirstMatchSemantics`,
  `TestE2EFullActionListRunsBeforeTerminality` (topic volume 250 so the
  second traversal proves the double run),
  `TestE2EStatsBuildAndCumulativeCounters` (traffic below volume so the
  reset does not perturb update accounting under 3 workers), and the two
  worker-pool tests in `workerpool_test.go`).

Key facts for later tickets: suppression is NOT here — every Trigger
still writes (row refreshed per episode); ticket 03 gates tracker-less
`report` at the rules loader (left alone) and adds the live-report set,
which must treat a suppressed write as a completed report action (the
reset runs per GLOSSARY/ADR 0008: "reset on every Trigger").

Context pointers: GLOSSARY **Trigger**; ADR 0008 (semantics), ADR 0007
(pool ordering); spec Implementation Decisions + stories 1, 4, 5, 16;
notes /tmp/bandage-v0-hot-path-notes/codebase-map.md §1.

Implemented on integration branch `feat/v0-hot-path` (merge commit
`5e1fff7`; cross-ticket code-review fixes through `78386ca`). Context:
spec `../spec.md`, sibling `03-suppress-live-report-writes.md`, semantics
of record `GLOSSARY.md` **Trigger** and `docs/adr/0008`.
