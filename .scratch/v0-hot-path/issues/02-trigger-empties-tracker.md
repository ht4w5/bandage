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

**Status:** ready-for-agent

- [ ] A Trigger clears the matched rule's tracker record for the
      match's key — the Target, per (Target, path) for replay trackers —
      once the report action completes without error
- [ ] A failed report write leaves the tracker record untouched, and
      the next matching event retries the report
- [ ] A match whose actions contain no report action never clears the
      tracker (log/goto/stop-only rules accumulate as before)
- [ ] Tracker-less rules are unaffected (nothing to clear)
- [ ] Actions see the Trigger-time tracker reading (pre-reset)
- [ ] Under the relaxed-ordering worker pool (ADR 0007), concurrently
      overflowing events leave the tracker consistent with a cleared
      bucket; live and replayed runs may differ only as ADR 0007 allows
- [ ] Demonstrated end to end at the daemon seam: a continuously
      abusive Target Triggers once per volume of traffic, not per event
- [ ] Full suite green under the race detector
