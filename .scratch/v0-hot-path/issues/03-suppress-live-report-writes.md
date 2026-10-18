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

**Status:** ready-for-agent

- [ ] While a report for (rule, Target) is alive, further Triggers for
      it write nothing; the rule matches and its actions run
- [ ] Each such Trigger still empties the rule's tracker (episode
      cadence preserved while the write is silent)
- [ ] A tracker-less report rule writes at most one report per
      (rule, Target) while it is alive
- [ ] Suppression is per (rule, Target): one rule's report never
      suppresses another rule's write, so reasons accrue across rules
- [ ] Deleting a report re-arms writing for that (rule, Target)
- [ ] Expiry (the sweeper) re-arms writing identically
- [ ] A live report's Sample and update time are unchanged
- [ ] Flagged Targets' events still enrich Filesize and feed other
      rules' trackers; no event is dropped from analysis
- [ ] After a restart, suppression state is rebuilt from the report
      table: alive reports suppress, deleted or expired ones do not
- [ ] Concurrent workers produce at most one write per live report
- [ ] The report document served by the API keeps its exact shape
- [ ] Full suite green under the race detector
