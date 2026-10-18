# Spec: v0 hot path — Trigger semantics and write-path efficiency

Status: ready-for-agent

## Problem Statement

bandage flags abusive Targets once and expects downstream tooling to ban
them, but the analyzer keeps re-Triggering for an already-flagged Target:
every further overflowing event re-runs the rule and re-upserts the same
report row through the single serialized sqlite write path. The v0
benchmark round measured this write path as the dominant bottleneck —
report upserts were 82–84% of write-path CPU and the Trigger path capped
at ≈22–23k lines/s and got *slower* with more workers, while the
trigger-free fast path scaled to 400k lines/s. Operators deploying the
flag→ban model pay that cost for writes that carry no new information.
On the fast path, the parser allocates ~32 objects per line (75% of all
allocated objects), and API reads queue behind upserts on the store's one
connection.

## Solution

Make a **Trigger** mean one thing per (rule, Target): a Trigger empties
the rule's tracker for that Target (abuse must recur at full volume
before the next Trigger), and while a report for (rule, Target) is alive
its write is suppressed — the rule keeps matching and all its actions
keep running, but the report is not written again. Multi-rule evidence
keeps accruing (one rule's report never hides a Target from another
rule), and flagged Targets' events keep enriching and feeding other
trackers — bandage remains an analyzer, not an enforcer. The report
database moves to WAL with a separate read path so `GET /reports` never
queues behind writes, upserts shed their redundant work, and the parser
rewrites on `encoding/json/v2` with a byte-identical behavior contract.
Ingest guidance documents the cheap transport (udp/unixgram) operators
should feed over.

## User Stories

### Trigger semantics

1. As an operator, I want a Trigger to empty the matched rule's tracker
   for that Target, so that a flagged Target must accumulate a full
   volume again before it can Trigger again.
2. As an operator, I want the report write suppressed while a live
   report exists for (rule, Target), so that a flagged Target cannot
   churn the write path.
3. As an operator, I want the rule to keep matching and all of its
   actions to run even while the write is suppressed, so that chain
   control flow (goto, jump, stop) and log actions behave identically
   for every event.
4. As an operator, I want the tracker emptied on every Trigger — whether
   or not the write landed — so that a rule's actions run once per
   accumulation episode rather than per event.
5. As an operator, I want a failed report write to leave the tracker
   intact, so that the next event retries the report instead of losing
   the detection.
6. As an operator, I want suppression decided per (rule, Target), so
   that one rule's report never silences another rule.
7. As ban-rule tooling, I want reasons to keep accruing across rules for
   an abusive Target, so that a ban's justification strengthens as more
   signals fire.
8. As an operator, I want flagged Targets' events to keep enriching
   Filesize estimates and feeding other rules' trackers, so that analysis
   stays complete for every event.
9. As an operator, I want deleting a report to re-arm writing for that
   (rule, Target), so that a still-abusive Target is reported again —
   tracker rules after a fresh episode, tracker-less rules on the next
   matching event.
10. As an operator, I want an expired report to re-arm writing the same
    way, so that a Target whose ban lapsed is re-reported when it
    recurs.
11. As an operator, I want a report's Sample and update time frozen while
    it is alive, so that I understand the report shows the Trigger-time
    evidence, not live activity.
12. As an operator, I want tracker-less rules (e.g. a `agent keyword`
    tripwire with a report action) to write at most one report per
    (rule, Target) while it is alive, so that user-agent bans don't
    churn the write path either.
13. As an operator, I want suppression state rebuilt from the report
    table at startup, so that a restart neither resurrects write churn
    nor hides reports that are still alive.
14. As an operator, I want concurrent workers to agree on suppression
    per (rule, Target), so that two simultaneously overflowing events
    produce at most one write under the relaxed-ordering worker pool.
15. As an operator, I want report writes to stay synchronous, so that
    every written report survives a process restart.
16. As an operator, I want a replay rule's Trigger to empty the tracker
    record for the matched (Target, path) key, so that per-path
    accumulation re-arms correctly while the (rule, Target) report stays
    suppressed.
17. As an operator, I want suppression to apply to the replay rule's
    report at (rule, Target) grain like every other rule, so that one
    live report per (rule, Target) is the single uniform rule.

### Write path and read path

18. As an operator, I want the report database in WAL mode, so that
    commits are cheap and readers never block the writer.
19. As an operator, I want `GET /reports` served on its own connections,
    so that report queries never queue behind upserts and upserts never
    queue behind queries.
20. As an operator, I want writes to keep landing through one write
    connection, so that write ordering stays deterministic as before.
21. As an operator, I want commits to survive process crashes and to
    tolerate losing only the final moments on power failure, so that
    durability matches what the flag→ban model needs.
22. As an operator, I want upserts to stop reading the row before
    writing it, so that each Trigger write does less work.
23. As an operator, I want the report document served by the API to keep
    its exact shape, so that downstream tooling needs no changes.
24. As an operator, I want to be told that WAL places files beside the
    database and how that affects backups, so that I don't lose reports
    to a naive backup script.

### Parser

25. As an operator, I want parsing on `encoding/json/v2` with identical
    Events for identical lines, so that my log format contract is
    unchanged.
26. As an operator, I want invalid lines to keep producing the same
    field-level errors and the same drop accounting, so that my
    malformed-traffic monitoring is unaffected.
27. As a maintainer, I want the parser's per-line allocations cut
    substantially, so that the fast path keeps its throughput headroom
    and GC pressure drops.

### Ingest and documentation

28. As an operator, I want documented ingest guidance recommending
    udp/unixgram for high-rate deployments with the tcp cost and the UDP
    kernel-buffer caveat spelled out, so that I deploy the cheap path.
29. As an operator, I want the tracker-less tripwire pattern (agent
    keyword filter + report action, no tracker) documented beside the
    rules documentation, so that user-agent bans are written correctly.

### Verification

30. As a maintainer, I want the benchmark scenarios re-modeled for the
    new Trigger semantics, so that episode-based Trigger behavior is
    measured instead of the old overflow-every-event trick.
31. As a maintainer, I want the committed benchmark baseline regenerated
    after these changes, so that future regression comparisons rest on
    honest numbers.
32. As a maintainer, I want the semantics changes proven at the daemon
    seam with the suite green under the race detector, so that the
    worker-pool interplay is verified, not assumed.

## Implementation Decisions

- **Trigger semantics** follow ADR 0008 and the GLOSSARY entry of the
  same name: a Trigger is a match that ran the rule's report action; it
  empties the matched rule's tracker for the Target (the match's key —
  per (Target, path) for replay trackers), and while a report for
  (rule, Target) is alive its write is suppressed. A failed write is not
  a Trigger outcome: the tracker stays intact and the next event
  retries.
- **Suppression lives in the report write path** (the report service),
  keyed exactly like report rows — (rule, Target). Its live-report set
  is derived from the report table: rebuilt at startup, maintained on
  Trigger, delete and expiry. In-memory state behind it is acceptable;
  the report table is the correctness source, so a restart re-derives it.
- **The evaluation traversal changes only in two places**: the matched
  rule's tracker record is cleared after its report action completes
  without error, and nothing else about matching, action dispatch, or
  terminality changes. Tracker-less rules have nothing to clear;
  suppression alone bounds their writes.
- **Report deletion and expiry re-arm writing**: the delete paths and
  the periodic sweeper must inform the live-report set as rows leave the
  table. The documented delete promise holds — a still-abusive Target is
  reported again on the next Trigger (immediately for tracker-less
  rules, after a fresh episode for tracker rules).
- **The report store** moves to `journal_mode=WAL` with
  `synchronous=NORMAL` (ADR 0009). Writes keep the single connection
  (write determinism, ADR 0007); reads move onto their own connections
  so the API never contends with upserts. `:memory:` databases ignore
  WAL and treat connections as separate databases — the test wiring
  handles this (shared-cache URI or single-connection fallback).
- **Upsert sheds its pre-read**: created_at is preserved by the upsert
  statement itself rather than a preceding SELECT; statements are
  prepared once and reused.
- **The parser** is rewritten on `encoding/json/v2` (stdlib in Go 1.27)
  with a behavior-identical contract: same required-field validation,
  same field-level errors, same drop accounting, same Event mapping.
  No third-party codec.
- **Docs**: ingest transport guidance (udp/unixgram recommended at high
  rate; tcp framing cost documented; UDP kernel-buffer drops noted) and
  the tracker-less tripwire pattern.
- **Benchmarks**: the overflow-every-event scenario (volume below the
  per-event increment) no longer models the world under these semantics;
  scenarios become first-Trigger vs re-arm-after-delete/expiry, and the
  baseline is regenerated wholesale.
- **No new glossary terms and no config surface**: the semantics are
  universal, not opt-in; the GLOSSARY **Trigger** entry and ADR 0008/0009
  are the vocabulary of record. The `Reason` slug contract (ADR 0004)
  and the report document format are untouched.

## Testing Decisions

- A good test asserts **external behavior**: whether a write landed or
  was suppressed, whether a subsequent Trigger is possible, that actions
  ran per event, what `/reports` serves, and what the drop counters
  say. Never the internal state of the live-report set or the tracker
  record.
- **The assembled daemon is the primary seam** (its in-package test
  harness: injected clock, substituted report store, syslog feed,
  processed-line waiting): Trigger cadence, suppression, re-arm on
  delete/expiry, restart re-derivation and the worker-pool interplay are
  all observable there end to end.
- Supporting seams, used only where the daemon seam can't observe
  cheaply — all existing: the evaluation service over stub tracker/report
  ports (reset cadence and action runs), the report service over a stub
  repository (suppression and re-arm rules), the report repository's own
  contract tests (WAL, split connections, pre-read-free upsert), and the
  parser's fixture tests as the rewrite's oracle.
- Prior art: the repo's in-package stdlib table tests (`tests :=
  []struct` + `t.Run`), the daemon e2e suite (test clock, processed-line
  waiting, log capture), the worker-pool/shutdown tests with wedged
  stores, and the benchmark suite's fixture-correctness tests. The
  domain-purity lint (domain packages never import adapters) stays green
  — suppression state is wired at the app layer, not into the domain.
- The performance claims are verified by the benchmark suite itself
  (`-benchmem`, regenerated baseline), not by ad-hoc timing in tests.

## Out of Scope

- **Write-behind / deferred report writes**: shelved; ADR 0008 records
  the accepted deferral window as policy for the future only.
- **Dropping flagged Targets' events** (a global skip set): rejected —
  it blinds other rules and makes an analyzer behave like an enforcer
  (ADR 0008 "Considered").
- **Ban-rule generation and enforcement**: never bandage's job (ADR
  0004).
- **The two remaining hot-path candidates** — de-globalizing per-line
  bookkeeping and alloc-free cache keys — stay measured candidates in
  the benchmark findings; their urgency dropped with the Trigger churn
  gone.
- **A CI benchstat regression gate**: the baseline stays a manual
  reference.
- **New config, rule-language changes, and requiring a tracker for
  report actions**: tracker-less rules stay legal by decision.
- **tcp framing changes**: documentation only.
- **Prometheus metrics and suppressed-write counters**: not decided;
  the human-facing `/stats` shape (ADR 0006) is unchanged.

## Further Notes

- Context pointers: the measurement basis and dispositions are in the
  benchmark effort's `findings.md` (`.scratch/v0-benchmarks/`), and the
  decisions of record are GLOSSARY **Trigger**, ADR 0008 (Trigger
  semantics) and ADR 0009 (WAL and the separate read path), with ADR
  0007 amended for the suppressed duplicate write.
- The semantics deliberately freeze a report's Sample and update time
  while it is alive: the flag→ban model treats further traffic from a
  flagged Target as noise, and delete/expiry is the operator's re-arm
  lever.
- Expected impact, from the measured numbers: one write per (rule,
  Target) per report lifetime instead of one per overflowing event takes
  the Trigger path from a per-event cost to a per-episode cost, which is
  the difference between the ≈23k lines/s write-bound ceiling and the
  fast path's scale-with-workers behavior.
