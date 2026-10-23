# Spec: escalation ladders on one tracker

Status: ready-for-agent

## Problem Statement

A Rule today pairs one Filter, at most one Tracker, and one ordered
action list: the rule either Matches and runs everything, or nothing.
Operators who watch traffic abuse want a *staged* response on a single
accumulation — for example a bandwidth Tracker leaking at 1MB/s where
50MB of accumulation should hand the Target's Events to a replay chain,
5GB should recommend a bandwidth limit, and 40GB should recommend a ban.
Writing three rules does not work: each rule namespaces its own tracker
state (three decaying buckets that disagree), `goto`/`report` end chain
traversal before the later rules see the Event, and one live Report per
(rule, Target) swallows the stronger write. Worse, a Tracker used as a
threshold gate for downstream trackers is broken by today's Trigger
reset: writing a Report empties the bucket and closes the gate, starving
the downstream trackers it was feeding. There is no way to say "the more
they take, the worse it gets" on one Tracker.

## Solution

An **Escalation** ladder on one Tracker: rungs with strictly ascending
volume thresholds in the Tracker's quantity, each with its own ordered
action list. On a Match, every rung the accumulated value is above
fires, lowest first — a handoff rung keeps feeding a downstream chain
per Event as long as the value stays above its threshold, and report
rungs write one Report per (rule, Target) whose stance escalates **in
place**: a Trigger from a strictly higher rung overrides the live
Report — reason, penalty, rate, sample and expiry move to the higher
rung's values. Nothing ever empties the tracker record: a Trigger only
suppresses while a live Report exists below it, so the gate stays open
and the ladder keeps climbing; leak is the only thing that de-escalates.
A Report's death (expiry or deletion) re-arms writing at the
accumulation's current stance.

## User Stories

1. As a rule author, I want multiple volume levels on one Tracker, each
   with its own action list, so that abuse escalates through stronger
   responses without me writing one rule per threshold.
2. As a rule author, I want each rung's threshold expressed in the
   Tracker's own quantity — requests, bytes or download equivalents —
   so that ladders read the same way as `volume` does today.
3. As a rule author, I want bandwidth rungs in human byte sizes
   (`50MB`, `5GB`), so that the ladder reads like traffic accounting.
4. As a rule author, I want rate rungs in plain request counts, so that
   burst thresholds are exact.
5. As a rule author, I want replay rungs in download equivalents, so
   that one threshold means the same abuse for a 1MB file and a 10GB
   file.
6. As a rule author, I want the first rung to hand Events to a replay
   chain, so that a suspect Target gets per-path inspection without a
   second Tracker and without ending the chain.
7. As a rule author, I want a handoff rung to fire on every Event while
   the value stays above its threshold, so that the downstream chain's
   trackers accumulate continuously and not in flickers.
8. As a rule author, I want each rung to carry its own report action
   with its own Reason and Penalty, so that the recommended stance and
   its downstream code climb from a throttle to a ban.
9. As a rule author, I want each rung's report action to carry its own
   `ttl`, so that the ban's lifetime runs from the ban rung (`reject`
   for 1d) and not from the first write.
10. As a rule author, I want every rung the value is above to fire on an
    Event, in ascending order, so that one large transfer cannot skip a
    response it flew past.
11. As a rule author, I want rungs to stop firing once leak has decayed
    the value below them, so that quiet Targets return to normal with no
    extra bookkeeping.
12. As a rule author, I want terminality declared by each rung's action
    list, so that a `jump` handoff rung does not end chain traversal.
13. As a rule author, I want the chain to end after the Rule only when a
    rung that actually fired carried `report`, `goto` or `stop`, so that
    later rules still see traffic that only crossed the handoff rung.
14. As a rule author, I want `goto` in a fired rung to run its target
    chain and then end this chain after the remaining fired rungs have
    run, so that handoff-and-halt ladders behave like `goto` does today.
15. As a rule author, I want `jump` in a fired rung to run its target
    chain and resume, so that a monitoring chain runs beside the rest of
    the chain.
16. As a rule author, I want the ladder's fired rungs decided once per
    Event before any action runs, so that actions within the event can
    never cancel a rung that already fired.
17. As a rule author, I want `log` actions on any rung with the same
    rule, Target, Event and tracker reading detail as today, so that I
    can watch a ladder fire in the debug log.
18. As a rule author, I want rung reasons free to be distinct or shared,
    so that I can carry one downstream code across the climb or give
    each stage its own meaning.
19. As a rule author, I want the loader to reject a ladder with fewer
    than two rungs, so that the single-volume form stays the one way to
    write a single threshold.
20. As a rule author, I want the loader to reject thresholds that are
    not strictly ascending, so that "every rung above the value" is
    always a prefix of the ladder and a lower rung can never outrank a
    higher one.
21. As a rule author, I want the loader to reject a ladder declared
    beside `actions` or `tracker.volume`, so that there is never
    ambiguity about which response a Match runs.
22. As a rule author, I want the loader to reject a ladder without a
    Tracker, so that every threshold has something to accumulate.
23. As a rule author, I want each rung threshold parsed in the Tracker
    kind's quantity (and nothing else), so that `50MB` on a rate rule is
    a load error and not a runtime surprise.
24. As a rule author, I want every load error to name the rule it
    belongs to, so that a bad ladder is found where it is written.
25. As a rule author, I want `bandage -t` to print every rung with its
    threshold and actions, so that I can audit the whole ladder before
    deploying.
26. As a rule author, I want existing single-volume rules to load and
    behave exactly as before, so that adopting ladders is never forced.
27. As a report consumer, I want one Report per (rule, Target) whose
    stance escalates in place, so that I always apply the strongest
    response the ladder has reached.
28. As a report consumer, I want a higher rung to override a live
    Report completely — reason, penalty, rate, sample and expiry — so
    that the row always describes the abuse as it stands.
29. As a report consumer, I want a lower rung to never override a live
    Report, so that a ban cannot silently soften back into a throttle.
30. As a report consumer, I want the Sample to be the event that
    justified the report's current stance, so that the evidence always
    backs the penalty I am asked to apply.
31. As a report consumer, I want the override to move `updated_at` and
    `expires_at`, so that my tooling notices the stance change and the
    ban lives for the ban rung's `ttl`.
32. As a report consumer, I want `created_at` frozen at first flagged,
    so that I can see how long the Target has been in trouble.
33. As a report consumer, I want the tracker reading to record the rung
    that wrote it (its threshold as `volume`), so that I can see which
    threshold justified the current stance.
34. As a report consumer, I want the report document's shape unchanged,
    so that my integration keeps working across this feature.
35. As a bandage operator, I want no Trigger to ever empty a tracker
    record, so that a Tracker acting as a threshold gate keeps feeding
    downstream trackers instead of flickering shut on every write.
36. As a bandage operator, I want writes bounded by report aliveness
    alone, so that suppression needs no reset to keep one live Report
    per (rule, Target).
37. As a bandage operator, I want a dead Report (expired or deleted) to
    re-arm a fresh write on the next matching Event at the
    accumulation's current stance, so that a still-abusive Target is
    immediately recommended again.
38. As a bandage operator, I want a failed report write to leave the
    tracker record intact and retry on the next matching Event, so that
    no detection is lost to a transient write failure.
39. As a bandage operator, I want the tracker cache-entry TTL derived
    from the ladder's top rung, so that tracker state outlives the whole
    climb and never expires mid-ladder.
40. As a bandage operator, I want the report document contract and its
    pinned example untouched by this feature, so that downstream
    consumers see no format change.

## Implementation Decisions

- The rule model gains an **Escalation**: an `at` threshold in the
  Tracker's quantity plus its own ordered action list. A rule carries an
  action list **or** an escalation ladder, never both; the ladder's
  thresholds stand in for the rule's `volume`. Naming: *Escalation*
  (glossary term; avoid tier, stage, level — `Level` stays the log level
  enum); the config key is `escalations` at rule level.
- Developer decisions locked in design review (grilling rounds):
  1. **Escalate in place** — one Report per (rule, Target) whose stance
     escalates; per-reason rows were considered and rejected for now.
     Rung reasons are unconstrained: distinct or shared, author's call;
     the Reason of the live Report follows the rung that last wrote it.
  2. **Terminality per fired rung** — the chain ends after the Rule iff a
     rung that fired carried `report`/`goto`/`stop`; rung terminality is
     a static property of the rung's action list.
  3. **Scalar rungs only** — a rung is one quantity in the Tracker's
     kind; volume methods (`constant`, `clamped-linear`,
     `inverse-square`, `step`) stay exclusive to the single-volume form.
     Replay ladders use download equivalents, already normalized by
     Filesize.
  4. The concept is named **Escalation** everywhere (config, glossary,
     docs).
  5. **Only `created_at` is frozen.** The override moves reason, penalty,
     rate, sample, the tracker reading, `updated_at` and `expires_at` to
     the overriding rung's values. The old sample/penalty freeze existed
     to keep "the stance always matches the sample that justified it";
     once the stance moves, freezing the sample would break that
     invariant, so the Sample is redefined as the event that justified
     the report's *current* stance.
  6. **Nothing ever resets the tracker** — a Trigger suppresses or
     overrides, never empties the record (this retires ADR 0008's
     Trigger reset everywhere, not just in ladders: a single-volume rule
     can be a threshold gate too). The "one Trigger per accumulation
     episode" cadence and "abuse must recur at full volume" retire with
     it; report aliveness alone bounds writes.
  7. **Override guard = the recorded threshold.** The live Report's
     tracker reading records the threshold of the rung that last wrote
     it; a Trigger may write over a live Report only when its rung's
     threshold is strictly above that recorded volume, and the write
     overrides the row in place. Rejected alternatives: an explicit
     escalation field on the report record (contract change for a value
     already present), keying on Reason (slugs have no order — a lower
     rung could retitle a ban downward), no guard (per-event rewrite
     churn). The guard survives restarts because the live set is rebuilt
     from the report table.
  8. **Post-death behaviour** — when a Report dies and the value is
     still above thresholds, the next matching Event writes fresh at the
     lowest crossed rung and overrides in place up the crossed rungs
     within that same Event; the fresh Report reflects the accumulation
     as it stands (a dead Report's stance is not remembered).
- Firing: the fired rungs are computed **once** from the post-
  accumulation value, before any action runs; every rung with `at` below
  the value fires, in ascending order. Strictly ascending thresholds mean
  the fired rungs are always a **prefix** of the ladder — the invariant
  behind per-Event terminality and the guard's ordering. Rungs are
  level-triggered: they fire on every Event while the value stays above
  them, and stop as leak decays it below.
- TTL: the tracker cache-entry TTL derives from the ladder's top rung
  (`top/leak`, with the existing zero-leak default and minimum), so state
  outlives the climb. Replay's per-event TTL re-derivation uses the same
  top rung.
- The report document's canonical serialization, envelope and record
  fields are unchanged; only its lifecycle prose gains the escalation
  wording. That wording — like the rules guide, plan and glossary-facing
  behavior descriptions — lands with the implementation, so the contract
  never describes unshipped behaviour; the wording decisions are pinned
  here and in ADR 0013.
- Modules touched: the rules loader (new `escalations` key plus the
  validation matrix: mutual exclusion, minimum rung count, strictly
  ascending thresholds, per-kind quantity parsing, per-rung action
  validation reusing the existing action parser); the domain rule model
  (Escalation, ladder-aware match/terminality/override-ordering/TTL
  questions); the evaluation service (fired-rung dispatch, per-rung
  reading, no resets); the report service (override write, sample and
  reading refresh, strictly-higher guard in the live-report suppression);
  the `--test` plan printer (one line per rung with its actions); the
  documentation set (rules guide, report contract lifecycle, plan, and
  ADR 0013 amending the Trigger-semantics ADR).
- ADR 0013 records the ladder semantics, the in-place override and the
  retirement of the Trigger reset. The glossary is updated: Escalation
  added; Match, Trigger, Overflow, Rule, Reason, Penalty and Sample
  reworded to the ladder model.
- The rules format stays at version 0: the change is additive and the
  single-volume form is the one-rung equivalence.
- A `jump` is the idiomatic handoff action on a rung below report rungs
  (`goto` there would end the chain on every Event above that rung); the
  rules guide documents this.

## Testing Decisions

- A good test states external behavior: rules documents accepted or
  rejected, Events ingested, the served report document, chain traversal
  as seen in the log actions, and tracker state as seen through what
  fires. Internal helpers (rung selection, the override guard comparison,
  TTL derivation) are never asserted on directly — they are covered
  through the two seams below.
- **The daemon seam** (primary): the full daemon driven over its ingest
  surface with a real report store and tracker cache, observed through
  the served report document and captured log records. Every runtime
  story is tested here: ascending firing order on a multi-rung Event,
  level-triggered handoff rungs feeding their chain per Event, per-fired-
  rung terminality (a `jump` rung below report rungs leaves later rules
  running), in-place override (reason, penalty, `updated_at`,
  `expires_at`, sample and reading move; `created_at` frozen), never-
  downgrade on lower-rung re-fire, no reset (the bucket value survives a
  write and the gate keeps feeding downstream trackers), re-arm on
  expiry or deletion writing at the current stance (including an
  override up the crossed rungs within that Event), failed writes
  retrying with the record intact, and untouched single-volume
  behaviour. Prior art: the end-to-end Trigger-semantics suite (whose
  cadence test is rewritten from "once per volume of traffic" to "one
  write per report lifetime" under the no-reset decision), the
  goto/jump/stop traversal suite, and the report-identity suite.
- **The rules loader and validated-plan seam** (secondary): the
  validation matrix as failing/passing document pairs (mutual exclusion
  with `actions` and `tracker.volume`, ladder without a Tracker, fewer
  than two rungs, non-ascending thresholds, wrong quantity per Tracker
  kind, unparseable `at`), and the plan printer showing each rung with
  its threshold and actions. Prior art: the rules loader suite (a
  failing and a passing case per validation) and the shipped-format plan
  tests.
- Modules covered end to end through those seams: the rules loader, the
  evaluation service's rung dispatch and terminality, the report
  service's suppression and override, and the plan printer.
- The report document contract test (the byte-for-byte pinned example)
  is expected to pass untouched: the contract's fields do not change.
- No new test seams; no table-driven unit tests of the domain helpers.

## Out of Scope

- Method-shaped rungs (a rung whose threshold scales with Filesize);
  volume methods remain single-volume only.
- Per-reason report rows or one Report per rung (rejected for now in
  favour of in-place escalation; revisitable).
- New penalty vocabulary, new report-document fields, or any change to
  the report document contract shape.
- Multiple trackers per rule (ADR 0003 is untouched).
- Persisting tracker state across restarts; Eviction of tracker state
  behaves as today (and still starts that target over empty).
- Hot reload of rules; renumbering rung thresholds under live reports
  changes what counts as "higher" until those reports die — acceptable
  for a no-hot-reload daemon.
- Downstream enforcement: splint and ban-rule derivation are unchanged;
  how a consumer applies an escalated Penalty stays the consumer's
  decision.

## Further Notes

- ADR 0013 records the trade-off and amends the Trigger-semantics ADR
  0008: the reset retires everywhere, and a live Report's freeze
  narrows to `created_at` alone.
- With no reset there is no cadence governor left: while the value stays
  above rungs, their actions run per Event — handoff and log rungs run
  every Event (which is the point of a gate), and report rungs attempt a
  suppressed write per Event (an in-memory live-set check, no I/O).
- The prefix invariant (fired rungs are always a prefix of the ladder)
  is the load-bearing trick behind per-Event terminality and the
  guard's ordering; it is preserved by the loader's strictly-ascending
  validation and is worth stating in the code comments where rung
  dispatch lives.
- The override guard rides on the recorded `tracker.volume`, so editing
  rung thresholds between deployments changes what counts as "higher"
  for reports written before the change. Documented, accepted.
