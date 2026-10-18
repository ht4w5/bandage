# Writing rules

Rules live in the rules file (`configs/rules.yml` is a complete
example): `version: 0`, an ordered list of chains, each chain an
ordered list of rules. A **Rule** is an id, a filter, at most one
tracker, and an ordered list of actions (report, log, goto, jump,
stop). The filter expression language and the full DSL are specified
in [PLAN.md](../PLAN.md) §1.

Two glossary entries govern what happens at runtime
([GLOSSARY.md](../GLOSSARY.md), [ADR 0008](adr/0008-trigger-semantics-one-live-report.md)):

- **Match** — the rule's filter accepts the Event and its tracker (if
  any) overflows; the rule's actions then run. A rule without a tracker
  matches on the filter alone.
- **Trigger** — a Match that ran the rule's report action. The report
  action is the only write path to reports.

Trigger semantics hold for every rule (ADR 0008):

- One **Report** per (rule, Target) per report lifetime. While the
  report for (rule, Target) is alive, further Triggers write nothing:
  the report freezes — its Sample and update time stay at the first
  write. The rule itself is untouched: it keeps matching and its other
  actions keep running per event.
- Each Trigger empties the rule's tracker for the Target (per
  (Target, path) for replay trackers), so abuse must accumulate a full
  volume again before the next write. Tracker-less rules have nothing
  to empty.
- A failed report write is not a Trigger outcome: the tracker stays
  intact and the next matching event retries the report.
- Deleting a report (`DELETE /reports`) or letting its `ttl` expire
  re-arms writing — immediately on the next matching event for
  tracker-less rules, after a fresh accumulation episode for tracker
  rules.

Validate config and rules before deploying: `bandage -t -c bandage.yml
-r rules.yml` prints the validated plan and exits without ingesting.

## Pattern: the tracker-less tripwire

The tripwire flags every request carrying a known-bad signal (classically
a user agent) immediately — no accumulation, no volume: an agent keyword
filter plus a report action, and **no tracker**. Its writes are bounded
by report suppression alone (see the Trigger semantics above).

```yaml
version: 0
chains:
  - name: trip
    rules:
      - id: ua-trip
        filter: 'agent keyword "curl"'
        actions:
          - report:
              reason: ua-trip
              ttl: 24h
```

How it behaves:

- Every matching event is a Match and therefore a Trigger — there is no
  tracker to overflow and none to empty.
- The first Trigger writes one Report per (rule, Target). Further
  Triggers while that report is alive write nothing (the Sample and the
  update time freeze at the first write): the flag is written once per
  offending source, not once per request.
- The **Target** is the event's source aggregated at the default
  prefix — per address for IPv4, per /64 for IPv6. A tracker-less rule
  has no `target_prefix` to configure; each offending source gets one
  report of its own.
- Re-arm: `DELETE /reports?rule=ua-trip&target=203.0.113.7` or expiry
  at `ttl` re-arms writing — the next matching event writes a fresh
  report immediately. A still-offending source keeps matching (and its
  other actions keep running) while suppressed, so nothing is lost by
  the silence.
- A restart does not re-arm a live report: the live-report set is
  derived from the report table at startup (the table is the
  correctness source, ADR 0008).
- `reason` is the machine-readable slug downstream tooling turns into a
  ban rule (ADR 0004): a lowercase slug `^[a-z0-9][a-z0-9_-]*$`,
  shared freely between rules; the rule id is internal provenance.
  bandage produces reports and never ban rules.
- The filter above is a case-sensitive substring match on the Event's
  user agent (`agent "…"` matches the agent exactly). Values match
  case-sensitively without normalization; `and`, `or` and `not` are
  reserved and must be quoted when used as values.

Rules with a tracker work the same way with two differences, both in
the Trigger semantics: a Match additionally requires the tracker to
overflow, and each Trigger empties the tracker for the Target, so a
deleted or expired report is rewritten only after a fresh accumulation
episode.
