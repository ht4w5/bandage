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

## `penalty` and `rate`

Every report action declares a **Penalty** — the enforcement stance the
report recommends for the Target — with a `penalty` key beside `reason`
and `ttl` ([GLOSSARY.md](../GLOSSARY.md),
[ADR 0010](adr/0010-reports-carry-an-advisory-penalty.md)). The
vocabulary is closed to five values; the limit penalties carry a `rate`:

| `penalty` | recommends | `rate` |
| --- | --- | --- |
| `drop` | discard the target's traffic silently | none |
| `reject` | refuse the target's traffic with an error signal | none |
| `limit-pkt-rate` | throttle to `rate` packets per second | required |
| `limit-bandwidth` | throttle to `rate` response-payload bytes per second | required |
| `limit-req-rate` | throttle to `rate` requests per second | required |

`rate` is a plain count (`200`) or a decimal human size (`1MB` =
1000000), optionally suffixed `/s` — the same quantity language as the
tracker's `leak` and `volume`. The penalty name states the unit: the
rate of `limit-bandwidth` counts response-payload bytes, the bytes the
report's Sample records as `sent`. Every limit is aggregate over the
report's Target — the whole prefix, not each host inside it.

`bandage -t` prints the penalty and rate of every report action, so
every recommendation can be audited before deploying:

```
    action report reason=iso-egress-overflow ttl=168h0m0s penalty=limit-bandwidth rate=1000000
```

Load refuses a rules file where:

- `penalty` is missing or is not one of the five values;
- `rate` accompanies `drop` or `reject`;
- a `limit-*` penalty has a missing, zero, fractional or unparseable
  `rate`.

The penalty is advice and nothing more: bandage validates it for
well-formedness only — never against the rule's tracker or reason
(ADR 0010). Rules sharing one reason may recommend different penalties,
a tripwire may recommend a limit and a tracked rule `drop`, and whether
— or how restrictively — a consumer applies the penalty is the
consumer's decision. bandage produces reports and never ban rules
(ADR 0004).

Worked examples — the three idiomatic shapes:

The tracker-less tripwire flags immediately and recommends matching
immediate action: `drop`, no rate (full pattern below):

```yaml
      - id: ua-trip
        filter: 'agent keyword "curl"'
        actions:
          - report:
              reason: ua-trip
              ttl: 24h
              penalty: drop
```

A bandwidth-tracked rule recommends `limit-bandwidth`, its rate in
response-payload bytes per second:

```yaml
      - id: sustained-iso-egress
        tracker: {track: bandwidth, leak: 1MB, volume: 100GB}
        actions:
          - report:
              reason: iso-egress-overflow
              ttl: 7d
              penalty: limit-bandwidth
              rate: 1MB
```

A rate-tracked rule recommends `limit-req-rate`, its rate in requests
per second:

```yaml
      - id: bursty-api
        tracker: {track: rate, leak: 10, volume: 200}
        actions:
          - report:
              reason: api-rate-overflow
              ttl: 12h
              penalty: limit-req-rate
              rate: 200
```

These pairings are idiomatic, not enforced: `limit-pkt-rate` (packets
per second) and `reject` round out the vocabulary for rules whose
traffic calls for them.

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
              penalty: drop
```

How it behaves:

- Every matching event is a Match and therefore a Trigger — there is no
  tracker to overflow and none to empty.
- Its `penalty: drop` recommends discarding the offending source's
  traffic — the stance a flag this serious warrants. `drop` carries no
  `rate` (see [penalty and rate](#penalty-and-rate) above).
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
