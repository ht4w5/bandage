# bandage

Realtime web log analysis: bandage consumes access-log events, maintains
leaky-bucket trackers per target, and publishes reports that downstream
tooling turns into ban rules.

## Language

### Pipeline

**Event**:
A single parsed access-log record as it flows through enrichment and
evaluation.
_Avoid_: request, log entry, record

**Filter**:
A predicate over an Event deciding whether a rule considers the event.
_Avoid_: where clause, condition

**Filesize**:
The estimated total size of a path, learned from observed transfers and
unavailable until enough samples have been seen.
_Avoid_: size index, file length

### Rules

**Chain**:
An ordered group of rules traversed for each event, entered by name from
other chains.
_Avoid_: stage, pipeline

**Rule**:
A named condition-action pairing: a filter, at most one tracker, and an
ordered list of actions.
_Avoid_: detector, query

**Action**:
A step executed when a rule matches: report, log, goto, jump, or stop.
_Avoid_: statement, command

**Match**:
When a rule's filter accepts an event and its tracker (if any) overflows;
the rule's actions then run.
_Avoid_: fire, hit

**Trigger**:
A match that wrote a report; its event becomes the report's sample and its
wall-clock time stamps the report.
_Avoid_: firing, hit

### Trackers

**Tracker**:
Leaky-bucket state for one target, accumulating a quantity (rate,
bandwidth, or replay) that decays at a configured leak.
_Avoid_: bucket, counter, analyzer

**Overflow**:
When a tracker's accumulated value exceeds its configured volume.
_Avoid_: exceed, breach

**Target**:
The aggregated source prefix that a tracker keys on and a report is about.
_Avoid_: key, addr, client

### Reports

**Report**:
The record that a rule matched for a target, carrying its tracker reading
and sample, alive until expiry or deletion.
_Avoid_: finding, record, ban

**Reason**:
The machine-readable trigger code a report carries into downstream ban
rules; distinct from the rule ID, which is internal.
_Avoid_: blame, cause

**Sample**:
The most recent event that created a report.
_Avoid_: example, evidence

**Ban rule**:
An enforcement rule that downstream tooling derives from reports; bandage
produces reports and never ban rules.
_Avoid_: ban, penalty
