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
A match that ran the rule's report action; when it writes, its event
becomes the report's sample and its wall-clock time stamps the report.
While that report is alive, further Triggers for the Target write nothing
(the rule's other actions still run), and each Trigger empties the rule's
tracker for the Target. A failed write is not a Trigger outcome: the
tracker record stays intact and the next matching event retries the
report.
_Avoid_: firing, hit

### Trackers

**Tracker**:
Leaky-bucket state for one target (per target and path for replay),
accumulating a quantity (rate, bandwidth, or replay) that decays at a
configured leak.
_Avoid_: bucket, counter, analyzer

**Overflow**:
When a tracker's accumulated value exceeds its configured volume.
_Avoid_: exceed, breach

**Target**:
The aggregated source prefix that a tracker keys on and a report is about.
_Avoid_: key, addr, client

**Volume method**:
A replay tracker's tolerated volume as a function of file size —
`constant`, `clamped-linear`, `inverse-square`, or `step` — in tolerated
download equivalents. Only replay configures one.
_Avoid_: threshold formula, scaling curve

**Eviction**:
Tracker state removed because the tracker cache entry cap is reached;
that target's tracker starts over empty.
_Avoid_: capped drop, drop, expiry

### Reports

**Report**:
The record that a rule matched for a target, carrying its tracker reading,
sample, and penalty, alive until expiry or deletion.
_Avoid_: finding, record, ban

**Reason**:
The machine-readable trigger code a report carries into downstream ban
rules; distinct from the rule ID, which is internal.
_Avoid_: blame, cause

**Penalty**:
The enforcement stance a report carries — drop, reject, or a limit at a
packet, bandwidth, or request rate — declared by the rule's report action; advisory, a report consumer
decides how to apply it.
_Avoid_: sanction, remedy, enforcement action

**Sample**:
The most recent event that created a report.
_Avoid_: example, evidence

### Enforcement

**Ban rule**:
An enforcement rule derived from reports by downstream tooling: the
report's Target prefixes and the Penalty stance a firewall driver applies
to them. The bandage daemon produces reports and never enforces;
`splint` is the tool that derives ban rules from reports and installs
them.
_Avoid_: ban

**Firewall driver**:
The pluggable backend that enforces ban rules at its enforcement
surface — a kernel firewall like nftables, or another surface such as a
web server or a WAF; it applies each Penalty as stated or declines it.
_Avoid_: backend, adapter
