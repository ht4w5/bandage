# Escalation ladders: in-place stance escalation, no Trigger reset

Operators want staged responses on one accumulation — a handoff rung, a
throttle recommendation, a ban — and three rules cannot express it: each
rule namespaces its own tracker state, terminal actions end chain
traversal before later rules see the event, and one live report per
(rule, Target) swallows the stronger write. A rule therefore trades its
volume for an **escalation ladder** (GLOSSARY): rungs with strictly
ascending thresholds in the tracker's quantity, each with its own action
list, every exceeded rung firing lowest-first on each matching event.
Two runtime decisions follow, and both amend ADR 0008.

A Trigger **never empties the tracker record** (reversing ADR 0008's
reset). The bucket is accumulation state and the report table is
suppression state — one mechanism, one job — and a tracker may double as
a threshold gate for downstream trackers, which a reset would close on
every write. Writes re-arm only when a report dies (expiry or deletion);
the next matching event writes at the accumulation's current stance.

A live report is **overridden in place** by a Trigger from a strictly
higher rung: reason, penalty, rate, sample, tracker reading, `updated_at`
and `expires_at` all move to the higher rung's values, and `created_at`
alone stays frozen at first flagged. The guard is the volume recorded in
the live report's tracker reading — the threshold of the rung that last
wrote it — so no new contract field is needed and the guard survives the
live-set rebuild at startup; a rung at or below the recorded volume is
suppressed exactly as in ADR 0008.

Considered: one report row per reason (rejected for now — in-place keeps
report identity (rule, Target) and the report document contract
unchanged); an explicit escalation field on the report record (rejected:
the recorded threshold already orders rungs); keying the guard on reason
(rejected: slugs have no order, and a lower rung could retitle a live
ban downward); keeping the reset outside the ladder (rejected: a
single-volume rule can be a threshold gate too).

Consequences: "one Trigger per accumulation episode" retires — a
suppressed Trigger is silent and harmless now that nothing resets, and a
dead report re-arms a fresh write on the next matching event, which
escalates up the crossed rungs within that event. The report contract's
lifecycle wording changes (the sample and the timestamps follow the
latest write) while its fields do not. ADR 0008's suppression and
failed-write rules stand as written.
