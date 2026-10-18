# Trigger semantics: one live report per (rule, Target), tracker reset on Trigger

Deployments flag a Target once and let downstream tooling ban it (ADR
0004), so repeated Triggers for the same (rule, Target) re-upsert one row
for no operational gain against the serialized write path. A **Trigger
is a match that ran the rule's report action**, and we decide two things
about it: each Trigger **empties the rule's tracker** for that Target —
the leaky bucket re-arms, so abuse must recur at full volume before the
next Trigger — and while a report for (rule, Target) is alive, the
Trigger's **write is suppressed** (a live-report set derived from the
report table — rebuilt at startup, maintained on Trigger, delete and
expiry — decides). The rule itself is untouched: it still matches and
its other actions (log, goto, jump, stop) still run. Report writes stay
**synchronous**; if they are ever deferred (write-behind was considered
and shelved in the 2026 benchmark round), losing at most the deferral
window on a hard crash is acceptable, because the next matching event
re-discovers the Target.

Considered: suppressing the whole rule for flagged Targets, or dropping
their events before evaluation (a global skip set). Rejected:
suppressing the rule would make goto/jump/stop depend on report
aliveness and change chain traversal per Target; global dropping blinds
every other rule, and the reasons accruing across rules are exactly what
justifies a ban (ADR 0004); it also makes a component whose mandate is
"produces reports and never ban rules" (ADR 0004) behave like it bans.

Consequences: a report's sample and `updated_at` freeze while it is
alive; deleting or expiring it re-arms writing — tracker rules must
overflow again, tracker-less rules re-Trigger on the next matching
event. Resetting on every Trigger (write or suppressed) keeps the action
cadence at one run per accumulation episode even while the write is
silent. ADR 0007's "a duplicate trigger just refreshes the same row" is
superseded: while the report is alive, further Triggers write nothing.
