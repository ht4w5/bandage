# Trigger semantics: one live report per (rule, Target), tracker reset on Trigger

Deployments flag a Target once and let downstream tooling ban it (ADR
0004), so repeated Triggers for the same (rule, Target) re-upsert one row
for no operational gain against the serialized write path. We decide: a
**Trigger empties the matched rule's tracker** for that Target — the
leaky bucket re-arms, so abuse must recur at full volume to Trigger again
— and **while a report for (rule, Target) is alive, the rule skips that
Target's events entirely** (no match, no actions, no write), enforced by
a skip set derived from the report table: rebuilt at startup, maintained
on Trigger, delete and expiry. Report writes stay **synchronous**; if
they are ever deferred (write-behind was considered and shelved in the
2026 benchmark round), losing at most the deferral window on a hard
crash is acceptable, because the next matching event re-discovers the
Target.

Considered: dropping flagged Targets' events before evaluation entirely
(a global skip set). Rejected: it blinds every other rule, and the
reasons accruing across rules are exactly what justifies a ban (ADR
0004); it also makes a component whose mandate is "produces reports and
never ban rules" (ADR 0004) behave like it bans.

Consequences: a report's sample and `updated_at` freeze while it is
alive; deleting or expiring it re-arms reporting — tracker rules must
overflow again, tracker-less rules re-Trigger on the next matching
event. A skipped Target's events run none of the rule's actions, so its
goto/jump/stop do not apply either. ADR 0007's "a duplicate trigger just
refreshes the same row" is superseded: duplicates are suppressed while
the report is alive.
