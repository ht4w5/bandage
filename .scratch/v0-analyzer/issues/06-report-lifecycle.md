# 06: Report lifecycle — triggers, expiry, dismiss

**What to build:** a report consumer sees when a target first appeared and whether it is still active; stale reports age out on their own; an operator can dismiss a false positive knowing that a persisting condition will surface again.

**Blocked by:** 01: Walking skeleton — Event to Report list

**Status:** ready-for-agent

- [ ] `created_at` is fixed at the Trigger that created the Report; `updated_at` and `expires_at` (Trigger wall-clock time plus the action's ttl) are recomputed unconditionally on every Trigger, regardless of any previous `expires_at`.
- [ ] A re-Trigger on the same (rule, Target) keeps the Report's identity and refreshes its Tracker reading and Sample.
- [ ] Expired Reports are never returned by `GET /reports` and are deleted from storage by a periodic sweeper.
- [ ] `DELETE /reports` requires `?rule=` and/or `?target=`, returns the number of deleted rows, and is dismiss-not-silence: tracker state is untouched, so a Report whose condition persists returns on the next Trigger.
- [ ] Expiry and timestamp behavior is verified with the injected wall clock, without sleeps.
