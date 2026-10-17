# 06: Report lifecycle — triggers, expiry, dismiss

**What to build:** a report consumer sees when a target first appeared and whether it is still active; stale reports age out on their own; an operator can dismiss a false positive knowing that a persisting condition will surface again.

**Blocked by:** 01: Walking skeleton — Event to Report list

**Status:** resolved

- [x] `created_at` is fixed at the Trigger that created the Report; `updated_at` and `expires_at` (Trigger wall-clock time plus the action's ttl) are recomputed unconditionally on every Trigger, regardless of any previous `expires_at`.
- [x] A re-Trigger on the same (rule, Target) keeps the Report's identity and refreshes its Tracker reading and Sample.
- [x] Expired Reports are never returned by `GET /reports` and are deleted from storage by a periodic sweeper.
- [x] `DELETE /reports` requires `?rule=` and/or `?target=`, returns the number of deleted rows, and is dismiss-not-silence: tracker state is untouched, so a Report whose condition persists returns on the next Trigger.
- [x] Expiry and timestamp behavior is verified with the injected wall clock, without sleeps.

## Answer

Implemented on `feat/v0-analyzer` (merge commit `51b249f`).
`created_at` fixed at the creating Trigger; `updated_at`/`expires_at`
(trigger wall clock + action ttl) recomputed unconditionally per Trigger;
re-Trigger refreshes tracker reading + sample; expired rows excluded from
`GET /reports` and deleted by the periodic sweeper (`sweepOnce` shared
with tests); `DELETE /reports` requires `?rule=`/`?target=`, returns
`{"deleted": n}`, 400 without filters, and is dismiss-not-silence — all
verified via the injected clock with no sleeps.

Decision (flagged by the implementer, kept): `DELETE` counts rows
regardless of expiry — dismissal addresses storage, not just the live
list. Context: `/home/user2/Devel/bandage-impl-notes/DECISIONS.md` §9.
