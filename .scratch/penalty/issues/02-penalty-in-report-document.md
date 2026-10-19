# 02: Penalty flows into the report document

**What to build:** A report consumer sees the recommended penalty on every report they read from `GET /reports`, in the nested shape `"penalty": {"action": …, "rate": …}` — `rate` present exactly when the action is a limit, an integer ≥ 1 in the unit the action name states. The stance is written by the Trigger that creates the report and travels with it: it persists across a daemon restart, it freezes with the report while the report is alive (always matching the Sample that justified it), and a re-armed write after deletion or expiry carries the penalty of the rules loaded at write time.

**Blocked by:** 01

**Status:** resolved

- [x] `GET /reports` report entries carry the nested penalty; `rate` is present exactly for `limit-*` actions and absent otherwise
- [x] `rate` is serialized as an integer ≥ 1 in the unit named by the action (pkt/s, response-payload B/s, req/s)
- [x] The Trigger copies the penalty from the report action into the report record
- [x] The penalty survives a daemon restart (store reopen) with its report
- [x] While a report is alive, the penalty freezes with it, matching its Sample
- [x] After `DELETE /reports` or expiry, the replacement Trigger's report carries the then-loaded rules' penalty
- [x] Verified at the assembled-daemon seam: raw nginx-JSON syslog messages in, `GET /reports` JSON out, injected clock

Implemented on integration branch `feat/penalty` (merge commit
`a8d1a58`; cross-ticket code-review fixes through `ef0e6d9`, incl.
strict `Penalty.MarshalJSON`: a limit penalty without a rate now errors
instead of silently omitting `rate`). Context: spec `../spec.md`, ADR
0008/0010; wire contract `docs/reports.md`; successor
`03-canonical-report-document.md`.
