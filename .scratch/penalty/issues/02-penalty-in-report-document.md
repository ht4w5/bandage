# 02: Penalty flows into the report document

**What to build:** A report consumer sees the recommended penalty on every report they read from `GET /reports`, in the nested shape `"penalty": {"action": …, "rate": …}` — `rate` present exactly when the action is a limit, an integer ≥ 1 in the unit the action name states. The stance is written by the Trigger that creates the report and travels with it: it persists across a daemon restart, it freezes with the report while the report is alive (always matching the Sample that justified it), and a re-armed write after deletion or expiry carries the penalty of the rules loaded at write time.

**Blocked by:** 01

**Status:** ready-for-agent

- [ ] `GET /reports` report entries carry the nested penalty; `rate` is present exactly for `limit-*` actions and absent otherwise
- [ ] `rate` is serialized as an integer ≥ 1 in the unit named by the action (pkt/s, response-payload B/s, req/s)
- [ ] The Trigger copies the penalty from the report action into the report record
- [ ] The penalty survives a daemon restart (store reopen) with its report
- [ ] While a report is alive, the penalty freezes with it, matching its Sample
- [ ] After `DELETE /reports` or expiry, the replacement Trigger's report carries the then-loaded rules' penalty
- [ ] Verified at the assembled-daemon seam: raw nginx-JSON syslog messages in, `GET /reports` JSON out, injected clock
