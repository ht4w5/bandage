# 01: Walking skeleton — Event to Report list

**What to build:** bandage runs end to end. An operator starts the daemon with a config and a rules file, feeds it access-log Events over syslog, and sees a Report in the JSON report list served over HTTP once a rule's Tracker overflows. Everything is minimal but real: `filter: any`, `rate`/`bandwidth` trackers with explicit leak and volume, one `report` action.

**Blocked by:** None (can start immediately)

**Status:** resolved

- [x] Config is strictly decoded before any socket opens: ingest block keyed by driver (syslog over tcp/udp/unixgram with listen address and parser selection), database block keyed by driver (sqlite with path), api listen address, cache settings; unknown keys and invalid values abort startup.
- [x] A rules file with format version 0 loads: chains of rules, each with an ID, `filter: any`, at most one rate or bandwidth Tracker with explicit leak and volume, and a report Action with required Reason slug (`^[a-z0-9][a-z0-9_-]*$`) and ttl; duplicate rule IDs, `report` without a Tracker, bad Reason slugs, and non-positive ttl are rejected at load.
- [x] `-check` validates config and rules, prints the validated plan, and exits without ingesting anything.
- [x] Syslog ingest parses nginx JSON Events; required fields are validated (time as Unix seconds with fraction UTC, client address, method, path, status 100–599, sent bytes ≥ 0; agent optional; host/server/duration accepted and ignored; unknown fields ignored); malformed lines are dropped and counted.
- [x] rate and bandwidth Trackers implement the leaky-bucket math with event-time decay (`value += increment`, decay `leak × Δt` floored at zero, Overflow strictly above volume) and cache TTL derived as volume/leak.
- [x] A Trigger upserts exactly one Report per (rule, Target): rule, chain, Reason, Target, created/updated/expires timestamps, Tracker reading (kind, value, leak, volume), and Sample (the triggering Event's time, path, agent, status, sent, size). The report action is the only write path.
- [x] Reports persist in sqlite and survive restart; Tracker state is memory-only and restart-cold (per ADR 0002).
- [x] `GET /reports` returns the version-0 report document (generation timestamp plus reports array, RFC 3339 UTC times), sorted by created_at descending, filterable by `?rule=` and `?target=`; `GET /ping` returns liveness; nothing else is exposed and there is no URL version prefix.
- [x] The end-to-end behavior is verified through the primary seam: raw syslog message in, `GET /reports` JSON out, driven by the injected wall clock.

## Answer

Implemented on integration branch `feat/v0-analyzer` (merge commit `a2f3b15`;
followed by cross-ticket code-review fixes through `16735ce`). All nine
checklist items are done and verified at the primary seam (raw nginx-JSON
syslog in → `GET /reports` JSON out, injected wall clock).

Context: spec `../spec.md`, design `../../PLAN.md`, binding implementation
decisions `/home/user2/Devel/bandage-impl-notes/DECISIONS.md`.

Notes:
- `Sample.size` is 0 (FilesizeUnknown) until ticket 05's enrichment landed.
- Follow-up (hardening): `http.Server` has no `ReadHeaderTimeout`; a slow
  client can delay graceful shutdown until the context expires.
