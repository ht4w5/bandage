# 01: Prefactor — one report lifecycle module

**What to build:** Every report mutation — the Trigger write, report
deletion through the API, and the periodic expiry sweep — flows through
one module (the report service) instead of the write path and the
delete/sweep paths reaching into the report repository independently.
Nothing operator-visible changes: the report document, deletion
semantics and expiry semantics are exactly as before. This is the seam
the live-report state of ticket 03 hangs on ("make the change easy,
then make the easy change").

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] Every write, delete and expiry deletion of reports passes through
      the report service; no caller mutates report rows around it
- [ ] The report service's interface coherently covers the Trigger
      write, delete-by-filter and delete-expired; the API and the
      sweeper call it, not the repository directly
- [ ] The report repository adapter keeps its own contract intact
- [ ] No behavior change anywhere: the full suite — including the daemon
      end-to-end tests and the repository contract tests — is green
      under the race detector
