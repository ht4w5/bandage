# 01: Rename the adapter tree to infra

**What to build:** The internal adapter tree — the memory tracker cache, syslog ingest, nginx parser, sqlite report repository and HTTP API — carries the name the team uses for it (`infra`), with subpackage names and behavior untouched. Nothing operator-visible changes; the point is that the code layout matches how we talk about the code before further work lands on it.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] The tree is renamed and every import resolves; build and the full race-enabled suite pass unchanged
- [ ] Subpackage names are unchanged (memory cache, syslog ingest, nginx parser, sqlite persistence, HTTP API)
- [ ] No reference to the old tree name remains in code, package docs or design documents (archived issue-tracker history excepted)
- [ ] No behavior change: no test edits beyond the rename itself
