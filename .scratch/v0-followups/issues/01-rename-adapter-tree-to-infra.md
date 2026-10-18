# 01: Rename the adapter tree to infra

**What to build:** The internal adapter tree — the memory tracker cache, syslog ingest, nginx parser, sqlite report repository and HTTP API — carries the name the team uses for it (`infra`), with subpackage names and behavior untouched. Nothing operator-visible changes; the point is that the code layout matches how we talk about the code before further work lands on it.

**Blocked by:** None (can start immediately)

**Status:** resolved

- [x] The tree is renamed and every import resolves; build and the full race-enabled suite pass unchanged
- [x] Subpackage names are unchanged (memory cache, syslog ingest, nginx parser, sqlite persistence, HTTP API)
- [x] No reference to the old tree name remains in code, package docs or design documents (archived issue-tracker history excepted)
- [x] No behavior change: no test edits beyond the rename itself

## Answer

Implemented on integration branch `feat/v0-followups` (merge commit
`b79c9f3`; cross-ticket code-review fixes through `a69fb58`). The tree
moved by `git mv` (pure renames), the five app-wiring imports and
PLAN.md's layout sections followed, and the full race suite passed with
zero assertion edits.

Context: spec `../spec.md`, layout of record `../../PLAN.md`.

Note: the code review found two comments still saying "its adapters"
generically; reworded to "the infra tree" in the review pass.
