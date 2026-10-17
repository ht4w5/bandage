# 02: Filter language on rules

**What to build:** a rule author writes `filter` expressions in the webjail language so rules select exactly the Events they care about; a typo in an expression is caught by `-check` with a precise position instead of silently mis-selecting at runtime.

**Blocked by:** 01: Walking skeleton — Event to Report list

**Status:** ready-for-agent

- [ ] Filters support the full v0 primitive set with exact-match semantics: `any`, `none`, `src` (address or prefix), `method` word, `path` with exact/prefix/suffix/keyword forms, `agent` with exact/keyword forms, `status` (code or class), `sent >=`/`<=` size with binary units, combined with `and`/`or`/`not` and parentheses in webjail's precedence.
- [ ] A rule's filter gates its Tracker: non-matching Events neither accumulate nor decay that rule's Tracker, and never Match it.
- [ ] Filter syntax and value errors surface from `-check` with line and column, and an unparseable filter rejects the rules file before ingest.
- [ ] The prior-art filter test suites (parse trees, error positions, matching semantics) are ported and pass against the rule-level behavior.
