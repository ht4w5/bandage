# 02: Filter language on rules

**What to build:** a rule author writes `filter` expressions in the webjail language so rules select exactly the Events they care about; a typo in an expression is caught by `-check` with a precise position instead of silently mis-selecting at runtime.

**Blocked by:** 01: Walking skeleton — Event to Report list

**Status:** resolved

- [x] Filters support the full v0 primitive set with exact-match semantics: `any`, `none`, `src` (address or prefix), `method` word, `path` with exact/prefix/suffix/keyword forms, `agent` with exact/keyword forms, `status` (code or class), `sent >=`/`<=` size with binary units, combined with `and`/`or`/`not` and parentheses in webjail's precedence.
- [x] A rule's filter gates its Tracker: non-matching Events neither accumulate nor decay that rule's Tracker, and never Match it.
- [x] Filter syntax and value errors surface from `-check` with line and column, and an unparseable filter rejects the rules file before ingest.
- [x] The prior-art filter test suites (parse trees, error positions, matching semantics) are ported and pass against the rule-level behavior.

## Answer

Implemented on `feat/v0-analyzer` (merge commit `9446791`). The webjail v0
filter language is ported into `internal/bandage/filter` (lexer/parser/AST,
exact-match semantics, positioned `ParseError{Line, Col}` per
`porting-notes.md` §F, binary size units per §E); filters gate trackers at
the evaluation seam; `-check` reports `filter: L:C: message` and the plan
prints each rule's filter source. Test suites (parse trees, error
positions, matching semantics) were authored fresh — webjail has none
(DECISIONS §2).

Context: `/home/user2/Devel/bandage-impl-notes/{webjail-map,porting-notes,DECISIONS}.md`.
