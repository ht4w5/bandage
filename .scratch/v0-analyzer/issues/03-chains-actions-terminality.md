# 03: Chains, actions, and terminality

**What to build:** a rule author composes chains: a routing chain classifies Events and dispatches them into topic chains with `goto`/`jump`, `stop` excludes early, `log` debugs live traffic, and the author can trust that traversal can never loop — a cyclic rules file fails `-check`.

**Blocked by:** 01: Walking skeleton — Event to Report list

**Status:** resolved

- [x] Actions run in order when a rule Matches: `report` (from ticket 01), `log` (flux's `"level,message"` shape, logging the Event and the rule's Tracker reading), `goto` (run the target chain, then end this chain), `jump` (run the target chain, then resume this chain), `stop` (end traversal of this chain).
- [x] Terminality is per-rule: a rule containing `report`, `goto`, or `stop` always runs its full action list first, then ends traversal of its chain; other chains are still evaluated for the same Event.
- [x] Chains are traversed in file order, rules within a chain in order, with the first Match per chain terminating as above.
- [x] The `goto`/`jump` graph is validated to be acyclic at rule build time — a cyclic rules file is rejected by `-check`; shared target chains (several chains dispatching to one) are accepted.
- [x] `goto`/`jump` targets that name a nonexistent chain are rejected at load.

## Answer

Implemented on `feat/v0-analyzer` (merge commit `b3e2fd7`). Full action
vocabulary with per-rule terminality, chain-graph validation (dangling
targets, cycles, duplicate chain names), and `log` in flux's
`"level,message"` shape logging the event and tracker reading.

Context: `/home/user2/Devel/bandage-impl-notes/DECISIONS.md` §1 (flux's
goto bug not ported) and §9 (action YAML shapes).

Semantic decision pinned by tests: every chain is traversed for every
event in file order (ticket: "other chains are still evaluated"), so a
goto/jump target chain runs at the dispatch point AND at its own
file-order position. Terminality only ends the containing chain.
