# 01: Penalty on the report action: DSL, validation, `bandage -t`

**What to build:** A rule author declares the enforcement stance a report recommends, directly on the report action beside `reason` and `ttl`: a `penalty:` key taking exactly `drop`, `reject`, `limit-pkt-rate`, `limit-bandwidth` or `limit-req-rate`, and a `rate:` key giving limit penalties their per-second threshold (plain counts like `200`, or decimal human sizes like `1MB` = 1e6, in the unit the penalty name states). The rules loader enforces the validation matrix at load time and the `bandage -t` plan prints each report action's penalty and rate so the author can audit every recommendation before deploying. The rules documentation explains `penalty`/`rate` with worked examples (a tripwire advising `drop`, tracker rules with their idiomatic limits) and the shipped example configs declare a penalty on every report action.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] `penalty:` accepts exactly the five closed values and nothing else
- [ ] `rate:` accepts plain counts and decimal human sizes (`1MB` = 1e6)
- [ ] Load refuses: missing `penalty`; unknown penalty value; `rate` present with `drop`/`reject`; missing or non-positive `rate` with a `limit-*` penalty
- [ ] No coherence check between the penalty and the rule's tracker or reason (ADR 0010)
- [ ] `bandage -t` plan prints penalty and rate for every report action
- [ ] Rules doc gains a `penalty`/`rate` section with worked examples, including the tripwire-with-`drop` pattern and idiomatic tracker→limit pairings
- [ ] Shipped example configs declare a penalty on every report action
- [ ] Tests at the rules-loading seam follow the suite's convention: a failing and a passing case per validation, plus plan-print assertions
