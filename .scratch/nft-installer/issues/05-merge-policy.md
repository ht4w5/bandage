# 05: Merge policy: most specific, then strictest

**What to build:** when reports disagree about overlapping Targets, the
compiled ban rules resolve it exactly as the spec's merge policy states:
the most specific Target wins — even with a weaker stance, so a
fine-grained report carves an exception under a broader ban — ties on
specificity resolve to the strictest Penalty, and limits of incomparable
dimensions are combined rather than arbitrarily ordered. The same reports
always compile to the same ban rules, whatever order they arrive in.

**Blocked by:** 04 — Penalty mapping and direction split

**Status:** ready-for-agent

- [ ] Ban rules group by (family, prefix length, penalty), each holding an equal-length prefix set, and order by prefix length descending then strictness, so nftables first-match reproduces the merge policy
- [ ] A narrower Target wins over a broader one in both directions: a weaker `/32` stance exceptions a stronger `/16` ban, and a stronger `/32` stance tightens under a weaker `/16`
- [ ] Ties on specificity resolve strictest-first: `drop` > `reject` > limits, smaller `rate` stricter within one action
- [ ] Tied limits of different actions combine — one meter per direction, both enforced — with no invented action ordering
- [ ] Permuting the input document's report order produces an identical compiled ruleset (canonical compile)
- [ ] Seam tests cover the exception scenarios in both directions, tie-breaks, combined limits, and order-independence, with a failing and a passing case per rule

Context: spec `../spec.md` (Compilation model: merge policy).
