# 06: Shipped ladder example and reference docs

**What to build:** The shipped rules config gains a worked escalation
ladder — handoff rung, throttle recommendation, ban — that validates,
prints its whole climb in `bandage -t`, and stands as the reference
example operators copy. The rules guide's escalation section completes
(worked example, per-kind quantities, per-fired-rung terminality, the
in-place override and its freeze rules, the jump-not-goto handoff idiom),
and the rules format and validation reference sections describe the
ladder and its load-time matrix, so the documentation set and the
implementation cannot drift.

**Blocked by:** 04, 05

**Status:** ready-for-agent

- [ ] The shipped rules config carries a worked ladder (handoff →
      throttle → ban) that loads and validates
- [ ] `bandage -t` on the shipped config shows every rung with its
      threshold and actions
- [ ] The rules guide's escalation section is complete with the worked
      example and the handoff idiom
- [ ] The rules format and validation reference sections describe the
      ladder, the per-kind threshold quantities and the full load-time
      validation matrix
- [ ] No documented behaviour in the set describes anything the
      implementation does not do, and vice versa
