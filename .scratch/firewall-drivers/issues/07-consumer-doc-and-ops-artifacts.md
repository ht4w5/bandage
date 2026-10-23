# 07: Consumer doc and ops artifacts per driver

**What to build:** an operator deploys and verifies `splint` without
reading code, whatever firewall driver they run. The consumer doc
carries a general section — the engine's flags, the merge policy, the
lifecycle, the dry-run audit recipe showing the plan and hash output —
and one section per driver carrying its flags, its targeting and scope
recipes, its Penalty mapping including what it declines, and its
caveats. The sample systemd unit ships with documented install and
enable steps.

**Blocked by:** 04 — Driver-owned identity; 05 — Driver-owned targeting
and enforcement scope; 06 — Firewall driver selection and grouped flags

**Status:** ready-for-agent

- [ ] The consumer doc has a general section: engine flag reference, merge policy, exclusions, lifecycle (startup test install, keep-last, reset-on-exit), dry-run audit recipe with the plan and `hash=` output
- [ ] The doc has one section per firewall driver: its flags, its targeting and enforcement-scope recipes, its Penalty-to-enforcement mapping including its declines, and its caveats
- [ ] The nftables section carries: the kernel floor (~5.9) for reject at prerouting with the startup test install as the guard; the namespace stable-handle recipes; the one-instance-per-enforcement-point discipline
- [ ] The doc carries the cross-cutting caveats: TLS terminates at whatever fronts bandage (which serves plain HTTP); a ban can linger up to one update interval past its Report's expiry; the skip probe is ruleset existence, not rule bodies; a crashed installer's table lingers until reset or reboot
- [ ] The sample systemd unit's install and enable steps are documented and work as written
- [ ] Terminology follows the GLOSSARY (Ban rule, Report, Target, Penalty, Firewall driver); ADR 0012's decisions are stated as fact, not re-litigated
- [ ] Every documented command, flag and output sample is verified against the built binary

Context: spec `../spec.md` (Consumer doc decision; Further Notes);
GLOSSARY's Enforcement cluster; ADR 0012.

