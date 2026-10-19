# 09: Deployment artifacts and consumer-doc pass

**What to build:** an operator deploys and verifies `splint-nft` without
reading code: a shipped sample systemd unit, a dry-run audit recipe, and one
consumer document carrying the flags, the penalty-to-nftables mapping table,
the merge policy, the exclusion defaults, and the caveats — kernel floor for
reject at prerouting, TLS termination being a deployment concern, ban
staleness bounded by the update interval, one instance per namespace.

**Blocked by:** 03 — Safety; 04 — Penalty mapping; 05 — Merge policy;
06 — Ruleset identity; 07 — Netns targeting; 08 — mTLS fetch

**Status:** resolved

- [x] A sample systemd unit ships with the repo and installs/enables per its documented steps
- [x] The dry-run audit recipe shows an operator how to preview and verify a ruleset before enforcing
- [x] The consumer doc carries: the flag reference, the penalty→nftables mapping table, the merge policy, the exclusion and prefilter defaults
- [x] The consumer doc carries the caveats: kernel floor (~5.9) for reject at prerouting with the startup test install as the guard; TLS terminates at whatever fronts bandage (which serves plain HTTP); a ban can linger up to one update interval past its Report's expiry; one instance per namespace
- [x] The network-namespace recipes are documented (stable handle via an ip-netns-attach-style name; Docker's per-pid namespace path)
- [x] Doc and spec terminology follow the GLOSSARY (Ban rule, Report, Target, Penalty)

Implemented on integration branch `feat/splint-nft` (merge commit `62a0e10`; cross-ticket code-review fixes through `1879da4`). GLOSSARY and ADR 0004/0011 already carried the splint-nft content (committed with the spec) and were verified against the implementation rather than rewritten.

Context: spec `../spec.md`; ADR 0011; GLOSSARY's Ban rule entry.
