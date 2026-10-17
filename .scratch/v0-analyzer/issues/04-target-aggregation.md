# 04: Target aggregation (`target_prefix`)

**What to build:** an operator groups abusive clients by network: each Tracker declares its Target aggregation, so several source addresses in one prefix share Tracker state and appear as one aggregated Report Target (e.g. IPv6 clients at /64), with IPv6 never reported finer than /64.

**Blocked by:** 01: Walking skeleton — Event to Report list

**Status:** resolved

- [x] Each Tracker declares `target_prefix` with separate IPv4 and IPv6 prefix lengths (default {32, 64}); out-of-range values (IPv4 > 32, IPv6 finer than /64) are rejected at load.
- [x] Tracker state is keyed by the Event's source address aggregated to the Tracker's prefix; the Report Target is that aggregated prefix.
- [x] Two source addresses within one aggregated prefix share one Tracker's state and produce one Report Target; addresses in different prefixes stay separate.
- [x] Both IPv4 and IPv6 sources aggregate correctly, and report targets are rendered as prefixes.

## Answer

Implemented on `feat/v0-analyzer` (merge commit `63b1f48`).
`target_prefix` {ipv4, ipv6} per tracker (default {32, 64}; IPv6 never
finer than /64 — enforced at load and in the aggregation math); tracker
state keyed and Report Target rendered as the canonical aggregated prefix
(`203.0.113.0/24`, `2001:db8::/64`, single hosts as `…/32`). Shared state
per prefix, separation across prefixes, both families, `?target=` matches
the prefix string — all e2e-verified.

Context: `/home/user2/Devel/bandage-impl-notes/DECISIONS.md` §8–§9.
