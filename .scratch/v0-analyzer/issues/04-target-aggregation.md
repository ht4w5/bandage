# 04: Target aggregation (`target_prefix`)

**What to build:** an operator groups abusive clients by network: each Tracker declares its Target aggregation, so several source addresses in one prefix share Tracker state and appear as one aggregated Report Target (e.g. IPv6 clients at /64), with IPv6 never reported finer than /64.

**Blocked by:** 01: Walking skeleton — Event to Report list

**Status:** ready-for-agent

- [ ] Each Tracker declares `target_prefix` with separate IPv4 and IPv6 prefix lengths (default {32, 64}); out-of-range values (IPv4 > 32, IPv6 finer than /64) are rejected at load.
- [ ] Tracker state is keyed by the Event's source address aggregated to the Tracker's prefix; the Report Target is that aggregated prefix.
- [ ] Two source addresses within one aggregated prefix share one Tracker's state and produce one Report Target; addresses in different prefixes stay separate.
- [ ] Both IPv4 and IPv6 sources aggregate correctly, and report targets are rendered as prefixes.
