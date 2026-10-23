# 05: Replay ladders

**What to build:** A ladder on a replay tracker: thresholds in download
equivalents — already normalized by Filesize, so `2` means two full
downloads of that path whether it is a 1MB or a 10GB file — with the same
firing, terminality and override semantics as rate and bandwidth ladders.
Warm-up blindness is preserved: events whose Filesize is unknown skip the
tracker entirely (no increment, no decay). The cache-entry TTL re-derives
per event from the ladder's top rung, so a replay ladder's state outlives
the climb exactly like the other kinds. Volume methods (`constant`,
`clamped-linear`, `inverse-square`, `step`) stay exclusive to the
single-volume form, and load says so.

**Blocked by:** 03

**Status:** ready-for-agent

- [ ] A replay tracker accepts `escalations` with plain-number thresholds
      in download equivalents
- [ ] Events with unknown Filesize skip the tracker entirely (no
      increment, no decay, no cache touch)
- [ ] The cache-entry TTL re-derives per event from the ladder's top rung
- [ ] Load refuses a volume-method block on a ladder rule and a ladder on
      a single-volume rule, each error naming the rule
- [ ] Fired rungs, per-fired-rung terminality and report override behave
      exactly as for rate and bandwidth ladders
