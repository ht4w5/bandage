# 03: Escalation rungs — the ladder end to end (routing actions)

**What to build:** A rule author replaces the tracker's `volume` with an
`escalations` ladder: two or more rungs, each a threshold in the tracker's
quantity (`50MB`, `500`, …) plus its own ordered action list. On every
matching Event, every rung the accumulated value stands above fires,
lowest first — so a `jump`/`goto` handoff rung keeps feeding its
downstream chain per Event while the value stays above its threshold,
instead of flickering on and off. Terminality is decided per *fired* rung:
the chain ends after the rule only when a fired rung carried
report/goto/stop, so a handoff rung below report rungs leaves later rules
running. The tracker cache-entry TTL derives from the ladder's top rung so
state outlives the whole climb. Load refuses every malformed ladder with
an error naming the rule, and `bandage -t` prints each rung with its
threshold and actions so the whole climb is auditable before deploying.
Report actions on rungs write with today's suppression semantics (the
in-place override arrives in ticket 04).

**Blocked by:** 01

**Status:** ready-for-agent

- [ ] A ladder of two or more rungs loads; the rule carries no `actions`
      and no `tracker.volume` beside it
- [ ] On each matching Event the fired rungs are decided once from the
      post-accumulation value, before any action runs, and every fired
      rung runs lowest first
- [ ] A handoff rung fires on every Event while the value stays above its
      threshold, feeding the target chain continuously
- [ ] Chain traversal ends after the rule iff a fired rung carried
      report/goto/stop; a fired `jump` never ends the chain; a fired
      `goto` runs its target chain and ends this chain after the
      remaining fired rungs have run
- [ ] The tracker cache-entry TTL derives from the ladder's top rung
      (with the existing zero-leak default and minimum)
- [ ] Load refuses, each error naming the rule: a ladder beside `actions`
      or beside `tracker.volume`; a ladder without a tracker; fewer than
      two rungs; thresholds not strictly ascending; thresholds that do
      not parse as the track kind's quantity (bytes for bandwidth, plain
      numbers for rate); a ladder on a replay tracker (deferred to ticket
      05, with a clear error saying so)
- [ ] `bandage -t` prints every rung with its threshold and its actions
- [ ] A report action on a rung writes one Report per (rule, Target),
      suppressed while that Report is alive
- [ ] The rules guide documents ladders, including the `jump`-not-`goto`
      handoff idiom (a `goto` rung ends the chain on every Event above
      its threshold)
