# 07: Re-model benchmark scenarios, regenerate the baseline

**What to build:** The benchmark suite measures the world the new
semantics create. The overflow-every-event trick (volume below the
per-event increment) is retired or renamed to what it now measures;
scenarios model first-Trigger and re-arm-after-delete/expiry episodes.
The committed benchstat baseline is regenerated wholesale so future
regression comparisons rest on honest numbers, and the spec's
performance claim — the Trigger path moves from a per-event cost to a
per-episode cost — is confirmed with numbers.

**Blocked by:** 02 (Trigger empties the rule's tracker), 03 (Suppress
the report write while a report is alive), 04 (Report store — cheap
upserts, WAL, split read path), 05 (Parser rewrite on encoding/json/v2)
— numbers must reflect the final state

**Status:** ready-for-agent

- [ ] Episode scenarios replace the overflow-every-event trick (first
      Trigger vs re-arm after delete/expiry), with scenario contracts
      pinned by correctness tests like the existing suite's
- [ ] Trigger-path evidence recorded: one write per (rule, Target) per
      report lifetime in the episode scenarios, and the fast-path floors
      unchanged or improved
- [ ] The committed benchstat baseline is regenerated wholesale
      (-count=10 with the established hygiene) and its provenance noted
- [ ] Results are recorded with method details (GOMAXPROCS, Go version)
      as in the benchmark effort's conventions
