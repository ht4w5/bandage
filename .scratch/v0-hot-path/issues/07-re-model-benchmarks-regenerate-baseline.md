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

**Status:** resolved

- [x] Episode scenarios replace the overflow-every-event trick (first
      Trigger vs re-arm after delete/expiry), with scenario contracts
      pinned by correctness tests like the existing suite's
- [x] Trigger-path evidence recorded: one write per (rule, Target) per
      report lifetime in the episode scenarios, and the fast-path floors
      unchanged or improved
- [x] The committed benchstat baseline is regenerated wholesale
      (-count=10 with the established hygiene) and its provenance noted
- [x] Results are recorded with method details (GOMAXPROCS, Go version)
      as in the benchmark effort's conventions

## Answer

**What changed**

- **Episode scenarios replace the overflow-every-event trick** (spec
  stories 30–31). The write side of the suite now models report
  episodes — one write per (rule, Target) per report lifetime:
  `first-trigger` (the first Trigger writes, later Triggers in the
  lifetime are suppressed), `rearm-delete` and `rearm-expiry` (the
  operator's delete / report expiry re-arm writing — spec stories 9–10;
  the re-arm step is part of the timed workload). The episode fixture
  has volume above the per-event increment (`volume: 3` = a Trigger per
  `benchEpisodeLen` = 4 events per Target). The trick's fixture
  survives only at `domain/evaluation`, **renamed to what it now
  measures** (`Evaluate/trigger-every` — the Trigger path at one-event
  episodes, its write suppressed above that seam). Files:
  `internal/app/evaluate_bench_test.go` (memRepo + writeLedger +
  countingSink + episodeOracle + the episode scenarios),
  `internal/app/throughput_bench_test.go` (scenario matrix, re-arm at
  drain boundaries, `writes/op` metric),
  `internal/domain/evaluation/evaluation_bench_test.go` (rename).
- **Scenario contracts pinned by correctness tests** in the suite's
  style: `TestEvaluateBenchScenarios` and
  `TestBenchPipelineScenariosMatchTheirNames` compare the run against
  `episodeOracle` (the documented episode semantics simulated from the
  fixture events alone — it can disagree with the code under test) and
  assert **one write per (rule, Target) per report lifetime** per
  (rule, Target, lifetime) cell; `TestBenchChainsMatchTheirNames` pins
  the renamed stub-port fixture. The pins caught two harness bugs
  during the round (a report lifetime that did not roll at the pipeline
  seam; an oracle boundary rolled for first-trigger's whole-run
  lifetime).
- **Committed baseline regenerated wholesale** at
  `.scratch/v0-benchmarks/baseline/{bench-count10.txt,benchstat.txt}`
  with the established hygiene
  (`GOMAXPROCS=22 go test -run=^$ -bench=. -benchmem -count=10 -p=1
  ./...`, benchstat medians of 10). Provenance: 2026-10-18, commit
  `61d1423` (feat/v0-hot-path with tickets 01–05), go1.27.0 linux/amd64,
  GOMAXPROCS=22, Intel Core Ultra 9 185H — recorded in findings.md
  §"Baseline for future regression comparison" and its new
  §"Addendum — v0-hot-path". The write rate is a baseline metric
  (`writes/op`) so the one-write-per-lifetime claim rests on the
  numbers themselves.

**Key numbers** (benchstat medians of 10; method per the benchmark
effort's conventions — GOMAXPROCS=22, go1.27.0 linux/amd64)

- **The claim — Trigger path per-event → per-episode** (Pipeline,
  lines/s at workers 1/2/4/8): the retired per-event write world
  (`match-every`) was flat at 23.3k/21.8k/22.2k/21.7k with ≈1
  write/line. Now `first-trigger` runs 365.7k/370.1k/443.4k/624.0k at
  0.00066 writes/op — one write per (rule, Target) per report
  lifetime — and `rearm-delete` (a write every episode) runs
  237.8k/265.3k/315.5k/411.0k at 0.109 writes/op: both **scale with
  workers** instead of sitting on the write-bound ceiling, and
  `first-trigger` reaches within ~7% of the match-never floor. At the
  evaluate seam the write-per-event cell (`EvaluateSQLite`) moved
  118.4µ/op → 1.214µ (`first-trigger`) / 5.994µ (`rearm-delete`) /
  4.833µ (`rearm-expiry`).
- **One write per (rule, Target) per report lifetime**: asserted per
  cell by both pins, and visible as `writes/op` = 661µ
  (first-trigger), 109m (rearm-delete), 0 (match-never) vs the old
  ≈1.0 (a write per event).
- **Fast-path floors unchanged or improved** (match-never lines/s,
  before → after): Pipeline 206.9k→396.4k (w=1) … 404.5k→668.4k (w=8);
  match-never-evicting 203.1k→371.8k … 389.3k→629.6k; unixgram
  172.9k→314.4k … 360.8k→460.2k; tcp 150.9k→233.9k … 224.5k→230.4k
  (now flat at the ≈230k tcp framing ceiling). The stub-port micro
  floors are unchanged within ~1% by a same-day A/B of old vs new
  fixtures on identical semantics (61d1423): `EvaluateMemory/match-never`
  734n→738n, `Evaluate/match-never` 401n→404n medians — cross-baseline
  micro deltas are run-environment drift.
- **Upsert before/after folded in from ticket 04** (median of 5; raw
  runs at `/tmp/bench-before-raw.txt`, `/tmp/bench-after-raw.txt`;
  full table in ticket 04's answer): memory/insert 31.8µ→10.0µ (−69%),
  memory/update 25.3µ→4.5µ (−82%), file/insert 76.4µ→18.2µ (−76%),
  file/update 63.4µ→8.7µ (−86%); allocs 53–54 → 22. The per-episode
  write is cheap and rare now.

**Context pointers**

- Benchmarks + pins: `internal/app/evaluate_bench_test.go`,
  `internal/app/throughput_bench_test.go`,
  `internal/domain/evaluation/evaluation_bench_test.go`
- Record + method + provenance: `.scratch/v0-benchmarks/findings.md`
  §"Addendum — v0-hot-path" and §"Baseline for future regression
  comparison"; regenerated baseline at
  `.scratch/v0-benchmarks/baseline/{bench-count10.txt,benchstat.txt}`
- Spec: `.scratch/v0-hot-path/spec.md` stories 30–31 and
  Implementation Decisions §"Benchmarks"; exploration notes
  `/tmp/bandage-v0-hot-path-notes/codebase-map.md` §6 (the retired
  trick's three sites)
- Semantics the scenarios model: GLOSSARY **Trigger**, ADR 0008/0009;
  the upsert before/after evidence in ticket 04's answer
  (`.scratch/v0-hot-path/issues/04-store-cheap-upserts-wal-read-split.md`)

**Follow-ups noticed** (not in this ticket): `PipelineIngest/tcp/*`
now sits flat at the ≈230k lines/s framing ceiling at every worker
count (the findings' tcp-disposition stays accurate — docs-only);
micro benchmarks should always be compared same-baseline, never across
rounds (see the addendum's drift note).
