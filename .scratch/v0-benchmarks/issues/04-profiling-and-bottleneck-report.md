# 04 — Profiling, attribution and bottleneck report (spec Phases 3–4)

Type: research
Status: ready-for-agent
Blocked by: 02, 03

Attribute the measured cost to code and produce the ranked bottleneck
report.

## Scope

- Profiles on the pipeline benchmark (Go 1.27 toolchain):
  `-cpuprofile`, `-memprofile`, `-mutexprofile`, `-blockprofile`; top
  frames attributed per stage of the spec's hot-path inventory.
- Worker-scaling attribution: which profile frames explain the
  saturation point found in ticket 03?
- Verdict per hypothesis H1–H6 (confirmed / refuted / partial) with
  evidence quoted from profiles and microbenchmarks.
- Method hygiene: benchstat (`-count=10`), fixed `GOMAXPROCS` noted,
  machine and Go version recorded.
- Write `findings.md` in this effort directory: ranked bottleneck table
  (ns/op, B/op, allocs/op, % of pipeline time, lines/sec/core),
  hypothesis verdicts, and recommended fixes as follow-up issues —
  created only from evidence, ordered by measured impact.
- Commit the baseline benchstat output for future regression comparison.

## Done when

- `findings.md` exists with the ranked table, every hypothesis has an
  evidence-backed verdict, and follow-up issues (if any) are filed and
  linked from `findings.md`.

## Answer

Attribution done with pprof on the ticket-03 pipeline benchmarks
(go1.27.0, linux/amd64, Intel Core Ultra 9 185H, 22 logical CPUs,
**GOMAXPROCS=22 pinned**, quiet-but-not-isolated machine). The full
report is [`findings.md`](../findings.md); method hygiene and exact
reproduction commands live there.

**Baseline (committed)** — `GOMAXPROCS=22 go test -run=^$ -bench=.
-benchmem -count=10 -p=1 ./...` (whole suite, packages serial),
benchstat summary beside it: `baseline/bench-count10.txt` +
`baseline/benchstat.txt`. Key medians: match-never 204.1k → 396.4k
lines/s (workers 1 → 8); match-every flat 23.6k → 21.9k;
tcp/match-never 147.8k → 222.6k (flatten at workers = 4). Profile
extracts (`-cpuprofile/-memprofile/-mutexprofile/-blockprofile`,
selections mn1/mn8/me1/me8/tcpmn8) committed under `profiles/`.

**Ranked bottlenecks** (% of pipeline = CPU-profile share of
`runPipeline`; lines/sec/core = 1e9/ns/op serial, throughput ÷ workers
for pipeline rows): 1) **report write (on match)** 31.4µs/upsert
(`:memory:`) / 75.9µs (file), 53–54 allocs — **82% of write-path CPU**,
31.9k lines/sec/core; 2) **parse** 3.019µs (full), 32 allocs/1.5KiB —
**83% of fast-path CPU**, 331k lines/sec/core; 3) **tcp ingest** ≈
+1.9µs/line, ceiling 222.6k lines/s; 4) **evaluate** 739ns/1.505µs —
5–6%; 5) **enrich + 2× store update** ≈ 230ns — ~4%; 6)
**`progress.bump`** 48.4ns + 112B/line — 2% CPU but 25.5% of mutex
contention. GC is the cross-cutting tail: gc-pause-frac 1.2% → 4.7%
with worker count.

**Worker-scaling attribution** — match-every's workers=1 saturation is
the single-connection sqlite upsert: `Upsert` = 83.8% of pipeline CPU
and `DB.BeginTx → DB.conn` = **62.7% of all blocking delay (≈ workers ×
runtime queued on one connection)**. match-never's sublinearity is feed
handoff + GC, not a lock: workers block on `d.lines` (2.87s vs 0.65s of
feeder back-pressure), the fleet only sustains ~3.4 busy cores at
workers = 8, GC worsens with scale. tcp's workers=4 flatten is the
single-threaded go-syslog scan chain (21.5% of all samples).

**Verdicts** — H1 **confirmed** (parse = 83% fast-path CPU, 75% of
alloc objects, generic-map unmarshal = 87% of parse); H2 **partial**
(real global cost: parallel bump slower than serial, largest mutex-delay
site, 112B/line churn — but ~20M lines/s serialization ceiling is not
today's flatten); H3 **partial** (per-call 32B concat confirmed and
small; hot-key contention refuted at pipeline scale — 0.7% of mutex
delay despite the Zipf corpus); H4 **confirmed/dominant** (see above;
match-every costs 8.6× match-never and never scales); H5 **partial**
(ingest-before-pipeline ceiling confirmed for tcp, −44% at workers = 8;
the unbuffered handoff itself is minor — same handoff carries 396k
lines/s); H6 **partial** (clean O(rules) at ~12.5ns/rule, zero allocs,
but <1% at realistic rule counts; material only at ≥100 rules/chain).

**Follow-up issues filed from evidence, ordered by measured impact**
(the standing `.scratch/v0-followups/issues/` tracker, continuing its
numbering after its earlier 01–05): 06-batch-report-persistence (H4),
07-cut-parse-allocations (H1), 08-ingest-tcp-framing-cost (H5),
09-deglobalize-progress-bump (H2), 10-alloc-free-store-keys (H3). No
issue for H6 (threshold documented) or the read path (off hot path at
v0 scale).
