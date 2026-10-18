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
