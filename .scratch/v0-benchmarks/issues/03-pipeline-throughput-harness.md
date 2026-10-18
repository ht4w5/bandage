# 03 — Pipeline throughput and worker scaling (spec Phase 2)

Type: task
Status: ready-for-agent
Depends on: 01

Measure the assembled pipeline, not the parts: sustained lines/sec and
where it saturates.

## Scope

- In-package end-to-end harness driving the real `runPipeline` chain
  with a pre-generated corpus (no network in the timed path): workers =
  1/2/4/8; tracker cache sized to avoid evictions, plus a second run
  with an evicting cap.
- Ingest-inclusive variant over a real loopback syslog socket (tcp and
  unixgram) to capture go-syslog and channel-handoff cost. H5.
- Match-path scenarios: rules that fire on every event vs. rules that
  never fire, isolating report-write cost. H4.
- Record allocs/op, GC fraction and the daemon `/stats` counters beside
  throughput.

## Done when

- A lines/sec number per worker count per scenario exists, the scaling
  curve's flatten point is named, and raw results are recorded under
  `## Answer` in this file.
