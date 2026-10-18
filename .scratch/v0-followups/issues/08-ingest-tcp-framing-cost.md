# 08 — Reduce ingest tcp framing cost (go-syslog scan path)

Type: task
Status: needs-triage
Evidence: `.scratch/v0-benchmarks/findings.md` § Worker-scaling
attribution, H5 verdict (partial).

Ingest over tcp caps the pipeline at 222.6k lines/s (flattens at
workers = 4) versus 396.4k with no socket, and costs ~1.9µs/line on
top of the pipeline. The CPU profile attributes 21.5% of all samples
to go-syslog's `Server.scan` chain (bufio.Scanner 13.6%, rfc3164
parser 7.3%, format.detect 1.65%, Dump 1.53%); one scanner goroutine
per connection makes it a serial stage. unixgram is much cheaper
(−11%).

## Scope

- Measure and reduce the daemon-side per-line ingest cost for tcp:
  framing/format detection/Dump allocations in the go-syslog path, the
  parts→lines forwarding step, or a replacement/framing bypass where
  safe. Keep the syslog surface (networks, framing, format acceptance)
  unchanged unless a config-compatible improvement is obvious.
- Decide explicitly whether the tcp ceiling matters for the supported
  deployments (unixgram is the shipped default in
  `configs/bandage.yml`); a documented "won't fix — unixgram
  supported" verdict is acceptable if the evidence supports it.

## Done when

- Either a measured improvement (benchstat vs baseline for
  `PipelineIngest/tcp/*`) or an evidence-backed wontfix note in this
  issue, with `make test` green either way.
