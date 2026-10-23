# webmedkit

Realtime web log analysis, in two binaries: `bandage` consumes access-log
events, maintains leaky-bucket trackers per target, and publishes
reports; `splint`, the companion binary, turns those reports into ban
rules.

## Operator documentation

- [docs/ingest.md](docs/ingest.md) — ingest transports: choosing
  udp/unixgram/tcp, the tcp framing cost, the UDP kernel-buffer caveat
- [docs/reports.md](docs/reports.md) — the report document contract:
  envelope, record fields and penalty, evolution policy
- [docs/rules.md](docs/rules.md) — writing rules, Match/Trigger
  semantics, and the tracker-less tripwire pattern
- [docs/splint.md](docs/splint.md) — splint, the companion
  binary that installs ban rules from reports: engine options and
  lifecycle, the firewall-driver reference (nftables today),
  deployment and caveats
- [docs/storage.md](docs/storage.md) — the report store on sqlite WAL:
  the files beside the database and backing them up

Example configuration lives in [configs/](configs/) (`bandage.yml`,
`rules.yml`, and the sample `splint.service` systemd unit). The
vocabulary of record is [GLOSSARY.md](GLOSSARY.md); the design plan is
[PLAN.md](PLAN.md); accepted decisions are recorded
as ADRs in [docs/adr/](docs/adr/) — [0008](docs/adr/0008-trigger-semantics-one-live-report.md)
(Trigger semantics) and [0009](docs/adr/0009-wal-with-a-separate-read-path.md)
(WAL and the split read path) govern the behavior the operator docs
describe.

## Development

`make build`, `make test` (race detector), `make bench`. `make build`
produces `bin/bandage` and `bin/splint`, the companion binary that
derives ban rules from reports. Agent-facing
process docs live in [docs/agents/](docs/agents/) and in [AGENTS.md](AGENTS.md).
