# 06: Operator docs — ingest transport and the tripwire pattern

**What to build:** Operators can deploy and configure the cheap path
from the docs alone. Ingest guidance recommends udp/unixgram for
high-rate deployments and spells out the tcp framing cost and the UDP
kernel-buffer drop caveat; the tracker-less tripwire pattern (agent
keyword filter plus a report action, no tracker) is documented beside
the rules documentation with its Trigger semantics (one write per
(rule, Target) per report lifetime; delete or expiry re-arms); and the
WAL backup note warns that database files now live beside the main
file. All of it speaks the glossary's language and matches ADR 0008 and
ADR 0009.

**Blocked by:** 02 (Trigger empties the rule's tracker), 03 (Suppress
the report write while a report is alive), 04 (Report store — cheap
upserts, WAL, split read path) — docs describe shipped behavior

**Status:** resolved

- [x] Ingest guidance recommends udp/unixgram at high rate, with the
      tcp cost and the UDP kernel-buffer caveat stated
- [x] The tracker-less tripwire pattern is documented with its Trigger
      semantics (single live report per (rule, Target); delete/expiry
      re-arms)
- [x] The WAL backup note covers the files beside the database and
      checkpointing/backing them up
- [x] Documentation uses glossary vocabulary (Match, Trigger, Report,
      Target) and agrees with ADR 0008 and ADR 0009

## Answer

Operator docs are born here, as `docs/*.md` with a root `README.md`
pointer (the repo had none — PLAN.md §7/8 and config comments were the
only prose). Written against the shipped behavior pinned by the tests
in `bandage/internal/app` (suppress/trigger semantics), `bandage/internal/domain/report`
and `bandage/internal/infra/persistence/sqlite` (WAL, read split):

- `docs/ingest.md` — ingest transport guidance: udp/unixgram recommended
  at high rate (one datagram is one message, no framing, no per-sender
  state); the tcp cost spelled out (per-connection goroutine + scanner,
  newline/RFC-6587 framing per message, head-of-line blocking, a
  >64 KiB message ends the connection's stream — verified against
  go-syslog.v2's scan loop and bufio.Scanner's token limit); the UDP
  kernel-buffer caveat (64 KiB read buffer request, `net.core.rmem_max`
  clamps, silent kernel drops invisible to `received`/`dropped`, watch
  `UdpRcvbufErrors`, unixgram pushes back on the sender instead).
- `docs/rules.md` — the rules documentation (rule anatomy, Match/Trigger
  recap per GLOSSARY and ADR 0008, `bandage -t` validation) with the
  tracker-less tripwire pattern beside it: `agent keyword "curl"` filter
  + report action, no tracker. Its Trigger semantics: every matching
  event Triggers; one write per (rule, Target) per report lifetime
  (Sample and update time freeze while alive, other actions keep
  running); delete/expiry re-arms (next matching event writes
  immediately for tracker-less rules, fresh accumulation episode for
  tracker rules); restart re-derives suppression from the report table;
  Target is the default aggregation (per address IPv4 / per /64 IPv6 —
  `TrackerConfig.TargetString` nil-falls-back, `bandage/internal/domain/target.go`);
  reason slug contract per ADR 0004.
- `docs/storage.md` — the WAL backup note: `reports.db-wal`/`-shm` beside
  `reports.db`, stale-copy hazard of backing up the main file alone,
  checkpoint (`PRAGMA wal_checkpoint(TRUNCATE)`), stop-and-copy or
  sqlite `.backup`/`VACUUM INTO`, restore the files together,
  `synchronous=NORMAL` durability and the network-filesystem ban (ADR
  0009).
- `README.md` — root pointer to the three docs plus configs/, GLOSSARY,
  PLAN, ADR 0008/0009.

No new terms (all prose is glossary vocabulary: Match, Trigger, Report,
Target, Sample, Reason, Ban rule) and no config surface — only the
existing keys in `configs/bandage.yml` are documented. No test suites
added for prose; `make test` (race detector) stays green.

Context pointers: GLOSSARY.md; ADR 0008 (Trigger semantics), ADR 0009
(WAL + separate read path), ADR 0004 (reason slug); spec stories 28–29
and Implementation Decisions 'Docs'; oracle tests
`bandage/internal/app/suppress_test.go` (incl. `tripwireRules` fixture),
`bandage/internal/app/trigger_test.go`, `bandage/internal/domain/report/*_test.go`,
`bandage/internal/infra/persistence/sqlite/*_test.go`; notes
/tmp/bandage-v0-hot-path-notes/codebase-map.md §7 (surprise #3).

Follow-up (out of scope here): PLAN.md §8 still lists "`report` on a
tracker-less rule" as a load-time rejection, which ticket 03 removed
(loader accepts it now, `rules_test.go:169`) — the plan predates the
suppression decision and could use a correction note.

Implemented on integration branch `feat/v0-hot-path` (merge commit
`aa300c8`; cross-ticket code-review fixes through `78386ca`, including
the PLAN.md alignment). Context: spec `../spec.md`, `docs/adr/0008` and
`docs/adr/0009`.
