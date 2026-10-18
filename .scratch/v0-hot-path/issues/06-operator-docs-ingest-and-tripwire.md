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

**Status:** ready-for-agent

- [ ] Ingest guidance recommends udp/unixgram at high rate, with the
      tcp cost and the UDP kernel-buffer caveat stated
- [ ] The tracker-less tripwire pattern is documented with its Trigger
      semantics (single live report per (rule, Target); delete/expiry
      re-arms)
- [ ] The WAL backup note covers the files beside the database and
      checkpointing/backing them up
- [ ] Documentation uses glossary vocabulary (Match, Trigger, Report,
      Target) and agrees with ADR 0008 and ADR 0009
