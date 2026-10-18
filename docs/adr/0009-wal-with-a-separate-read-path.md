# WAL with a separate read path

The report store serialized everything through one connection so writes
landed deterministically (ADR 0007), but the 2026 benchmark round showed
API reads contending with upserts on that same connection. We switch the
file database to `journal_mode=WAL` with `synchronous=NORMAL` (safe
across process crashes; recent commits may be lost only on power failure
— within the deferral window ADR 0008 accepts) and split the paths:
**writes keep the single connection** (write determinism stands), while
**reads get their own connections**, so `GET /reports` never queues
behind upserts. WAL adds no write parallelism — sqlite is single-writer
in every journal mode.

Consequences: `:memory:` test databases ignore WAL, and two connections
to `:memory:` are separate databases — tests use a shared-cache URI or
stay single-connection. WAL files live beside the database (backups
checkpoint or include them), and WAL does not work over network
filesystems.
