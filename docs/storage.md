# Report storage: WAL files and backups

Reports live in one sqlite database (`db.sqlite.path`, e.g.
`/var/lib/bandage/reports.db` — see `configs/bandage.yml`), one row per
(rule, Target). Reports survive restarts; tracker state is memory-only
(ADR 0002). The file database runs `journal_mode=WAL` with
`synchronous=NORMAL`: writes go through a single connection and API
reads use their own, so `GET /reports` never queues behind upserts
([ADR 0009](adr/0009-wal-with-a-separate-read-path.md)).

## The files beside the database

In WAL mode the database is not one file. While bandage runs (and after
an unclean stop) these live beside the main file:

- `reports.db` — the main database file;
- `reports.db-wal` — the write-ahead log: committed reports not yet
  folded back into the main file;
- `reports.db-shm` — scratch shared memory for the WAL.

A backup that copies `reports.db` alone while bandage runs restores a
stale view: everything still in the `-wal` is missing. Back up with one
of these instead:

1. **Stop bandage, then copy `reports.db`.** A clean shutdown
   checkpoints the WAL into the database and removes the `-wal`/`-shm`
   files, so the single file is complete.
2. **Back up live with sqlite's own backup machinery** — it reads a
   consistent snapshot while bandage keeps writing:
   `sqlite3 /var/lib/bandage/reports.db ".backup /backups/reports.db"`
   (or `VACUUM INTO`).
3. **Checkpoint, then copy everything present.** `sqlite3
   /var/lib/bandage/reports.db "PRAGMA wal_checkpoint(TRUNCATE);"`
   folds the WAL into the main file; if you copy while bandage runs,
   take `reports.db-wal` (and `-shm`) along with `reports.db` — a
   file-level copy of a live database is race-prone, so prefer 1 or 2
   (ADR 0009: backups checkpoint or include the WAL files).

Restore what you copied **together**: dropping a bare `reports.db` back
into place without the `-wal` that came with it loses everything that
log carried. The side files are recreated on the next start; after a
restore there is nothing to clean up manually.

## Durability and placement

- `synchronous=NORMAL` in WAL mode: a committed report survives a
  process crash; only power failure can lose the final moments (ADR
  0009 — the loss window a restart re-discovers anyway).
- WAL does not work over network filesystems. Keep `db.sqlite.path` on
  local storage (ADR 0009).
