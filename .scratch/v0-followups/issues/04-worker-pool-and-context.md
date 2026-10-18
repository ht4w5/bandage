# 04: Worker pool and daemon lifetime context

**What to build:** The daemon keeps up with a busy log stream and shuts down predictably. `pipeline.workers` (default: the machine's CPU count) configures N pipeline goroutines and `-w` overrides it with the usual precedence; every received line is processed exactly once across workers, tracker state for a shared Target stays consistent under concurrency, and `pipeline.workers: 1` gives strictly ordered processing for reproducible runs. SIGINT/SIGTERM drains in-flight work first — report upserts complete — and shutdown is bounded even if a store call hangs.

**Blocked by:** 02 — Build identity and the pflag command line

**Status:** resolved

- [x] `pipeline.workers` defaults to the CPU count when absent; values below 1 are rejected at config load; `-w` overrides the config value when passed explicitly
- [x] With several workers, every received line is counted exactly once: received equals parsed plus dropped, with no loss or duplication under `-race`
- [x] Concurrent Events for one Target never corrupt tracker state: per-key updates stay atomic and accumulation never decays backwards; a duplicate concurrent trigger just refreshes the same (rule, Target) report
- [x] `pipeline.workers: 1` processes Events strictly in arrival order
- [x] Shutdown on SIGINT/SIGTERM drains the pipeline first (in-flight report upserts complete), then closes resources; shutdown completes within the caller's deadline even if a store call never returns
- [x] The report store uses a single connection for both file and memory databases; writes are deterministic under concurrency
- [x] Docs state that replaying a log *in order* reproduces results (per ADR 0007); the suite passes with several workers under `-race`

## Answer

Implemented on integration branch `feat/v0-followups` (merge commit
`c9c647d`; cross-ticket code-review fixes through `a69fb58`).
`pipeline.workers` (strict, CPU-count default) with `-w` override; N
pipeline goroutines with exactly-once accounting and atomic per-key
tracker updates; strict order at `workers: 1`; daemon lifetime context
from SIGINT/SIGTERM with drain-first bounded shutdown; sqlite single
connection for file and memory databases.

Context: spec `../spec.md`, `../../docs/adr/0007-relaxed-event-ordering-worker-pool.md`.

Notes:
- A wedged store is injected through a new unexported `withStore` option
  (not in the spec's seam list) to prove bounded shutdown without sleeps.
- The code-review follow-up (`a69fb58`) moved the `-w` flag's ≥1 check to
  resolution (story 16: the resolved count is never below 1).
