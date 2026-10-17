# 04: Worker pool and daemon lifetime context

**What to build:** The daemon keeps up with a busy log stream and shuts down predictably. `pipeline.workers` (default: the machine's CPU count) configures N pipeline goroutines and `-w` overrides it with the usual precedence; every received line is processed exactly once across workers, tracker state for a shared Target stays consistent under concurrency, and `pipeline.workers: 1` gives strictly ordered processing for reproducible runs. SIGINT/SIGTERM drains in-flight work first — report upserts complete — and shutdown is bounded even if a store call hangs.

**Blocked by:** 02 — Build identity and the pflag command line

**Status:** ready-for-agent

- [ ] `pipeline.workers` defaults to the CPU count when absent; values below 1 are rejected at config load; `-w` overrides the config value when passed explicitly
- [ ] With several workers, every received line is counted exactly once: received equals parsed plus dropped, with no loss or duplication under `-race`
- [ ] Concurrent Events for one Target never corrupt tracker state: per-key updates stay atomic and accumulation never decays backwards; a duplicate concurrent trigger just refreshes the same (rule, Target) report
- [ ] `pipeline.workers: 1` processes Events strictly in arrival order
- [ ] Shutdown on SIGINT/SIGTERM drains the pipeline first (in-flight report upserts complete), then closes resources; shutdown completes within the caller's deadline even if a store call never returns
- [ ] The report store uses a single connection for both file and memory databases; writes are deterministic under concurrency
- [ ] Docs state that replaying a log *in order* reproduces results (per ADR 0007); the suite passes with several workers under `-race`
