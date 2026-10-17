# Spec: v0 follow-ups — build identity, CLI, logging, worker pool, stats

Status: ready-for-agent

## Problem Statement

bandage v0 analyzes logs and serves reports correctly, but the operating
and developer experience around it is thin. Operators cannot tell which
build of the daemon is running (there is no version output and no build
identity in logs), cannot interrogate the daemon's health without reading
periodic log lines (there is no queryable surface for drop accounting or
tracker cache pressure), and cannot make the daemon keep up with a busy
log stream because events are processed by a single goroutine with no way
to tune parallelism. The command line is stdlib-flag long-only (no
shorthands, no version or help flag), logging is `slog` text with a
flag-only level, shutdown does not observe cancellation (a wedged
database call would hang shutdown forever), and the code layout names its
adapter tree something the team doesn't call it.

## Solution

bandage gains an operator-facing polish pass. A Makefile injects build
identity (version, commit, build date, dirty flag) into a dedicated
identity module; `bandage -v` prints it, startup logs carry it, and the
new human-facing `GET /stats` endpoint shows it alongside cumulative
pipeline and tracker cache counters. The CLI moves to pflag with
shorthands (`-c`, `-r`, `-t`, `-l`, `-w`, `-v`, `-h`), where `-t/--test`
replaces `-check`. Logging moves to zerolog with a single `log.level`
config key. The pipeline runs on N worker goroutines (`pipeline.workers`
config, `-w` override, defaulting to the CPU count), with per-Target
tracker updates staying atomic and a `workers: 1` escape hatch for strict
ordering. A daemon-lifetime context flows through the pipeline and
sweeper, and shutdown drains in-flight work first and cancels only as a
bounded backstop. The adapter tree is renamed `infra`.

## User Stories

1. As an operator, I want `bandage -v` to print the build identity (name, version, commit, build date, Go version, platform), so that I can tell exactly which build is deployed.
2. As an operator, I want `bandage -h` to print usage and exit successfully, so that I can discover the flags without reading docs.
3. As an operator, I want shorthand flags (`-c`, `-r`, `-t`, `-l`, `-w`, `-v`, `-h`) alongside the long forms, so that routine invocations are quick to type.
4. As an operator, I want an unknown flag to print the error plus usage and exit non-zero, so that typos fail loudly instead of being ignored.
5. As an operator, I want `bandage --test` to validate config and rules and print the validated plan without ingesting anything, so that I can review a deployment safely (this replaces `bandage -check`).
6. As an operator, I want the `--test` plan output to open with the build identity header, so that I know which build produced the plan.
7. As an operator, I want to override the configured log level with `-l/--log-level`, so that I can raise verbosity for one run without editing the config file.
8. As an operator, I want to override the configured worker count with `-w/--workers`, so that I can tune parallelism per machine without editing the config file.
9. As an operator, I want explicit command-line flags to win over config file values, and config file values over built-in defaults, so that precedence is predictable.
10. As an operator, I want a `log.level` config key (`debug`, `info`, `warn`, `error`; default `info`), so that logging is deployment configuration rather than a startup flag I must remember.
11. As an operator, I want logs written as structured records with the message and its fields intact (rule, target, tracker reading on `log` actions; identity fields at startup), so that log output stays greppable and machine-readable.
12. As an operator, I want every log level word accepted for the rules DSL's `log` action to be a level the daemon logger actually honors, so that a `log` action's level and the log level filter mean the same thing.
13. As a rule author, I want the `log` action's level vocabulary to stay exactly `debug`, `info`, `warn`, `error`, so that no rule can ever force a process exit or an above-error severity.
14. As an operator, I want the daemon's startup log record to carry name, version, commit and build date, so that the log stream itself identifies the running build.
15. As an operator, I want a `pipeline.workers` config key (default: the machine's CPU count), so that the daemon scales its event processing to the hardware without tuning.
16. As an operator, I want the resolved worker count to be at least 1 and invalid values rejected at load time, so that a broken config never reaches the running daemon.
17. As an operator, I want every received line processed exactly once across all workers, so that the received/parsed/dropped accounting stays exact under load.
18. As an operator, I want Events for the same Target processed without corrupting tracker state, so that concurrency never double-counts or loses accumulation.
19. As an operator, I want `pipeline.workers: 1` to restore strict arrival-order processing, so that I have an escape hatch when I need bit-for-bit reproducible runs.
20. As an operator, I want replaying a log file in order to reproduce results, so that I can verify daemon behavior against known traffic (results may differ marginally from a live run at higher worker counts).
21. As an operator, I want `GET /stats` to answer with the daemon's build identity and cumulative counters, so that I can see health without scraping logs.
22. As an operator, I want `/stats` to show received, parsed and dropped line counts since start, so that I can spot ingestion problems.
23. As an operator, I want `/stats` to show tracker cache gets, sets, misses, evictions, current size and the entry cap, so that I can see cache pressure and whether Evictions are resetting tracker state.
24. As an operator, I want `/stats` to show the worker count, uptime and a generation timestamp, so that the snapshot is self-describing.
25. As an operator, I want `/stats` served read-only on the same listener as the report API, so that one address covers all operational access.
26. As an operator, I want `/stats` to be explicitly human-facing and unversioned, so that I read it with my eyes and don't build tooling against it; if I need machine metrics I can ask for the future Prometheus-format endpoint.
27. As an operator, I want the periodic statistics log line to keep flowing, so that long-running daemons leave a health trail even when nobody polls `/stats`.
28. As an operator, I want every Eviction logged and counted with its tracker namespace and Target, so that an emptied bucket never resets silently.
29. As an operator, I want those log records and docs to say "eviction", matching the counters, so that one word means one thing everywhere.
30. As an operator, I want SIGINT/SIGTERM to shut the daemon down with a graceful drain first, so that events already in the pipeline finish and their report upserts complete before exit.
31. As an operator, I want shutdown to be bounded even if a database call hangs, so that the daemon cannot wedge forever on the way down.
32. As an operator, I want in-flight tracker updates and report writes to complete normally during shutdown, so that a clean stop loses no evidence.
33. As a release engineer, I want `make build` to inject version, commit, build date and dirty state into the binary, so that every artifact is self-identifying.
34. As a release engineer, I want the version seeded from a version file and the commit/dirty flag read from git, so that a release build needs no manual bookkeeping.
35. As a release engineer, I want reproducible build dates via `SOURCE_DATE_EPOCH`, so that bit-reproducible release builds are possible.
36. As a release engineer, I want uncommitted builds marked dirty, so that a binary built from a modified tree is never mistaken for a clean release.
37. As a release engineer, I want `make test` to run the whole suite with the race detector, so that the worker pool's concurrency is exercised on every run.
38. As a release engineer, I want `make clean` to remove build output, so that the tree resets predictably.
39. As a developer, I want the adapter tree named `infra`, so that the code layout matches how the team talks about the code.
40. As a developer, I want the domain's dependency rule (stdlib plus domain only) to survive the logging migration, so that the domain core stays free of third-party imports.
41. As a developer, I want the logging implementation behind a tiny logger port declared beside its one consumer, so that the domain's `log` action stays testable and swap-friendly.
42. As a developer, I want one program-wide logger built from the config, so that construction and level policy live in one place.
43. As a developer, I want config and rules validation to reject unknown keys and invalid values for the new settings before any socket opens, so that strict loading stays strict.
44. As a report consumer, I want the report API to behave exactly as before (list, filter, delete, ping), so that this work breaks no downstream tooling.
45. As an operator, I want the API docs to explain plainly that deleting reports does not touch tracker state and a still-overflowing Target is reported again on the next trigger, so that deletion semantics are unambiguous without jargon.
46. As a downstream tool maintainer, I want the report document's format version and shape untouched, so that my ban-rule derivation keeps working.

## Implementation Decisions

**Adapter tree rename.** The internal adapter tree is renamed to `infra`;
subpackage names (memory cache, syslog ingest, nginx parser, sqlite
persistence, HTTP API) are unchanged. The only import churn is in the app
wiring; documentation layout sections follow the rename.

**Build identity module (mirrors bandaid's).** A small identity module
holds the name plus four linker-injected values: version, commit, build
date, dirty flag. All derived strings (the one-line summary and the short
header) are computed once at init; accessors expose the raw values. There
is deliberately no user-agent helper — bandage makes no outbound HTTP
requests. The identity surfaces in exactly four places: `-v` output, the
startup log record's fields, the `/stats` build block, and the `--test`
plan header. No HTTP `Server` header.

**Makefile (mirrors bandaid's).** Injects the four values via `-ldflags
-X`, with `-s -w` and `-trimpath`; version comes from a version file
(`v0.1` initially) with a `dev` fallback, commit and dirty flag from git,
build date honoring `SOURCE_DATE_EPOCH`. Targets: default build, test
(`go test -race -count=1 ./...`), clean. Build output goes to a git-ignored
bin directory.

**CLI (pflag).** Flag table with shorthands: `--config/-c` (default
`bandage.yml`), `--rules/-r` (default `rules.yml`), `--test/-t`,
`--log-level/-l` (empty default), `--workers/-w` (zero default),
`--version/-v`, `--help/-h`. `-v` prints the identity summary and exits 0;
`-h` prints usage (headed by the short identity header) and exits 0;
unknown flags exit 2 with usage. Precedence for `log-level` and `workers`
is explicit flag > config > default, decided by whether the flag was set.
The former "check" surface is renamed to "test" everywhere — Go names,
plan output, and documentation — except archived issue-tracker history,
which stays as written. Flag parsing sits behind a `run(args)` seam in the
command entry point.

**Logging (per ADR 0005).** zerolog replaces slog everywhere. Config
gains `log.level` only (four-word vocabulary, default `info`); the
rendering is fixed console-style text on stderr. The app wiring builds the
single program-wide logger from config and passes it to the command, the
daemon and the adapters; the domain logger adapter lives there too (no
dedicated logging package "for now"). The domain keeps its dependency
rule: its own level enum replaces the stdlib level type on the `log`
action, and a tiny logger interface is declared beside its one consumer
(the evaluation module's `log` action). The DSL's four level words map to
zerolog levels; zerolog's `fatal`/`panic` are unreachable from rules — a
rule must never be able to exit the process.

**Worker pool (per ADR 0007).** The pipeline body runs on N goroutines
reading the ingest line channel; the sweeper is one more goroutine.
Default N is the CPU count; `pipeline.workers` configures it, `-w`
overrides, the resolved value must be ≥ 1 (validated at load). Event
ordering is relaxed: per-key tracker updates remain atomic (the cache's
no-I/O update callback), accumulation never decays backwards, and a
duplicate concurrent trigger merely re-upserts the same (rule, target)
report. The sqlite store opens a single connection for all paths, making
writes deterministic under concurrency. `workers: 1` restores strict
arrival order; documentation states that replaying a log in order
reproduces results.

**Daemon context.** The command builds a lifetime context from
SIGINT/SIGTERM and passes it into daemon start; the pipeline and sweeper
use it in place of ad-hoc background contexts. Shutdown keeps drain-first
order (stop ingest, close the line channel, wait for workers) so in-flight
report upserts complete; only when the caller's shutdown context expires
does the daemon cancel the lifetime context to abort stragglers. Port
signatures (enrichment, tracker cache, report sink/repository) are
unchanged — their context parameters simply become live, which also
prepares the future tracker-cache persistence seam (ADR 0002).

**Stats endpoint (per ADR 0006).** `GET /stats` returns indented JSON
with: a generation timestamp, uptime, a build block (name, version,
commit, build date, dirty, Go version, platform), a pipeline block
(worker count, received, parsed, dropped), and a tracker cache block
(gets, sets, misses, evictions, size, entry cap). Counters are cumulative
since start. The document carries no format version — it is
human-facing and explicitly not a stable machine contract; metric
gathering would arrive later as a separate Prometheus-format endpoint.
A narrow stats-source interface is declared beside the HTTP API's
consumer and satisfied structurally by the daemon, which assembles the
snapshot from its counters, the cache statistics, and the identity
module. The periodic statistics log line stays. This deliberately amends
the v0 "nothing else exposed" story.

**Vocabulary alignment.** Log messages, comments, test names and design
docs say *eviction* (the glossary term, matching the stats counter),
never "capped drop". Deletion semantics in docs are explained plainly —
deleting reports does not touch tracker state, so a Target that still
overflows is reported again on the next trigger — without leaning on
"dismiss"/"silence" as terms.

**Config surface.** Strict decoding covers the new keys: `log.level`
(one of the four level words) and `pipeline.workers` (positive integer or
absent). Unknown keys and invalid values still abort startup before any
socket opens. No hot reload; changes take effect on restart.

## Testing Decisions

- **What makes a good test:** assert only external behavior — feed log
  messages in, read the report list and stats out, observe the captured
  log records where logging is the contract. Never assert internal bucket
  values except as surfaced in report evidence. Time-dependent behavior is
  driven through the injected clock and event timestamps, never `sleep`;
  concurrency is proven by the race detector and exact accounting, not by
  timing.
- **Primary seam (existing, one):** the assembled daemon — real rule
  loader, parser, enrichment, evaluation, report service and sqlite
  in-memory repository behind the HTTP API — driven by raw nginx-JSON
  messages at a real ingest listener and asserted through the API. It
  carries the worker pool (several workers under `-race` with every line
  accounted for, plus a `workers: 1` determinism case), context threading
  and bounded shutdown (in-flight reports survive, shutdown completes),
  `/stats` contents (build block, counter flow including evictions),
  eviction wording in captured logs, and the startup identity fields.
- **Log capture (existing seam, adapted):** the daemon's unexported
  logger option and the test log-capture helper — the same injection
  point, reworked from a stdlib slog handler to a zerolog writer/hook
  capturing level, message and fields.
- **One new seam:** `run(args)` plus a fresh flag set in the command
  entry point — flag shorthands, `-v`/`-h` exit behavior, and
  flag-over-config precedence, all unreachable from the daemon seam. No
  other behavior may be tested through it.
- **Existing unit seams only, unchanged:** strict config parsing (the new
  `log.level`/`pipeline.workers` keys get passing and failing cases),
  rule parsing and the `--test` plan text, domain level parsing (including
  rejected words), tracker math and enrichment. Each filter/parser/tracker
  suite keeps its current shape.
- **Not tested as contract:** the exact `/stats` JSON shape (ADR 0006:
  human-facing, unversioned — tests assert 200 and the counter values that
  must be reflected, not field-for-field equality); the identity module's
  linker-injected strings (verified by `make build` and `bin/bandage -v`).
- **Prior art:** the existing end-to-end suite in the app package
  (injected clock, raw-line sender, captured logs, report-derived
  assertions), the strict-config table tests, and the webjail-style
  table-driven domain tests.

## Out of Scope

- A Prometheus-format or any machine-readable metrics endpoint (future
  work per ADR 0006; `/stats` is not its placeholder contract).
- Configurable log format or output (JSON encoding, file output,
  rotation); `log.level` is the only logging knob for now.
- Build identity in HTTP headers or any outbound-request metadata.
- Per-Target ordered event routing (the `workers: 1` setting is the
  reproducibility hatch; hash-routed queues are not built).
- Persistent tracker state (ADR 0002 stands; the live context parameters
  merely prepare its persistence seam).
- Hot reload of config or rules.
- TLS/authentication on the syslog ingest and HTTP API; binding guidance
  for a public `/stats` stays an operator concern.
- Release automation beyond build/test/clean: cross-compilation,
  container images, package publishing, version bumping.
- Rewriting archived issue-tracker history (`-check` mentions stay).
- Any change to the report document, the rules DSL, tracker semantics, or
  the ban-rule contract.

## Further Notes

- Design-time decisions are recorded in ADR 0005 (zerolog behind a domain
  logger port), ADR 0006 (human-facing `/stats`, Prometheus for metrics),
  and ADR 0007 (relaxed event ordering under the worker pool); the
  glossary gained the term **Eviction**.
- This spec amends four v0 user stories: the validation command is
  `--test` (was `-check`); replaying a log *in order* reproduces results
  (was unconditional); the API exposes `/stats` in addition to ping and
  reports (was "nothing else exposed"); and deletion semantics are stated
  plainly rather than through "dismiss"/"silence" language.
- The root plan document is updated alongside implementation: layout and
  config sketches, statistics and API sections, and the CLI/validation
  section. Its house rules are unchanged (ADR 0005 keeps the domain
  dependency rule intact).
- Natural ticket boundaries: adapter-tree rename; build identity module
  and Makefile; pflag CLI with the test rename; zerolog migration; worker
  pool with daemon context; `/stats` endpoint.
