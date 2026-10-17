# Spec: bandage v0 — realtime web log analyzer with published report list

Status: ready-for-agent

## Problem Statement

Operators of high-traffic web servers need to know which clients are abusing
their service (bandwidth draining, replay scraping, sustained large-object
egress) while it is happening, not hours later in a batch job. Today the
signals exist in access logs but turning them into answers requires either
batch analytics over a log warehouse or hand-rolled scripts; neither gives a
continuously current list of abusive targets with the evidence to justify
action. Operators also want the eventual enforcement output (ban rules) to be
derivable mechanically from what the analyzer reports.

## Solution

bandage is a long-running daemon that consumes access logs over syslog in
realtime, evaluates operator-written rule chains against every event, and
maintains a live **report list** served as JSON over HTTP. Rules pair a
webjail-style filter with a leaky-bucket **tracker** (rate, bandwidth, or
replay) that decays over time and **overflows** when abuse is sustained; on a
**match**, the rule's actions run, and a `report` action writes a **report**
about the offending **target** with its tracker reading and a **sample**
event. Reports persist in sqlite across restarts, expire on their own, and
can be dismissed over the API. Each report carries a machine-readable
**reason** slug destined for downstream **ban rules**.

## User Stories

1. As an operator, I want a daemon that consumes my access logs over syslog continuously, so that abuse is detected while it happens rather than in a later batch run.
2. As a rule author, I want to define rules as named YAML chains with filter expressions and actions, so that detection logic is compact, reviewable, and composable.
3. As a rule author, I want filters in the webjail expression language (`src`, `method`, `path`, `agent`, `status`, `sent` combined with `and`/`or`/`not`), so that I select events without writing SQL.
4. As a rule author, I want each rule to declare at most one leaky-bucket tracker with explicit `leak` and `volume`, so that thresholds are visible configuration rather than derived magic.
5. As a rule author, I want to choose the tracker kind — `rate` (requests), `bandwidth` (bytes), or `replay` (transferred fraction of file size) — so that I can detect different abuse shapes.
6. As a rule author, I want the `replay` tracker's volume to be configurable as `constant`, `clamped-linear`, `inverse-square`, or `step` in file size, so that tolerance can scale with object size.
7. As a rule author, I want to set the tracker's target aggregation (`target_prefix` with separate IPv4 and IPv6 prefix lengths, e.g. /32 and /64), so that related clients can be grouped and individual IPv6 addresses are never reported finer than /64.
8. As a rule author, I want tracker state keyed per target (and per target+path for `replay`), so that abuse by one client network does not smear onto others.
9. As a rule author, I want actions in lowercase (`report`, `log`, `goto`, `jump`, `stop`) run in order when a rule matches, so that control flow reads predictably.
10. As a rule author, I want `goto` to run the target chain and end mine, and `jump` to run the target chain and resume mine, so that I can build classification front-chains that dispatch to topic chains.
11. As a rule author, I want the chain graph validated to be acyclic at build time, so that traversal can never loop at runtime.
12. As a rule author, I want several chains to be able to dispatch to the same target chain, so that shared sub-logic is not copy-pasted.
13. As a rule author, I want terminality to be per-rule: all actions of a matching rule always run, and a rule containing `report`, `goto`, or `stop` ends traversal of its chain, so that combined actions behave predictably while later rules in the chain are skipped.
14. As a rule author, I want rules without a tracker to match on filter alone for routing (`stop`, `goto`, `jump`, `log`), so that simple inclusion/exclusion logic needs no buckets.
15. As a rule author, I want `report` to require a tracker on the rule, so that every report is evidence-backed and report volume stays bounded to targets that actually overflowed.
16. As a rule author, I want `report` to require a `reason` slug and a `ttl`, so that provenance and retention are explicit at authoring time.
17. As a rule author, I want multiple rules to be able to share one `reason`, so that several signals can feed a single ban reason downstream.
18. As a rule author, I want a `log` action in flux's `"level,message"` shape that logs the event and the tracker reading, so that I can debug rule behavior on live traffic.
19. As a rule author, I want `bandage -check` to validate config and rules and print the plan without ingesting anything, so that I can review rules safely before deployment.
20. As a rule author, I want filter syntax errors reported with line and column, so that I can fix expressions quickly.
21. As a rule author, I want load-time validation of duplicate rule IDs, unknown tracker kinds and volume methods, volume methods on non-replay trackers, dangling `goto`/`jump` targets, cyclic chain graphs, malformed reason slugs, non-positive TTLs, out-of-range target prefixes, and `report` without a tracker, so that a broken rules file never reaches the running daemon.
22. As an operator, I want config and rules loaded strictly, rejecting unknown keys and invalid values before any socket opens, so that typos fail loudly at startup.
23. As an operator, I want config and rules changes to take effect on restart only, so that behavior is reproducible and tracker state is never silently orphaned by renames.
24. As an operator, I want syslog ingestion over tcp, udp, or unixgram with the nginx JSON log format, so that bandage drops into my existing logging pipeline.
25. As an operator, I want malformed log lines and invalid required fields dropped and counted, so that one bad line never stalls the stream but is still visible.
26. As an operator, I want log fields I do not use yet (`host`, `server`, `duration`) accepted and ignored, and unknown fields tolerated, so that log format changes upstream do not break bandage.
27. As an operator, I want tracker decay computed from event time (log timestamps), so that behavior is faithful to the traffic timeline and replaying logs reproduces results.
28. As an operator, I want report timestamps (`created_at`, `updated_at`, `expires_at`) computed from wall clock, so that expiry works even when logs are delayed or stop.
29. As an operator, I want `created_at` fixed at the trigger that created a report and `updated_at`/`expires_at` recomputed on every trigger, so that I can see when a target first appeared and whether it is still active.
30. As a report consumer, I want `GET /reports` to return the report list as JSON without any URL version prefix, so that consumption is trivial.
31. As a report consumer, I want each report to carry its rule, chain, reason, target, timestamps, tracker reading, and sample event, so that I can judge each report without querying anything else.
32. As a report consumer, I want reports sorted by `created_at` descending and filterable by `?rule=` and `?target=`, so that new reports surface first and I can drill into specifics.
33. As a report consumer, I want expired reports never returned and swept from storage, so that the list reflects live conditions.
34. As a report consumer, I want the tracker reading in each report to show value, leak, and volume at trigger time, so that I can see how far past the threshold the target is.
35. As a report consumer, I want `GET /ping` for liveness checks and nothing else exposed, so that the API surface stays minimal.
36. As an operator, I want `DELETE /reports` with required `?rule=`/`?target=` filters that reports a deleted-row count, so that I can dismiss false positives without risk of wiping the list.
37. As an operator, I understand that deletion is dismiss and not silence — a report whose condition persists returns on the next trigger — so that I am not surprised when dismissed abuse reappears.
38. As an operator, I want reports to survive daemon restarts (sqlite persistence), so that review history is never lost.
39. As an operator, I accept that tracker state and file-size estimates are memory-only and cold after restart, so that v0 stays simple; I want that trade-off documented.
40. As an operator, I want tracker state bounded by a configurable entry cap with a sane default, so that memory use is predictable.
41. As an operator, I want every capped-drop eviction logged, so that an emptied bucket never resets silently.
42. As an operator, I want file-size estimates learned from observed transfers with a warm-up sample threshold, so that replay tracking needs no external size index.
43. As an operator, I want ingest and database configuration keyed by driver name, so that other sources and stores can be added later without config format churn.
44. As a downstream tool maintainer, I want every report to carry a reason slug matching a strict lowercase pattern that is stable and shareable across rules, so that I can materialize ban rules from reports mechanically.
45. As a downstream tool maintainer, I want rule IDs and chain names present as internal provenance but the reason as the consumption contract, so that operators can reorganize rules without breaking my ban-rule generation.
46. As an operator, I want the report document to declare format version 0, so that consumers can evolve with us while the format settles.

## Implementation Decisions

**Architecture.** Go, following the webjail domain-driven layout: a domain core holding the `Event` value type (ingress fields plus derived file size), with one domain module per concern — filter, enrichment, track, evaluation, report — plus adapters for ingest, parsing, storage, and HTTP. Domain modules depend only on the domain core and the standard library. Ports are tiny interfaces declared beside their consumer, with atomic per-key update callbacks that must never perform I/O.

**DSL (per ADR 0001).** Flux-shaped YAML chains of rules; filters in webjail's expression language with its v0 primitive set unchanged (no regex, host, or duration filters); lowercase action names. The rules document declares format version 0. No SQL anywhere.

**Rule model (per ADR 0003).** A rule has an ID (namespaces tracker state), a filter defaulting to `any`, at most one tracker, and an ordered action list. A rule matches when its filter accepts the event and its tracker overflows; tracker-less rules match on filter alone and may carry only routing/logging actions — `report` requires a tracker.

**Tracker semantics.** Ported leaky-bucket math from flux: value accumulates an increment, decays by `leak × Δt` between events (floor zero), and overflows above `volume`. `rate` increments by one, `bandwidth` by sent bytes, `replay` by the transferred fraction of the estimated file size (skipped while the estimate is unknown). Volume methods apply to `replay` only. TTL of cache entries is `volume/leak` (default one hour when leak is zero). Decay uses event time.

**Actions and control flow.** `report` upserts a report; `log` emits debug output; `goto` runs the target chain then ends the current chain; `jump` runs the target chain then resumes the current chain; `stop` ends chain traversal. Terminality is per-rule: a rule containing `report`, `goto`, or `stop` ends traversal of its chain after all its actions have run; other chains are still evaluated. The `goto`/`jump` graph must be acyclic, enforced at build time; shared target chains are permitted.

**Ingress contract.** Required fields: time (Unix seconds with fraction, UTC), client address, method, path (the URL field), status (100–599), sent bytes (non-negative); agent optional. Host, server, and duration are reserved (accepted, ignored); unknown fields ignored. Invalid lines are dropped and counted. Derived: estimated file size, set by enrichment after a warm-up number of observations per path (EWMA), otherwise "unknown".

**Reports (per ADR 0004).** Identity is (rule, target). The record holds: rule, chain, reason (slug `^[a-z0-9][a-z0-9_-]*$`, shared reasons allowed), target (the aggregated source prefix), `created_at` (fixed at insert), `updated_at`, `expires_at` (recomputed as trigger wall-clock time plus the action's TTL, unconditionally overwriting any previous value), tracker reading at trigger (kind, value, leak, volume), and the sample (the triggering event's time, path, agent, status, sent, size). Every `report` action's write is the only write path to the table.

**Repository.** Port with upsert, list (filter by rule and target), delete by query returning a count, and delete-expired by timestamp. sqlite adapter; one row per (rule, target) with indexed rule, target, and expiry columns plus a record body. A periodic sweeper deletes expired rows; queries exclude expired rows as a safety net.

**HTTP API.** `GET /reports` (read-only; query params `?rule=`, `?target=`; never returns expired rows; sorted by `created_at` descending), `DELETE /reports` (requires `?rule=` and/or `?target=`; returns deleted count; dismiss semantics — tracker state untouched, so reports can return on the next trigger), `GET /ping`. No URL version prefix, no debug endpoints. The API never writes reports.

**Report document.** Format version 0: a top-level document with generation timestamp and a reports array whose entries are the report records above; RFC 3339 UTC timestamps.

**Tracker cache (per ADR 0002).** In-memory sharded store behind the tracker-cache port: per-shard locking with atomic no-I/O update callbacks, TTL expiry (lazy plus periodic sweep), and a global configurable entry cap (default 65536) enforced by per-shard LRU; capped drops are logged and counted. The same store serves file-size enrichment state (no TTL). Tracker and file-size state are deliberately volatile; reports are durable.

**Clocks.** Tracker decay uses event time; report timestamps use wall clock. The wall clock is injectable in app wiring so expiry behavior is testable.

**Configuration.** Strictly decoded: syslog ingest block keyed by driver (network tcp/udp/unixgram, listen address) with a parser selection; database block keyed by driver (sqlite with a file path); api listen address; cache entry cap. Unknown keys and invalid values are rejected before any socket opens. No hot reload. Sweep cadences are internal constants.

## Testing Decisions

- **What makes a good test:** assert only external behavior — feed log messages in, read the report list out. Never assert internal bucket values except as surfaced in report evidence; never assert log text except where logging is the contract (capped drops). Time-dependent behavior (decay, expiry, timestamps) is driven through the injected clock and event timestamps, never `sleep`.
- **Primary seam (one):** the assembled daemon — real rule loader, parser, enrichment, evaluation, report service, and sqlite in-memory repository behind the HTTP API — driven by raw nginx-JSON syslog messages at the ingest port and asserted through `GET /reports` JSON. Everything in the user stories is observable here: filters, overflow and decay, chain traversal and terminality, target aggregation, report timestamps and evidence, sort order, expiry exclusion, and delete-dismiss behavior.
- **CLI validation surface:** the `-check` command tested directly against a matrix of malformed configs and rules (each load-time validation rule gets at least one failing and one passing case).
- **Unit tests at existing ports only (no new seams):** filter parser (table-driven parse and error-position tests), nginx JSON parser (field mapping and drop cases), tracker math (accumulation, decay, overflow, volume methods, TTL derivation), file-size enrichment (EWMA warm-up gating). Each of these ports already exists in the reference projects.
- **Prior art:** webjail's table-driven domain tests (filter parsing with positioned errors, tracker and enrichment semantics) and flux's engine tests, including its bucket-semantics scenario fixtures; those suites are ported alongside the code they cover rather than rewritten from scratch.

## Out of Scope

- Ban-rule generation and enforcement (per ADR 0004): bandage produces reports; downstream tooling derives ban rules.
- Compound multi-tracker matching within one rule (per ADR 0003).
- The batch analyzer's YAML/SQL rule dialect and output formats (tables, MMDB, reason prefixes) (per ADR 0001).
- Persistent tracker state / hybrid memory-disk cache (per ADR 0002; the port is the future seam).
- Hot reload of config or rules.
- Filter primitives beyond webjail's v0 set: no regex, host, or duration filters.
- Target kinds beyond aggregated source address (user agent grouping, arbitrary keys); IPv6 aggregation finer than /64.
- URL versioning, debug/introspection endpoints, non-JSON outputs.
- TLS/authentication on the syslog ingest and HTTP API.
- Multiple simultaneous database or ingest drivers in one deployment.

## Further Notes

- The design is fully recorded in the plan document at the repository root, with terminology in the root glossary and the load-bearing decisions in the ADR directory (four ADRs: DSL lineage, durable reports with volatile trackers, one tracker per rule, reports feed ban rules).
- Milestone hardening work — worker pool tuning, backpressure policy, eviction statistics surfacing — is part of implementation but has no distinct behavioral contract beyond what this spec already states (bounded memory, counted drops).
- The deliberate asymmetry worth re-reading before changing anything: reports are the product and durable; everything upstream of them (trackers, file-size estimates) is disposable warm state.
