# 03: zerolog logging with log.level configuration

**What to build:** Logging becomes structured zerolog output configured by deployment, not by flags an operator must remember. A `log.level` config key (`debug`, `info`, `warn`, `error`; default `info`) sets the daemon's level, overridable by `-l` with flag > config > default precedence. Every log record — startup identity fields, `log`-action records (rule, Target, tracker reading), tracker cache eviction warnings — flows through one program-wide logger as console-style text on stderr. The rules DSL keeps its four level words and can never force a process exit.

**Blocked by:** 02 — Build identity and the pflag command line

**Status:** resolved

- [x] `log.level` accepts exactly `debug`, `info`, `warn`, `error` (default `info`); any other value is rejected by strict config load before any socket opens
- [x] `-l` overrides the config value when passed explicitly; the config value overrides the default
- [x] All log records are emitted through the one program-wide zerolog logger as console-style text on stderr; startup identity fields and `log`-action fields survive the migration
- [x] Level filtering is observable: records below the configured level are absent
- [x] The `log` action's level vocabulary stays the four words, shared with the one level parser; no rule can produce zerolog's `fatal`/`panic` or exit the process
- [x] The domain keeps its dependency rule — its own level enum and a logger port declared beside its one consumer, no third-party imports in the domain
- [x] Tests observe logs through the migrated capture seam (same injection point, zerolog writer/hook); suite green under `-race`

## Answer

Implemented on integration branch `feat/v0-followups` (merge commit
`d4f38d5`; cross-ticket code-review fixes through `a69fb58`). zerolog
console text on stderr from one program-wide logger
(`bandage/internal/app/logging.go`), `log.level` config key with `-l` precedence,
domain `Level` enum + `Logger` port beside its one consumer (ADR 0005),
the log-capture seam reworked at the same injection point, and the
"capped drop" → *eviction* sweep.

Context: spec `../spec.md`, `../../docs/adr/0005-logging-zerolog-behind-domain-port.md`.

Notes:
- The logger option is exported `WithLogger`: the spec's Testing Decisions
  say "unexported", but the Implementation Decisions require the wiring
  to pass the logger in — adjudicated for the export.
- `log` action records keep `rule`, `event`, `tracker` and gained
  `target` (both readings of the field requirement satisfied).
