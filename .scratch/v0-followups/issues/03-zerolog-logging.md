# 03: zerolog logging with log.level configuration

**What to build:** Logging becomes structured zerolog output configured by deployment, not by flags an operator must remember. A `log.level` config key (`debug`, `info`, `warn`, `error`; default `info`) sets the daemon's level, overridable by `-l` with flag > config > default precedence. Every log record — startup identity fields, `log`-action records (rule, Target, tracker reading), tracker cache eviction warnings — flows through one program-wide logger as console-style text on stderr. The rules DSL keeps its four level words and can never force a process exit.

**Blocked by:** 02 — Build identity and the pflag command line

**Status:** ready-for-agent

- [ ] `log.level` accepts exactly `debug`, `info`, `warn`, `error` (default `info`); any other value is rejected by strict config load before any socket opens
- [ ] `-l` overrides the config value when passed explicitly; the config value overrides the default
- [ ] All log records are emitted through the one program-wide zerolog logger as console-style text on stderr; startup identity fields and `log`-action fields survive the migration
- [ ] Level filtering is observable: records below the configured level are absent
- [ ] The `log` action's level vocabulary stays the four words, shared with the one level parser; no rule can produce zerolog's `fatal`/`panic` or exit the process
- [ ] The domain keeps its dependency rule — its own level enum and a logger port declared beside its one consumer, no third-party imports in the domain
- [ ] Tests observe logs through the migrated capture seam (same injection point, zerolog writer/hook); suite green under `-race`
