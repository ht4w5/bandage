# Logging: zerolog behind a domain Logger port

The logging implementation is zerolog, but `bandage/internal/domain*` keeps its
dependency rule (stdlib + `bandage/internal/domain` only): the domain defines its
own `Level` enum (the `log` action's vocabulary stays `debug` | `info` |
`warn` | `error`) and a tiny `Logger` port declared beside its one
consumer (`bandage/internal/domain/evaluation`'s `log` action). zerolog is the
sole implementation of that port, built from the `log.level` config key
and adapted outside the domain. zerolog's `fatal`/`panic` levels are
deliberately unreachable from the rules DSL — `Logger.Fatal` calls
`os.Exit`, which a rule must never be able to do.

Considered: using `zerolog.Logger` inside the domain as the literal slog
replacement; rejected because it would make a third-party import part of
the domain's dependency rule and force that rule to be amended.
