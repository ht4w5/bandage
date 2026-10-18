# 02: Build identity and the pflag command line

**What to build:** An operator can tell exactly which build of bandage is running and drive it with a modern command line. `make build` produces the binary with version, commit, build date and dirty state injected; `bandage -v` prints the identity summary; `bandage -h` prints usage headed by the short identity; `bandage -t` validates config and rules and prints the validated plan with an identity header (replacing `-check`); `-c` and `-r` shorthands work; a bad flag fails loudly. The startup log record names the running build.

**Blocked by:** None (can start immediately)

**Status:** resolved

- [x] `make build` produces the binary carrying version (seeded from the version file, `dev` fallback), commit and dirty flag from git, and a build date that honors `SOURCE_DATE_EPOCH`; an uncommitted tree builds a binary marked dirty
- [x] `bin/bandage -v` prints name, version, commit, build date, Go version and platform, and exits 0
- [x] `bin/bandage -h` prints usage headed by the short identity (name, version, commit) and exits 0
- [x] `bin/bandage -t` validates config and rules and prints the plan with the identity header; invalid config or rules fail non-zero with the load error; the former `-check` name appears nowhere in the operator-facing surface
- [x] `-c`, `-r` (and `-t`, `-v`, `-h`) behave exactly as their long forms; an unknown flag prints the error plus usage and exits 2
- [x] The startup log record carries name, version, commit and build date
- [x] Flag parsing, shorthands and exit behavior are covered at the command's `run(args)` seam; `make test` is race-enabled and green

## Answer

Implemented on integration branch `feat/v0-followups` (merge commit
`4c11746`; cross-ticket code-review fixes through `a69fb58`).
`internal/identity` mirrors bandaid's identity module; Makefile
build/test/clean with `SOURCE_DATE_EPOCH` and a git-ignored `bin/`; pflag
CLI behind `run(args)` with shorthands, `-v`/`-h` exit 0, unknown flags
exit 2 and flag > config > default precedence; `-check` is gone from the
operator-facing surface (`--test` everywhere, archived history excepted).

Context: spec `../spec.md`, prior-art notes
`/home/user2/Devel/bandage-wt/research-notes/ticket-02-identity-pflag-cli.md`.

Notes:
- `-l`/`-w` are parsed and resolved here; their behavior lands in
  tickets 03/04.
- Legacy `bandage -check` parses under pflag as `-c heck` (an opaque
  config error) — accepted: `-c`'s shorthand semantics are spec'd and the
  word is retired from the surface.
