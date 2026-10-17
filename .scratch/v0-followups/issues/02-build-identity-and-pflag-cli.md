# 02: Build identity and the pflag command line

**What to build:** An operator can tell exactly which build of bandage is running and drive it with a modern command line. `make build` produces the binary with version, commit, build date and dirty state injected; `bandage -v` prints the identity summary; `bandage -h` prints usage headed by the short identity; `bandage -t` validates config and rules and prints the validated plan with an identity header (replacing `-check`); `-c` and `-r` shorthands work; a bad flag fails loudly. The startup log record names the running build.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] `make build` produces the binary carrying version (seeded from the version file, `dev` fallback), commit and dirty flag from git, and a build date that honors `SOURCE_DATE_EPOCH`; an uncommitted tree builds a binary marked dirty
- [ ] `bin/bandage -v` prints name, version, commit, build date, Go version and platform, and exits 0
- [ ] `bin/bandage -h` prints usage headed by the short identity (name, version, commit) and exits 0
- [ ] `bin/bandage -t` validates config and rules and prints the plan with the identity header; invalid config or rules fail non-zero with the load error; the former `-check` name appears nowhere in the operator-facing surface
- [ ] `-c`, `-r` (and `-t`, `-v`, `-h`) behave exactly as their long forms; an unknown flag prints the error plus usage and exits 2
- [ ] The startup log record carries name, version, commit and build date
- [ ] Flag parsing, shorthands and exit behavior are covered at the command's `run(args)` seam; `make test` is race-enabled and green
