# 01: Build identity as equals

**What to build:** bandage and splint draw their build identity from the
same source as equals: one per-name build value constructed from the
four linker-injected stamps, used identically by both commands for their
summary and header output. The daemon's rendered identity does not
change; the bolted-on "named summary for the second command" path is
gone, so neither binary looks like an afterthought.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] The identity module exposes one per-name build value; both commands construct it with their own name and use the same accessors
- [ ] The program name is passed at compile time, never linker-stamped
- [ ] bandage's rendered identity output (summary and header) stays byte-identical, pinned at the identity module's own tests
- [ ] The package-level name constant and the bolted-on named-summary helper are deleted
- [ ] The repo's build and test targets cover both binaries

Context: spec `../spec.md` (Build identity decision); both commands share
the build-identity stamping of the daemon.

