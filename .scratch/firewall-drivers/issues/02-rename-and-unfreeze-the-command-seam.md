# 02: Rename the tool to `splint`; unfreeze the command seam

**What to build:** the tool is named `splint` everywhere operator-facing
— binary, command, sample systemd unit, consumer doc — with no
compatibility shims. The rebuilt command carries **no run-seam tests**:
command behaviour is not frozen by tests. Every validation worth keeping
is verified at the seam of the module that owns it, so the command
surface stays free to evolve.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] Binary, command, sample systemd unit and consumer doc naming all say `splint`; the old name survives only as history in ADRs
- [ ] Command-run tests are removed, not migrated
- [ ] Validations whose owner sits below the command keep a failing-and-passing pair at that owner's seam — fetcher options (certificate pair, timeout floor), policy parsing (prefixes), hook parsing, update-interval clamping — filling any pair that only ever existed at the run seam
- [ ] Validations whose owner is still moving (namespace paths, service ports and addresses) are re-homed at their new owner's seam by the tickets that move them (05/06) — noted in those tickets
- [ ] No test drives the command's run seam; `make test` and `make build` pass

Context: spec `../spec.md` (Rename decision; Testing Decisions: the
command run seam is deliberately untested); ADR 0012 records the rename.

