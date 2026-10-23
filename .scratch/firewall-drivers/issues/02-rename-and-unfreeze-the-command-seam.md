# 02: Rename the tool to `splint`; unfreeze the command seam

**What to build:** the tool is named `splint` everywhere operator-facing
— binary, command, sample systemd unit, consumer doc — with no
compatibility shims. The rebuilt command carries **no run-seam tests**:
command behaviour is not frozen by tests. Every validation worth keeping
is verified at the seam of the module that owns it, so the command
surface stays free to evolve.

**Blocked by:** None (can start immediately)

**Status:** resolved

- [x] Binary, command, sample systemd unit and consumer doc naming all say `splint`; the old name survives only as history in ADRs
- [x] Command-run tests are removed, not migrated
- [x] Validations whose owner sits below the command keep a failing-and-passing pair at that owner's seam — fetcher options (certificate pair, timeout floor), policy parsing (prefixes), hook parsing, update-interval clamping — filling any pair that only ever existed at the run seam
- [x] Validations whose owner is still moving (namespace paths, service ports and addresses) are re-homed at their new owner's seam by the tickets that move them (05/06) — noted in those tickets
- [x] No test drives the command's run seam; `make test` and `make build` pass

Implemented on integration branch `feat/firewall-drivers` (commits `8311760`, `3b53971`; merge `d8d19d8`). The run-seam suite was deleted, not migrated; the fetcher, policy, hook and interval pairs live at their owners' seams. As planned, namespace-path and service port/address validations died with the run seam and were re-homed at the factory seam by 05; hook parsing lives at `splint/internal/firewall/nft` and moved with the flag into the driver group in 06. The old name survives only as history in ADRs (identity fixtures renamed in the code-review fix pass).

Context: spec `../spec.md` (Rename decision; Testing Decisions: the
command run seam is deliberately untested); ADR 0012 records the rename.

