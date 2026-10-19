# 01: Walking skeleton: pull → compile → install → loop

**What to build:** `splint-nft` runs end to end, unprivileged: on a timer it
fetches the report document from a bandage API over plain HTTP, parses it as
the published version-0 contract, compiles the live reports into ban rules,
and installs them through a firewall-driver port, with `--dry-run` printing
what would be installed without touching netlink. The lifecycle is fluxc's:
a startup test install before the loop, the last rules kept on a failed
fetch, and a reset on clean exit. The ban rules here are the skeleton's
placeholder mapping — one drop ban rule per report's Target — which later
tickets replace with the real penalty mapping and merge policy.

**Blocked by:** None (can start immediately)

**Status:** resolved

- [x] The binary fetches the report document on an update interval defaulting to 5m with a 1m floor (a shorter value is clamped with a warning)
- [x] The document is consumed strictly as the published contract, in the consumer's own wire types: unknown fields are ignored; an unknown document version refuses the cycle — fatal at the startup test install, keep-last-rules with a loud log on later cycles
- [x] Records with a missing or unknown penalty or an unparseable Target are skipped, logged, and counted; the remaining records still compile
- [x] The compiler produces one drop ban rule per live report's Target (placeholder mapping, explicitly superseded by tickets 04 and 05)
- [x] Install goes through a tiny firewall-driver port (install/reset) with a stub implementation; `--dry-run` prints the compiled ban rules and requires neither netlink nor privileges
- [x] Startup performs one fetch-compile-install and exits non-zero on failure; a failed fetch mid-loop keeps the last installed rules with a loud log; SIGINT/SIGTERM reset before exit
- [x] Behavior is tested at the update-cycle seam (fake report endpoint + stub driver): a failing and a passing case per validation, and the report document's canonical example reused as the base fixture
- [x] The second command builds with the shared build identity alongside the daemon; the repo's build and test targets cover both

Implemented on integration branch `feat/splint-nft` (merge commit `3893d16`; cross-ticket code-review fixes through `1879da4`). The placeholder one-drop-per-Target mapping was superseded by `04-penalty-mapping.md` and `05-merge-policy.md` as the ticket planned.

Context: spec `../spec.md`; ADR 0011 (consumer-binary split).
