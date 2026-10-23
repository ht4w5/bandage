# 06: Firewall driver selection and grouped flags

**What to build:** the operator chooses the firewall driver. `--firewall`
selects from the registry, defaulting to nftables, and an unknown value
lists the known drivers. Driver-specific arguments are grouped under
their driver and validated at startup: the nftables group carries the
enforcement hook, the namespace paths and the service prefilter; setting
a flag that belongs to an unselected driver is a usage error, so a
mistyped combination fails loudly instead of silently not applying. The
usage output shows which flags belong to whom.

**Blocked by:** 05

**Status:** resolved

- [x] `--firewall` selects a driver from the registry; the default is nftables; an unknown value fails with the known drivers listed
- [x] The nftables flag group is complete: enforcement hook, namespace paths (repeatable), service prefilter ports and addresses; the hook flag leaves the engine flags
- [x] A flag belonging to an unselected driver, explicitly set, is a startup usage error
- [x] The usage output groups flags by owner (engine vs each driver)
- [x] One driver serves the whole run; no per-point driver mixing exists
- [x] Registry and factory validation carry a failing and a passing case at their own seams — no run-seam tests; command behaviour remains unfrozen and is verified by operating the built binary, not pinned by tests

Implemented on integration branch `feat/firewall-drivers` (commits `8006afc`, `ea30f2e`, `88140bf`). The registry key and `--firewall` value is `nftables` (spec user story 1). Registry and factory validation carry failing-and-passing pairs at their own seams; `cmd/splint` keeps zero test files and its behaviour was verified by operating the built binary. With only one driver registered, the unselected-driver refusal is seam-verified against stub factories and becomes operator-reachable when a second driver registers.

Context: spec `../spec.md` (Command surface); ADR 0012 records the
driver flag superseding the sibling-binary idea.

