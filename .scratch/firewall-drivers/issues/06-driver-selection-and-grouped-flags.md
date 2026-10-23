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

**Status:** ready-for-agent

- [ ] `--firewall` selects a driver from the registry; the default is nftables; an unknown value fails with the known drivers listed
- [ ] The nftables flag group is complete: enforcement hook, namespace paths (repeatable), service prefilter ports and addresses; the hook flag leaves the engine flags
- [ ] A flag belonging to an unselected driver, explicitly set, is a startup usage error
- [ ] The usage output groups flags by owner (engine vs each driver)
- [ ] One driver serves the whole run; no per-point driver mixing exists
- [ ] Registry and factory validation carry a failing and a passing case at their own seams — no run-seam tests; command behaviour remains unfrozen and is verified by operating the built binary, not pinned by tests

Context: spec `../spec.md` (Command surface); ADR 0012 records the
driver flag superseding the sibling-binary idea.

