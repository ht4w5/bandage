# 03: Safety: exclusions and the service prefilter

**What to build:** enforcement can never reach traffic the operator never
intended to touch. Excluded prefixes are subtracted from every ban set,
overriding every report, and every ban rule leads with the service
prefilter — the protected destinations' ports and addresses — so a ban
applies only to service traffic, never to SSH, monitoring, or unrelated
forwarded traffic.

**Blocked by:** 02 — Kernel install: the nftables driver

**Status:** ready-for-agent

- [ ] Loopback and link-local prefixes are always excluded and cannot be re-included
- [ ] RFC1918 and ULA prefixes are excluded by default, with an opt-out flag for hosts whose clients live in private space
- [ ] A repeatable `--exclude-prefix` flag adds operator exclusions (this one flag subsumes bandaid's whitelist and fluxc's exclude-prefix surfaces)
- [ ] Exclusions are subtracted from every ban set; a report whose Target is fully excluded produces no ban rule
- [ ] Every ban rule first matches the destination-port set and the destination-address set; either may be empty, meaning all; both are operator-configured
- [ ] `--dry-run` shows each ban rule's effective sets after exclusion subtraction
- [ ] Seam tests cover the subtraction, the prefilter construction, and the empty-set outcomes, with a failing and a passing case per validation

Context: spec `../spec.md` (Compilation model: exclusions, service
prefilter).
