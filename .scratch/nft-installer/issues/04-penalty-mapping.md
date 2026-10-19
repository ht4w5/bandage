# 04: Penalty mapping and direction split

**What to build:** every Penalty a Report carries is applied the way the
contract defines it — drop discards, reject refuses with an error signal,
`limit-pkt-rate` throttles packets, `limit-bandwidth` throttles
response-payload bytes in the direction those bytes actually flow — and
`limit-req-rate` is deliberately not applied, being application-layer
intent. The mapping is total over the closed vocabulary, so a consumer's
switch is never silently wrong.

**Blocked by:** 02 — Kernel install: the nftables driver

**Status:** ready-for-agent

- [ ] `drop` installs a silent drop
- [ ] `reject` installs `reject with icmpx admin-prohibited` in every hook (TCP peers get a reset automatically); the kernel floor for reject at prerouting is noted for the docs pass
- [ ] `limit-pkt-rate` installs an ingress packet-rate meter over `rate` per second followed by drop
- [ ] `limit-bandwidth` installs a byte-rate meter over `rate` bytes per second on an **egress** chain (output in input mode, forward in prerouting mode) matched on destination ∈ Target — the response direction the contract's unit names
- [ ] Rate meters carry a derived burst of one second's worth, floored — no burst flag
- [ ] `limit-req-rate` reports are skipped, logged, and counted; nothing is installed for them
- [ ] `--dry-run` prints one mapping line per ban rule (stance, rate, chain)
- [ ] Seam tests cover all five actions with a failing and a passing case each; the root-gated read-back covers both chains

Context: spec `../spec.md` (Penalty → nftables mapping); ADR 0010
(penalty intent) and ADR 0011 (`limit-req-rate` skip).
