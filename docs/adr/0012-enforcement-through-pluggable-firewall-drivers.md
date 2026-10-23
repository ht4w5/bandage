# Enforcement through pluggable firewall drivers

`splint` (renamed from `splint-nft`) is one consumer binary that enforces
ban rules through a selected **firewall driver** (`--firewall`; the
nftables driver in v0) instead of being an nftables tool. ADR 0011's
binding of the consumer to "a dedicated nftables table" is superseded
**in part** here; its daemon/consumer split and merge policy stand. The
old spec decision "a future backend is a sibling binary, not a driver
flag" is reversed. A driver is not necessarily a kernel firewall —
nginx, a WAF, or any enforcement surface may implement the seam — and
each driver owns the configuration that differs between surfaces: where
to enforce (nftables' nsfs namespace paths) and what to police (its
service prefilter of destination ports and addresses) are driver flags,
not engine flags.

A driver applies each Penalty exactly as stated or declines it loudly —
it never substitutes or tunes — and reports its declines so the engine
can log and count them. ADR 0011's "`limit-req-rate` is deliberately not
applied" narrows accordingly: the nftables driver declines request-rate
limits as application-layer intent; a driver whose enforcement surface
is the application layer may apply them. The rolling hash,
skip-if-unchanged and rule counters also live in the driver, because
only the driver knows which ban rules are actually effective and which
it drops; `--dry-run` prints the driver's plan without touching its
enforcement surface.

Considered: sibling consumer binaries per backend (rejected: each
duplicates fetch, merge and lifecycle, and a binary per backend does not
scale); a generic engine-level model of targets and enforcement scope
(rejected: targeting and scoping are exactly what differ between
enforcement surfaces — a web-server driver needs neither nsfs paths nor
destination-port prefiltering). Recorded because "splint is the nftables
tool" is now false: it is the ban-rule consumer whose enforcement
surface is pluggable.
