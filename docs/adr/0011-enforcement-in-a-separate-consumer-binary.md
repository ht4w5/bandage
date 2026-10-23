# Enforcement lives in a separate consumer binary

The repo now ships the downstream tooling ADR 0004 pointed at:
**splint-nft**, a companion binary that pulls the report document,
compiles ban rules from reports, and installs them into a dedicated
nftables table. The daemon's contract is unchanged — bandage produces
reports and never enforces — but "ban-rule generation and enforcement
are out of scope" is superseded **in part**: generation and enforcement
exist in this repo, outside the daemon, as a strict wire consumer of the
report document (it parses the published contract; it imports no daemon
internals). Overlapping reports compile most-specific-Target-first, ties
resolve by the strictest Penalty (`drop` > `reject` > limits;
dimensionally incomparable limits are combined rather than ordered), and
`limit-req-rate` reports are deliberately not applied — request rates
are application-layer intent.

Considered: enforcement inside the daemon (rejected: the advisory
penalty would collapse into mechanics the rule author never controls,
and CAP_NET_ADMIN would land on the log analyzer); a separate repo
(rejected: one test run and shared build identity are worth more than
the repo boundary, and keeping the consumer in-repo makes the report
contract load-bearing). Recorded because "this repo never enforces" is
now false at repo level and true at daemon level, which future readers
will trip over.

Superseded in part by ADR 0012: the consumer enforces through a
pluggable **firewall driver** selected by `--firewall`, not a binding to
a dedicated nftables table, and `limit-req-rate`'s non-application is
the nftables driver's decline rather than a blanket policy — a driver
whose enforcement surface is the application layer may apply it.
