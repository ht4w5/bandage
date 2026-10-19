# Reports feed ban rules; enforcement is out of scope

A report's `reason` exists to be materialized in ban rules that downstream
tooling generates from reports. The reason slug is therefore a
compatibility contract from day one: lowercase slug
(`^[a-z0-9][a-z0-9_-]*$`), not unique — several rules may share one reason
so multiple signals can feed a single ban reason. The rule ID is internal
provenance, not part of that contract.

bandage itself only produces reports; ban-rule generation and enforcement
are deliberately out of scope for v0.

Superseded in part by ADR 0011: the repo now ships **splint-nft**, the
downstream tooling that generates and installs ban rules from reports —
as a separate consumer binary, outside bandage the daemon, which still
only produces reports and never enforces.
