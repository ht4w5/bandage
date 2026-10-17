# One tracker per rule

Each rule has at most one tracker (leaky bucket), and a report's `tracker`
field is singular. Compound conditions ("requests ≥ N **and** bytes ≥ M")
are out of scope for v0.

The alternative — flux-style multi-bucket AND matching — is the natural
extension if needed, but it widens the DSL, the match semantics, and the
report shape for conditions no v0 rule needs.
