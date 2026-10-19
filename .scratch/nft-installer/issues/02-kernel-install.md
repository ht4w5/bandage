# 02: Kernel install: the nftables driver

**What to build:** as root, the ban rules actually exist in the kernel: a
wholly-owned inet table named `splint` in the target namespace, with an
ingress chain at the configured hook, holding the compiled ban rules. Every
install replaces the table's contents atomically; reset deletes the table.
Running without the needed privileges fails loudly at the startup install
rather than silently not banning.

**Blocked by:** 01 — Walking skeleton

**Status:** resolved

- [x] Install creates the owned `splint` inet table and an ingress chain at `--hook input` (default) or `--hook prerouting`, with each ban rule matching source ∈ its Target set and dropping
- [x] Each install rebuilds the whole table in a single atomic batch — no delete-then-rebuild window
- [x] Reset removes the owned table and tolerates it being already absent
- [x] Missing netlink privileges surface as a loud startup failure
- [x] The real driver is verified by one root-gated integration test — install, read the kernel state back, reset — skipped where privileges are absent
- [x] The stub driver remains the test surface; nothing at the update-cycle seam requires privileges
- [x] `--dry-run` still works unprivileged and unchanged

Implemented on integration branch `feat/splint-nft` (merge commit `8ea2775`; cross-ticket code-review fixes through `1879da4`). The driver kept the seams later tickets plugged into (prefilter, stance verdicts + egress chain, counters + `TableExists` probe, netns fd).

Context: spec `../spec.md` (nftables shape); flux's nft driver in the
reference checkout is the construction DNA.
