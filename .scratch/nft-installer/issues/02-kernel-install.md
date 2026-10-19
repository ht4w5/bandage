# 02: Kernel install: the nftables driver

**What to build:** as root, the ban rules actually exist in the kernel: a
wholly-owned inet table named `splint` in the target namespace, with an
ingress chain at the configured hook, holding the compiled ban rules. Every
install replaces the table's contents atomically; reset deletes the table.
Running without the needed privileges fails loudly at the startup install
rather than silently not banning.

**Blocked by:** 01 — Walking skeleton

**Status:** ready-for-agent

- [ ] Install creates the owned `splint` inet table and an ingress chain at `--hook input` (default) or `--hook prerouting`, with each ban rule matching source ∈ its Target set and dropping
- [ ] Each install rebuilds the whole table in a single atomic batch — no delete-then-rebuild window
- [ ] Reset removes the owned table and tolerates it being already absent
- [ ] Missing netlink privileges surface as a loud startup failure
- [ ] The real driver is verified by one root-gated integration test — install, read the kernel state back, reset — skipped where privileges are absent
- [ ] The stub driver remains the test surface; nothing at the update-cycle seam requires privileges
- [ ] `--dry-run` still works unprivileged and unchanged

Context: spec `../spec.md` (nftables shape); flux's nft driver in the
reference checkout is the construction DNA.
