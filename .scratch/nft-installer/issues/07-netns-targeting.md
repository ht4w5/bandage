# 07: Network-namespace targeting

**What to build:** the operator points `splint-nft` at a Docker container's
network namespace instead of the host, and gets exactly the same enforcement
there: one `splint` table per targeted namespace, installed through the
library's namespace-fd netlink option. A recreated container is picked up as
long as the operator keeps a stable namespace handle; a namespace that
vanishes mid-run never halts enforcement elsewhere.

**Blocked by:** 02 — Kernel install: the nftables driver

**Status:** ready-for-agent

- [ ] A repeatable `--netns <nsfs-path>` flag selects target namespaces; the default is the current namespace
- [ ] Each namespace gets its own `splint` table; one fetch-compile serves all targets
- [ ] Netlink runs per namespace through the library's namespace-fd option — no setns, no thread locking
- [ ] Namespace paths are re-opened every cycle, so a recreated container is picked up through a stable handle; the per-namespace installed-hash state follows each namespace
- [ ] An unreachable namespace is warned and skipped for the cycle; the other namespaces still install; reset on exit tolerates vanished namespaces
- [ ] The root-gated integration test installs into a non-default scratch namespace when privileges allow
- [ ] Seam tests cover multi-target install, skip-and-warn on a missing namespace, and per-namespace skip-if-unchanged

Context: spec `../spec.md` (Network namespaces); stable-handle recipes
land in ticket 09.
