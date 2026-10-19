# splint-nft: nftables rule installer — spec

Status: ready-for-agent

## Problem Statement

Bandage publishes reports and never enforces (ADR 0004; the GLOSSARY's
Ban rule entry): every report states a Target and the advisory Penalty
its rule author recommends for it, and then stops there. The operator
who wants those recommendations enforced has to write the consumer
themselves — fetch the report document, decide what overlapping reports
with different penalties mean, translate five penalty actions into
firewall constructs, and keep the result current as reports expire.
That is real work with real foot-guns: a naive consumer bans the
operator's own SSH session, misreads which direction a bandwidth limit
belongs to, or leaves stale bans behind when it dies.

## Solution

`splint-nft`, a companion binary shipped in this repo: it pulls the
report document from bandage on a fixed interval, compiles the reports
into ban rules, and installs them into a dedicated nftables table in the
host's — or a chosen container's — network namespace. The compiled rules
resolve overlapping reports by most specific Target first and strictest
Penalty on ties, apply each Penalty as stated, and are protected by a
service prefilter and default exclusions so enforcement can never reach
traffic the operator never intended to touch. The ruleset carries a
rolling hash: when the compiled ban rules have not changed, the install
is skipped entirely. On shutdown the table is reset; on a failed fetch
the last rules stay. The operator audits everything with `--dry-run`,
sees whether bans fire through per-rule counters, and deploys with a
sample systemd unit.

## User Stories

1. As an operator, I want splint-nft to pull the report document from bandage and install ban rules on a fixed interval, so that enforcement follows my reports without manual steps.
2. As an operator, I want a startup test install that fetches, compiles and installs once before the loop begins, so that a broken config, endpoint or kernel fails at deploy time rather than at ban time.
3. As an operator, I want the update interval to default to 5 minutes with a 1-minute floor, so that bans and un-bans track report expiry within minutes without timer churn.
4. As an operator, I want the last installed rules kept when a fetch fails, so that a bandage outage never opens the floodgates.
5. As an operator, I want the owned table reset on SIGINT/SIGTERM, so that stale bans never outlive a clean shutdown.
6. As an operator, I want splint-nft to fail loudly when it lacks the netlink privileges it needs, so that I notice at startup instead of silently not banning.
7. As an operator, I want to point splint-nft at a network namespace by path, so that I can enforce inside a Docker container's namespace instead of the host.
8. As an operator, I want that flag to be repeatable, so that one instance can enforce the same ban rules across several containers and the host.
9. As an operator, I want the namespace path re-opened every cycle, so that a recreated container is picked up as long as I keep a stable handle on its namespace.
10. As an operator, I want a namespace that vanished to be skipped with a warning while the others still install, so that one dead container cannot halt enforcement everywhere.
11. As an operator, I want to choose the enforcement hook (input or prerouting), so that I can protect a web server host or a routing box with the same tool.
12. As an operator, I want a prefilter of destination ports and destination addresses ahead of every ban lookup, so that bans never touch SSH, monitoring, or unrelated forwarded traffic.
13. As an operator, I want loopback and link-local excluded from bans always, so that local tooling can never be banned.
14. As an operator, I want private address space excluded by default with an opt-out, so that internal infrastructure is safe unless I say otherwise.
15. As an operator, I want my own exclusion prefixes subtracted from every ban set, so that no report can override my safety margins.
16. As an operator, I want fetches over plain HTTP locally and HTTPS with mutual TLS remotely, so that I can deploy the same binary in both shapes.
17. As an operator, I want the TLS surface to mirror bandaid's CA/cert/key flags and fetch timeout, so that I reuse my existing PKI runbook.
18. As an operator, I want `--dry-run` to print the compiled ban rules and the ruleset hash without touching netlink and without privileges, so that I can audit what would be enforced anywhere.
19. As an operator, I want per-rule counters with nonzero hits logged at each install, so that I can see whether a ban is firing.
20. As an operator, I want unchanged ban rules to skip the reinstall, so that quiet periods cost no netlink churn.
21. As an operator, I want the skip to still probe that the table exists, so that a recreated container or an external reset cannot hide behind an unchanged hash.
22. As an operator, I want the ruleset hash logged every cycle and printed by `--dry-run`, so that I can correlate installs across runs.
23. As an operator, I want a shipped sample systemd unit and dry-run audit recipe, so that deployment is copy-paste.
24. As an operator, I want one instance per namespace documented, so that I never run two instances fighting over one table.
25. As a rule author, I want my report action's penalty applied as stated — drop, reject, limit-pkt-rate, limit-bandwidth — so that my enforcement stance reaches the wire.
26. As a rule author, I want `limit-bandwidth` metered on the response direction, so that it throttles response-payload bytes exactly as the contract defines them.
27. As a rule author, I want `limit-req-rate` reports deliberately not applied, logged and counted instead, so that application-layer intent is never faked at the packet layer.
28. As a rule author, I want the most specific target to win even when its stance is weaker, so that a fine-grained report can carve an exception under a broader ban.
29. As a rule author, I want reports over the same specificity resolved by the strictest penalty, so that conflicting advice resolves deterministically.
30. As a rule author, I want tied limits of incomparable dimensions combined — both meters enforced — so that no recommendation is lost to an invented ordering.
31. As a rule author, I want `reject` rendered as an inet-family-neutral reject, so that TCP peers get a reset and the rest an error signal.
32. As a rule author, I want rate limits to carry a sensible derived burst, so that legitimate micro-bursts survive enforcement.
33. As a report consumer, I want records with a missing or unknown penalty or an unparseable target skipped with a log and a counter, so that one pre-release record never blocks enforcement of the rest.
34. As a report consumer, I want an unknown document version to refuse the cycle and keep the last rules, so that breaking changes are never silently miscompiled.
35. As a report consumer, I want unknown document fields ignored, so that the contract's additive changes never break me.
36. As a report consumer, I want the document parsed as the published contract rather than daemon internals, so that the contract stays the load-bearing integration surface.
37. As a report consumer, I want bans to expire with their reports through the full rebuild each cycle, so that un-bans happen without manual action.
38. As a report consumer, I want the penalty-to-nftables mapping published in the consumer docs, so that I know exactly what each recommendation becomes.
39. As an operator, I want the kernel floor for reject-in-prerouting documented, so that I can pick a hook knowingly on older kernels.
40. As a developer, I want the whole fetch-compile-install cycle exercised at the firewall-driver boundary with fixture documents, so that every policy is tested without netlink.
41. As a developer, I want the report document's canonical example reused as a fixture, so that the contract and its consumer cannot drift.
42. As a developer, I want a stub firewall driver, so that lifecycle behavior — skip-if-unchanged, keep-on-failure, reset-on-exit — is testable unprivileged.
43. As a developer, I want a root-gated netlink integration test for the real driver, so that the kernel surface is verified wherever privileges exist.
44. As a developer, I want the tests to assert only which ban rules would be installed, so that the compiler's internals stay refactorable.
45. As a developer, I want the rolling-hash construction mirrored from bandaid, so that the skip behavior is deterministic and familiar across both tools.

## Implementation Decisions

- **Binary and placement**: `splint-nft`, a second command in the bandage
  module, sharing the build-identity stamping of the daemon. The daemon
  is renamed nothing; `bandage` stays the flagship. A future backend is
  a sibling binary sharing the compiler, not a driver flag: there is no
  user-facing `--firewall-driver` in v0.
- **Strict contract consumer**: splint-nft parses the versioned report
  document (envelope, report records, penalty) into its own small wire
  DTOs and imports no daemon internals. It ignores unknown fields per
  the document's evolution policy, refuses a version it does not know,
  and stands as a living check that the published contract is
  sufficient.
- **Module shape**: a fetch loop (fluxc's lifecycle: startup test
  install, ticker, signal context), a pure compiler (reports to ban
  rules), and a tiny firewall-driver port — install and reset — with
  nftables and stub implementations.
- **nftables library**: `github.com/google/nftables` via netlink (flux's
  choice), including its network-namespace option; no shelling out to
  `nft`.
- **nftables shape**: one wholly-owned inet table named `splint` per
  target namespace, rebuilt wholesale in a single atomic batch per
  install (fluxc's two-batch delete-then-rebuild gap is deliberately not
  copied). Two chains per table: an **ingress** chain at the configured
  hook (input by default, prerouting for routing boxes) carrying drop,
  reject and packet-rate stances, and an **egress** chain (output in
  input mode, forward in prerouting mode) carrying bandwidth limits
  matched on destination ∈ target — the direction its unit names.
- **Penalty mapping** (total over the closed v0 vocabulary):

  | penalty | nftables construct |
  |---|---|
  | `drop` | verdict `drop` |
  | `reject` | `reject with icmpx admin-prohibited` (TCP gets a reset automatically) |
  | `limit-pkt-rate` | `limit rate over N/second`, then `drop` |
  | `limit-bandwidth` | `limit rate bytes over N/second` on the egress chain, then `drop` |
  | `limit-req-rate` | **not applied** — skipped, logged, counted |

- **Merge policy**: most specific Target wins (longest-prefix semantics:
  a `/32` report can carve an exception under a `/16` ban even with a
  weaker stance); ties on specificity resolve strictest-first (`drop` >
  `reject` > limits; smaller `rate` stricter within one action);
  dimensionally incomparable limits at a tie are combined — one meter
  per direction, both enforced.
- **Compilation**: reports group by (family, prefix length, penalty)
  into one ban rule per group with an equal-length prefix set (equal
  length prefixes are disjoint, so rules have no internal overlap);
  ban rules order by prefix length descending, then strictness, so
  nftables first-match reproduces the merge policy. Each rule first
  matches the service prefilter (destination-port and destination-address
  sets; either may be empty — empty means all).
- **Exclusions**: loopback and link-local are always excluded;
  RFC1918 and ULA are excluded by default with an opt-out flag;
  operator exclusion prefixes (repeatable) add to the list. Exclusions
  are subtracted from every ban set, overriding every report. This
  unifies what bandaid calls its whitelist and fluxc its exclude
  prefixes into one flag.
- **Rate-limit burst**: derived from the rate (one second's worth,
  floored) — no burst flag in v0. Arbitrary rates with nft's tiny
  default burst would drop legitimate micro-bursts.
- **Counters**: every compiled rule carries a packet/byte counter;
  nonzero hits are logged at each install, so the reported period is
  "since the last change".
- **Rolling hash** (bandaid's construction): the compiled ruleset after
  exclusions and merge, in canonical order, folded into an FNV-1a
  32-bit rolling chain with bandaid's seed. The install is skipped when
  the hash matches the last installed hash for that namespace **and**
  the table exists (a cheap probe each cycle); otherwise it installs.
  Known limit: tampering with rules under a surviving table is not
  detected — the probe is existence, not rule bodies. The hash appears
  in cycle logs and `--dry-run` output.
- **Lifecycle**: startup test install (exit non-zero on failure); fetch
  every cycle (default interval 5m, floor 1m, fetch timeout bandaid's
  default); a failed fetch keeps the last installed rules with a loud
  log; SIGINT/SIGTERM resets the owned table before exit (vanished
  namespaces tolerated); missing netlink privileges fail at startup.
- **Network namespaces**: a repeatable namespace-path flag; the netlink
  connection is created per namespace through the library's netns-fd
  option (no setns). Paths are re-opened every cycle so a recreated
  container is picked up through a stable handle; an unreachable
  namespace is warned and skipped for the cycle. Default: the current
  namespace. Documented: namespace names via an `ip netns attach`-style
  stable handle, Docker's per-pid namespace path, one instance per
  namespace.
- **Transport**: HTTP and HTTPS with mutual TLS — CA to verify the
  server, optional client certificate and key (bandaid's flag surface).
  Bandage itself serves plain HTTP, so TLS terminates at whatever fronts
  it; that deployment note goes in the docs. No insecure-skip-verify.
- **Ops artifacts**: a sample systemd unit and a dry-run audit recipe in
  the consumer documentation, alongside the flags, the mapping table,
  the merge policy, and the kernel floor (~5.9) for reject-in-prerouting
  — the startup test install is what catches older kernels.
- **Domain docs**: the GLOSSARY's Ban rule entry names splint-nft as the
  downstream tool; ADR 0011 records the daemon/splint split, the merge
  policy, and the `limit-req-rate` skip; ADR 0004 carries a
  superseded-in-part note.

## Testing Decisions

- **What makes a good test here**: only external behavior — given a
  report document, which ban rules would be installed, and when. No
  assertions on compiler internals, hash internals, or netlink encoding;
  the skip-if-unchanged behavior is asserted observably (a second
  identical document produces no install; a changed one does).
- **One seam — the update cycle at the firewall-driver boundary**: fetch
  from a fake report endpoint, compile, and observe the stub driver's
  install calls. Everything lives at this seam: the merge-policy matrix
  (most-specific exceptions, strictest ties, combined limits), the
  penalty mapping table, the `limit-req-rate` skip, exclusion
  subtraction, prefilter construction, skip-record and
  refuse-unknown-version tolerance, skip-if-unchanged with the table
  probe, keep-on-failed-fetch, reset-on-exit, and `--dry-run` text.
  Compiler policy cases come in as fixture documents, reusing the report
  document's canonical example as the base fixture and following the
  suite's convention of a failing and a passing case per validation.
- **Root-gated verification (not a second seam)**: the nftables driver
  gets one integration test — install, read the kernel rules back,
  reset — skipped where privileges are absent. It verifies the driver's
  own encoding, nothing else.
- **Prior art**: the daemon's end-to-end tests drive a full pipeline
  against fakes; bandaid tests its fetch-and-generate loop against a
  test HTTP server; flux ships a stub firewall driver beside its nft
  one. This spec's seam is the same shape as bandaid's loop test with
  flux's stub swapped in as the observation point.

## Out of Scope

- Any change to the bandage daemon: it keeps advising and never
  enforcing; the report API needs no new endpoint or field.
- In-kernel self-expiry of ban rules (set-element timeouts) —
  deliberately deferred; consequence accepted: a *crashed* installer
  leaves its table installed until reboot or manual reset, because
  expiry is rebuilt-based and only a clean exit resets.
- Enforcing `limit-req-rate` (application-layer intent).
- Any firewall backend besides nftables (iptables, pf, eBPF), and
  therefore the user-facing driver flag.
- Incremental updates: no set diffing or per-element patching; every
  install is a full atomic rebuild.
- TLS support inside bandage itself.
- Per-reason enforcement policy, a policy map, or a configurable merge
  policy — the merge policy is fixed in v0.
- Detection of rule-level tampering beneath a surviving table.
- Multiple splint-nft instances per namespace, or multiple tables per
  instance beyond the per-namespace table.
- Machine-readable metrics (counters are logged, not exported).
- Burst configurability, and any ban dimension beyond the Target's
  source prefix (no port, path, or agent bans).

## Further Notes

- Reference DNA: flux's `fluxc` supplies the client lifecycle and the
  nftables driver shape (interval sets per family, wholly-owned table);
  bandaid supplies the rolling hash, the mTLS fetch surface, the
  whitelist idea, and the fetch-and-generate loop test shape. Both live
  in the repo's reference checkouts.
- The report document's evolution policy (additive fields don't bump the
  version; new penalty values do) is what keeps splint-nft's switch over
  the penalty vocabulary total for version 0.
- Ban staleness is bounded by the update interval: a report that expires
  between cycles keeps its ban until the next install. The 5-minute
  default bounds that to five minutes; a shorter interval tightens it.
- The egress chain for bandwidth limits is the one place splint-nft
  departs from fluxc's single-hook shape: fluxc's bans are unconditional
  drops, while `limit-bandwidth`'s contract names response-payload
  bytes, which only exist in the response direction.
- Naming: the splint theme (a splint immobilizes) extends the repo's
  first-aid vocabulary; the `-nft` suffix names the artifact the tool
  manages, matching bandaid naming its geo-file job.
