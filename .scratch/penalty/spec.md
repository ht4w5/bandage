# Penalty in reports — spec

Status: ready-for-agent

## Problem Statement

Reports say what happened (a Reason, a Target, a tracker reading, a Sample) but not what to do about it. Every external report consumer must invent its own enforcement stance per report — one tool drops, another throttles — and nothing in the report tells them what the rule author meant. On top of that, the report JSON format exists only in the code that writes it: consumers reverse-engineer the shape, and there is no version or evolution policy to integrate against. Likewise for ingest: the nginx log format the parser expects is documented nowhere in the repo, so operators copy it from the reference projects and hope.

## Solution

Every report carries a **Penalty** — the enforcement stance the rule's report action recommends for the Target — as a required, closed vocabulary: `drop`, `reject`, `limit-pkt-rate`, `limit-bandwidth`, `limit-req-rate`, the limits carrying a `rate` in the unit their name states. The rule author sets it on the report action; the consumer decides what to do with it (bandage advises, never enforces). The report JSON becomes a canonical, versioned document published in the repo and pinned by a test that reproduces its own example. Ingest gets a shipped nginx `log_format` config carrying exactly the parser's field contract.

## User Stories

1. As a rule author, I want every report action to declare a penalty — `drop`, `reject`, `limit-pkt-rate`, `limit-bandwidth` or `limit-req-rate` — so that every report states the enforcement stance I recommend for its Target.
2. As a rule author, I want to declare the penalty as a `penalty:` key on the report action beside `reason` and `ttl`, so that the stance lives with the other report metadata.
3. As a rule author, I want to give a limit penalty its threshold with a `rate:` key, so that the recommendation carries how much is tolerated per second.
4. As a rule author, I want `rate` to accept plain counts (`200`) and decimal human sizes (`1MB` = 1e6), so that it reads like the tracker's leak and volume config.
5. As a rule author, I want the rate's unit to be named by the penalty I chose — packets, response-payload bytes, or requests per second — so that one parameter serves all three limits without unit ambiguity.
6. As a rule author, I want bandage to refuse a rules file where a limit penalty has no rate or a non-positive rate, so that an incomplete recommendation can never reach a consumer.
7. As a rule author, I want bandage to refuse a rules file where `rate` accompanies `drop` or `reject`, so that the config stays unambiguous.
8. As a rule author, I want bandage to refuse unknown penalty names at load time, so that typos surface at `bandage -t` rather than at enforcement time.
9. As a rule author, I want the `bandage -t` plan to print each report action's penalty and rate, so that I can audit every recommendation before deploying.
10. As a rule author, I want the penalty checked for well-formedness only — never against my rule's tracker or reason — so that I stay free to recommend any stance, since applying it is the consumer's decision.
11. As a rule author, I want rules sharing one reason to be able to recommend different penalties, so that the reason stays a shared trigger code while each rule advises what it saw fit.
12. As a rule author, I want a tracker-less tripwire rule to advise `drop` with no rate, so that immediate flags recommend a stance matching their severity.
13. As a rule author, I want a bandwidth-tracker rule to be able to advise `limit-bandwidth` and a rate-tracker rule `limit-req-rate`, so that the shipped examples show the idiomatic pairings.
14. As a report consumer, I want every report to carry its penalty, so that I never have to invent a default stance for a target.
15. As a report consumer, I want the penalty as a nested object — `action` plus `rate` for limits — so that the stance and its parameters travel together and future parameters never touch the report's top level.
16. As a report consumer, I want `action` restricted to the five closed values, so that my switch over the enum is total; if a value is ever added, the format version bumps.
17. As a report consumer, I want `rate` present exactly when `action` is a limit and absent otherwise, so that I never parse defensively.
18. As a report consumer, I want `rate` as an integer ≥ 1 in the unit named by the action, so that it feeds integer enforcement primitives without float noise.
19. As a report consumer, I want a canonical, versioned definition of the report document, so that I integrate against a published contract instead of reverse-engineering the code.
20. As a report consumer, I want the contract pinned by a test that reproduces its example byte-for-byte, so that document and implementation cannot drift.
21. As a report consumer, I want the intent of each penalty spelled out in the contract — drop discards the Target's traffic silently, reject refuses it with an error signal, limits throttle it to `rate` — so that the vocabulary means the same thing to every consumer.
22. As a report consumer, I want the contract to state explicitly that applying the penalty is my decision, so that I know bandage advises and never enforces.
23. As a report consumer, I want each limit defined over the report's Target as an aggregate, so that I know the number governs the whole prefix rather than each host inside it.
24. As a report consumer, I want `limit-bandwidth` defined over response payload — the bytes the Sample's `sent` counts — so that the recommendation and the evidence share one notion of bytes.
25. As a report consumer, I want the penalty to freeze with its report while the report is alive, so that the stance I read always matches the Sample that justified it.
26. As a report consumer, I want a deleted or expired report's replacement Trigger to carry the penalty of the loaded rules at write time, so that re-armed writes never resurrect stale advice.
27. As a report consumer, I want an evolution policy on the contract — additive fields don't bump the version, breaking changes including new penalty values do — so that I know exactly when my integration must change.
28. As a report consumer, I want the envelope and timestamp rules spelled out in the contract (version, generated_at, ordering, RFC 3339 UTC), so that parsing the document is mechanical.
29. As an operator, I want the penalty persisted with the report across daemon restarts, so that consumers see the same advice before and after a restart.
30. As an operator, I want a ready-to-include nginx `log_format` config shipped with bandage, so that I wire access-log ingest without reverse-engineering the parser's field contract.
31. As an operator, I want that log_format to carry the `agent` field, so that agent-based rules (the tripwire pattern) work with the shipped format.
32. As an operator, I want the log_format named `bandage`, so that including it never collides with an existing `flux` format definition in my nginx config.
33. As an operator, I want the ingest format named after bandage in the docs and config comments — with a flux-compatibility note for migrations — so that the repo's canonical formats are self-referential.
34. As an operator, I want the rules documentation to cover `penalty` and `rate` with worked examples, so that I can write correct report actions without reading parser code.

## Implementation Decisions

- **Penalty vocabulary** (closed enum): `drop`, `reject`, `limit-pkt-rate`, `limit-bandwidth`, `limit-req-rate`. The dimension lives in the name. Chosen over a single `limit` value with a unit-carrying parameter, which hid the dimension and made the parameter name collide with the rate tracker's request-count meaning (ADR 0010 records the trade-off).
- **Wire shape** (nested; decision-rich, from the design sessions):

  ```json
  "penalty": { "action": "limit-bandwidth", "rate": 1000000 }
  ```

  `action` mirrors the downstream webjail penalty wire field. `rate` is present iff `action` is a `limit-*`, integer (`int64`) ≥ 1, in the unit the action name states; `drop`/`reject` carry no `rate`.
- **Rules DSL** (flat keys on the report action, matching `reason`/`ttl` style):

  ```yaml
  - report:
      reason: iso-egress-overflow
      ttl: 7d
      penalty: limit-bandwidth
      rate: 1MB
  ```

- **Rate parsing**: the same decimal human-size parser the tracker config uses (`1MB` = 1e6, optional `/s` suffix tolerated); plain numbers count in the unit named by the penalty. Serialized as an integer on the wire.
- **Rate scope and unit semantics**: all limits are aggregate over the report's Target. `limit-bandwidth` is defined over response payload (the Sample's `sent` notion of bytes); `limit-pkt-rate` counts packets at the enforcement layer — an intentional asymmetry: the contract defines intent, not mechanics.
- **Penalty is required** on every report action and therefore on every report record. There is no report without a stance.
- **Validation matrix** at rules load: `penalty` required; value must be one of the five; `rate` required and positive with `limit-*`; `rate` rejected for `drop`/`reject`; unknown keys on the report action still rejected. No tracker↔penalty and no reason↔penalty coherence checks — coherence is the consumer's judgment (ADR 0010).
- **Canonical report document**: published as the repo's report-format doc (consumer-facing contract name `docs/reports.md`), superseding the plan's example. Envelope stays `version: 0` — the canonical v0 includes the penalty. Evolution policy in the doc: additive optional fields don't bump the version; breaking changes — including new enum values — do.
- **Trigger semantics unchanged** (ADR 0008): the penalty is written at the Trigger that creates the report and freezes with the report while it is alive; a re-armed write (after delete or expiry) carries the penalty of the then-loaded rules.
- **Persistence**: the report body JSON gains `penalty`; no new columns, no index changes, no migration. Rows predating the change decode without a penalty and are outside the canonical contract (pre-release).
- **Domain docs**: GLOSSARY updated (Penalty term; Report entry carries the penalty; Ban rule avoids only "ban"); ADR 0010 records the advisory framing, keeping ADR 0004 intact.
- **Docs and examples**: the rules doc gains a `penalty`/`rate` section with worked examples (tripwire with `drop`, tracker rules with their idiomatic limits); the example rules config gains penalties on every report action; the plan's report-format and validation sections are updated to reference the canonical doc; the `--test` plan prints penalty and rate.
- **Ingest**: a shipped nginx config snippet under `configs/nginx/` named `bandage_log.conf` — an operator-facing artifact, so its location is part of the contract. It contains exactly one directive: `log_format bandage escape=json` with the parser's seven mapped fields — `time` (`$msec`, rendered as a quoted JSON string), `client`, `method`, `url`, `status`, `sent`, `agent` (`agent` is parser-optional but the tripwire pattern depends on it; the reserved `host`/`server`/`duration` superset is deliberately excluded and stays accepted-and-ignored for deployments that add fields). No vhost, no usage comments.
- **Naming**: "flux log format" is retired from the parser's comment, the daemon config comment, and the ingest docs in favor of "the bandage nginx log format", with a "(flux-compatible)" migration note where it aids migration.

## Testing Decisions

- A good test asserts external behavior at the daemon's boundaries — raw rules YAML in → validated plan or load refusal out; raw nginx-JSON syslog messages in → `GET /reports` JSON out — and never asserts internal plumbing (which domain fields got copied into a report body).
- **Primary seam: the assembled daemon** (the existing end-to-end seam: real ingest listener, injected fixed wall clock whose timestamps already mirror the contract example, asserted through `GET /reports` JSON). Everything observable end-to-end is tested here: penalty propagation from rule to document, the byte-exact canonical-format pin against the report-format doc's example, freeze-while-alive, re-arm with the then-current penalty, and persistence across a store reopen. No new seam.
- **Secondary seam: rules loading** (the existing load-validation suite, failing and passing case per validation) — used only where the primary seam cannot see: the validation matrix's load refusals and the `--test` plan text, because a daemon that refuses to start cannot be driven end-to-end.
- The persistence round-trip is observed through the primary seam; the repository suite's existing schema-contract tests are updated to the new body shape rather than extended into a new seam.
- Prior art: the end-to-end suite's "primary seam" contract (syslog in, report document out), the rules suite's "every rule gets a failing and a passing case" convention, the sqlite schema-contract tests, and the parser compat pins (untouched — they keep proving `agent`-optional and reserved-field tolerance).

## Out of Scope

- Enforcement of any kind: bandage never applies penalties, and never generates Ban rules (ADR 0004).
- Consumer semantics beyond the defined intent: how, whether, or how restrictively a consumer applies a penalty is theirs (e.g. "take the strictest wins" policies across conflicting reports).
- A JSON Schema artifact for the report document (prose contract + byte-exact pin for now).
- Version bump or migrations for rows written before the penalty existed.
- Hot reload: rule edits (including penalty changes) take effect on restart, as today.
- New penalty values beyond the five; fractional or per-minute/per-hour rates; per-client scoping of limits within a Target.
- Coherence validation between penalty, tracker kind, and reason.
- Any change to the nginx parser.

## Further Notes

- The GLOSSARY and ADR 0010 were written during the design sessions; this spec implements them and does not reopen them.
- `rate` is deliberately kept as the parameter name despite colliding with the tracker kind `rate` (request accumulation): the namespaces never mix (tracker block vs. penalty block; `tracker.track` vs. `penalty.rate` on the wire), and the contract pins both meanings.
- The five enum names encode their dimension; resist future simplification back to a single `limit` value — the trade-off is recorded in ADR 0010.
- The report-format doc's example must be authored so a driven end-to-end scenario reproduces it exactly (the seam's injected clock already uses the plan example's timestamps); the byte-exact pin then guards both directions — code and doc.
