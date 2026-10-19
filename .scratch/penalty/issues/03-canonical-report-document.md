# 03: Canonical report document and the byte-exact pin

**What to build:** A report consumer integrates against a published contract instead of the code: the canonical report document definition (the report-format doc in the repo docs area, consumer-facing contract name `docs/reports.md`). It defines the envelope (`version: 0`, `generated_at`, report ordering, RFC 3339 UTC timestamps) and every record field including the penalty, states the intent of each penalty value (drop discards the Target's traffic silently, reject refuses it with an error signal, limits throttle it to `rate`, aggregated over the report's Target, `limit-bandwidth` over response payload), states explicitly that applying the penalty is the consumer's decision, and records the evolution policy: additive fields don't bump the version, breaking changes — including new penalty values — do. The doc's example is reproducible byte-for-byte, and a test at the assembled-daemon seam asserts the `GET /reports` document equals it exactly, so doc and implementation cannot drift.

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] Report-format doc published: envelope, record fields (including penalty), timestamp rules, example document
- [ ] Intent of each of the five penalty values defined; advisory clause ("the consumer decides whether and how to apply it") stated explicitly
- [ ] Evolution policy recorded: additive fields don't bump `version`; breaking changes, including new enum values, do
- [ ] The example document is authored so a driven daemon scenario reproduces it exactly (the seam's injected clock already mirrors the plan example's timestamps)
- [ ] A test at the assembled-daemon seam asserts the `GET /reports` document matches the doc's example byte-for-byte
- [ ] The plan's report-record and rules-validation sections updated to reference the contract doc
