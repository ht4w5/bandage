# Reports carry an advisory penalty

Every report carries a **Penalty** — the enforcement stance its rule's
report action recommends for the target: the closed vocabulary `drop`,
`reject`, `limit-pkt-rate`, `limit-bandwidth`, `limit-req-rate`, the
limit penalties carrying a `rate` in the unit their name states
(packets, response-payload bytes, or requests per second, aggregated
over the target). The penalty is required on the report action and
travels with the report into the canonical report document.

The penalty is advice: how a report consumer applies it — or whether to
at all — is deliberately out of bandage's control, so bandage defines
the vocabulary's intent (drop discards the target's traffic silently,
reject refuses it with an error signal, limits throttle it to `rate`)
but prescribes no mechanics, and validates the penalty for
well-formedness only — never against the rule's tracker or reason. This
keeps ADR 0004 unchanged: bandage produces reports and never ban rules;
the penalty is metadata that downstream tooling may fold into its ban
rules.

Considered: one `limit` value with a unit-carrying rate parameter
(rejected: the dimension hid in the parameter, and "rate" collided with
the rate tracker's request-count meaning); tying penalties to reasons or
tracker kinds at load time (rejected: reasons are shared across rules,
and coherence is the consumer's judgment). Recorded because the closed
five-value vocabulary looks over-specified until you see the
alternatives.
