# The report document

`GET /reports` serves the canonical, versioned **report document**: the
contract a report consumer integrates against instead of reverse-engineering
the code. This document defines version 0 — the envelope, every record
field including the penalty, the timestamp rules, the canonical
serialization, and the evolution policy. Its example is reproduced
byte-for-byte by the daemon and pinned by a test
(`internal/app/reportdoc_test.go`), so this contract and the
implementation cannot drift.

## Envelope

```text
{ "version": …, "generated_at": …, "reports": [ … ] }
```

| field | type | meaning |
|---|---|---|
| `version` | number | format version of the document; `0` |
| `generated_at` | string | when the document was generated, RFC 3339 UTC |
| `reports` | array | live report records (below), possibly empty |

The reports are ordered by `created_at` descending, then `rule` and
`target` ascending. Expired reports are never served. The `?rule=` and
`?target=` query parameters return a subset under the same ordering; they
do not change the document's shape.

## Report record

One record per (rule, target). `penalty` is the last key of a record, so
future additive fields append after it.

| field | type | meaning |
|---|---|---|
| `rule` | string | the rule ID that triggered (unique within its chain) |
| `chain` | string | the chain that owns the rule |
| `reason` | string | the machine-readable trigger code (a slug), the report's downstream identity |
| `target` | string | the aggregated source prefix the report is about, e.g. `203.0.113.7/32` |
| `created_at` | string | when the record was first written, RFC 3339 UTC |
| `updated_at` | string | when the record was last written; frozen while the report is alive ([ADR 0008](adr/0008-trigger-semantics-one-live-report.md)) |
| `expires_at` | string | when the report dies: `updated_at` plus the rule's `ttl` |
| `tracker` | object | the tracker reading that justified the report (below) |
| `sample` | object | the most recent event that created the report (below) |
| `penalty` | object | the advisory enforcement stance (below); present on every canonical record |

The `tracker` reading:

| field | type | meaning |
|---|---|---|
| `track` | string | tracker kind: `rate`, `bandwidth`, or `replay` |
| `value` | number | the accumulated quantity that overflowed `volume` (requests, response-payload bytes, or download equivalents — the tracker kind's quantity) |
| `leak` | number | the per-second decay applied to `value` |
| `volume` | number | the overflow threshold `value` exceeded |

The `sample`:

| field | type | meaning |
|---|---|---|
| `time` | string | the event's access-log timestamp, RFC 3339 UTC |
| `path` | string | the request path |
| `agent` | string | the user agent; empty when the log line carried none |
| `status` | number | the response status |
| `sent` | number | response payload bytes sent |
| `size` | number | the estimated total size of `path` in bytes; `0` when unknown |

### Timestamps

Every timestamp in the document is an RFC 3339 UTC string (a `Z`
suffix), at second precision: sub-second components are truncated, not
rounded. `generated_at` is the request time; `created_at`, `updated_at`
and `expires_at` are wall-clock write times.

## Penalty

The penalty is the enforcement stance the report's rule recommends for
its `target` ([ADR 0010](adr/0010-reports-carry-an-advisory-penalty.md)):

```text
"penalty": { "action": "limit-bandwidth", "rate": 1000000 }
```

| field | type | meaning |
|---|---|---|
| `action` | string | one of the five values below; closed at version 0 |
| `rate` | number | integer ≥ 1, present exactly when `action` is a `limit-*` |

The intent of each action:

| `action` | recommends |
|---|---|
| `drop` | discard the Target's traffic silently (no `rate`) |
| `reject` | refuse the Target's traffic with an error signal (no `rate`) |
| `limit-pkt-rate` | throttle the Target to `rate` packets per second |
| `limit-bandwidth` | throttle the Target to `rate` response-payload bytes per second — the bytes the sample's `sent` counts |
| `limit-req-rate` | throttle the Target to `rate` requests per second |

Every limit is an aggregate over the report's `target`: the number governs
the whole prefix, not each host inside it. The units are the intent, not
mechanics — `limit-pkt-rate` counts packets at whatever enforcement layer
the consumer applies.

### The penalty is advice

Applying the penalty is the consumer's decision. Bandage advises and
never enforces: it does not drop, refuse, or throttle anything itself,
and it validates the penalty for well-formedness only — never against the
rule's tracker or reason. A consumer may apply the penalty as stated, as
part of a stricter policy, or not at all.

The penalty is written with its report and freezes while the report is
alive ([ADR 0008](adr/0008-trigger-semantics-one-live-report.md)), so
the stance always matches the sample that justified it. A replacement
report — after deletion or expiry — carries the penalty of the rules
loaded at its write time.

## Evolution policy

The version stays `0` across additive changes: new optional fields (at
the record's end or inside its objects) do not bump `version`, so a
consumer must ignore unknown fields. Breaking changes do bump it —
including new `penalty.action` values: the enum is closed per version, so
a consumer's switch over the five values is total for version 0.

Records written before the penalty existed lack the `penalty` key; they
are pre-release and outside this contract.

## Canonical serialization

A `GET /reports` response is the document as JSON with two-space
indentation and keys in the order of the tables above, terminated by
exactly one newline. Strings are HTML-escaped as Go's `encoding/json`
does by default: `<`, `>` and `&` appear as the escapes
`\u003c`, `\u003e` and `\u0026`. The example below is exactly what `GET /reports`
returns (one trailing newline included), and the test compares the bytes.

## Example

The canonical example, from a driven run of the idiomatic pairing — a
bandwidth tracker recommending `limit-bandwidth` and its rate, over a
client that downloaded two 6000-byte files within one leak second:

```json
{
  "version": 0,
  "generated_at": "2025-10-17T18:00:00Z",
  "reports": [
    {
      "rule": "sustained-egress",
      "chain": "download-abuse",
      "reason": "egress-overflow",
      "target": "203.0.113.7/32",
      "created_at": "2025-10-17T18:00:00Z",
      "updated_at": "2025-10-17T18:00:00Z",
      "expires_at": "2025-10-18T18:00:00Z",
      "tracker": {
        "track": "bandwidth",
        "value": 11000,
        "leak": 1000,
        "volume": 10000
      },
      "sample": {
        "time": "2024-12-16T10:45:35Z",
        "path": "/releases/24.04.iso",
        "agent": "Wget/1.21",
        "status": 200,
        "sent": 6000,
        "size": 0
      },
      "penalty": {
        "action": "limit-bandwidth",
        "rate": 1000000
      }
    }
  ]
}
```

The first fenced `json` block of this document is the canonical example;
the test extracts it and compares it byte for byte with the `GET /reports`
response of that scenario (the response carries one trailing newline the
fence does not).
