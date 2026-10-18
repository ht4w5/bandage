# 05: Parser rewrite on encoding/json/v2

**What to build:** The nginx JSON parser decodes on `encoding/json/v2`
(stdlib in Go 1.27; no third-party codec) with a byte-identical behavior
contract: identical Events for identical lines, identical field-level
errors, identical drop accounting — operators notice only that the
analyzer keeps up better. The existing parser fixture tests are the
oracle for the rewrite.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] Every existing parser fixture test passes unmodified (same
      Events, same invalid-field and malformed-line outcomes)
- [ ] Unknown and reserved fields keep their handling (ignored; optional
      agent null means absent)
- [ ] Drop accounting is unchanged: the same lines drop for the same
      reasons, and field-level errors keep their identity
- [ ] Per-line allocation cost is cut substantially and recorded
      (B/op, allocs/op from the parser benchmark, before/after)
- [ ] No new dependency in the module graph
- [ ] Full suite green under the race detector
