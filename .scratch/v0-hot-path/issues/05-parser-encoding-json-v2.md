# 05: Parser rewrite on encoding/json/v2

**What to build:** The nginx JSON parser decodes on `encoding/json/v2`
(stdlib in Go 1.27; no third-party codec) with a byte-identical behavior
contract: identical Events for identical lines, identical field-level
errors, identical drop accounting — operators notice only that the
analyzer keeps up better. The existing parser fixture tests are the
oracle for the rewrite.

**Blocked by:** None (can start immediately)

**Status:** resolved

- [x] Every existing parser fixture test passes unmodified (same
      Events, same invalid-field and malformed-line outcomes)
- [x] Unknown and reserved fields keep their handling (ignored; optional
      agent null means absent)
- [x] Drop accounting is unchanged: the same lines drop for the same
      reasons, and field-level errors keep their identity
- [x] Per-line allocation cost is cut substantially and recorded
      (B/op, allocs/op from the parser benchmark, before/after)
- [x] No new dependency in the module graph
- [x] Full suite green under the race detector

## Answer

Done. `internal/infra/parse/nginx/nginx.go` decodes on
`encoding/json/v2` (+ `encoding/json/jsontext`); go.mod/go.sum untouched
(stdlib only). `nginx_test.go` (the fixture oracle) is byte-identical;
all fixtures pass.

**How.** `json.Unmarshal` fills a `rawFields` struct whose `fieldValue`
members implement `json.UnmarshalerFrom`: JSON strings decode once at
capture (`Decoder.ReadToken().String()`); every other kind keeps its
exact raw bytes as a zero-copy view of the line (`Decoder.ReadValue()`;
buffered decode never copies or compacts the input —
`jsontext/pools.go` `getBufferedDecoder` resets onto the caller's
slice). Required-field validation order, `FieldError` identity (field +
message), drop accounting and the Event mapping are unchanged,
including the quirks: a bare `null` line fails on `"time"` as a missing
field (not a malformed line), `time` accepts strings/numbers with the
fraction truncated/padded to 9 digits, and `sent`/`status` accept only
unquoted JSON integers (`1e2`, `1.5` ⇒ "must be an integer").

**Contract traps found by characterization against the old decoder**
(before/after verified identical on a 19-line edge battery):

- `jsontext.AllowDuplicateNames(true)` — plain v2 *rejects* duplicate
  member names; the old map decoder resolved them last-wins
  (`{"time":"1","time":"2"}` parses with time=2).
- `jsontext.AllowInvalidUTF8(true)` — nginx escape=json passes raw
  non-UTF-8 bytes through unescaped; plain v2 drops such lines as
  malformed. They keep parsing, invalid bytes kept as U+FFFD (matching
  the historic decoder, incl. lone-surrogate escapes like `\ud800`).
- Name matching stays exact/case-sensitive ("Time" does not satisfy
  "time"), including `\u`-escaped member names.

Error *text* (amended after the code review of this branch): jsontext
first added position info to malformed-line errors (e.g.
`jsontext: invalid character '0' after object value (expecting ',' or
'}') after offset 9` vs the pre-rewrite `invalid character '0' after
object key:value pair`) and v2's semantic renderer randomizes
`cannot`/`unable to` once per process (Hyrum-proofing). The wrap point
now re-renders every decode failure byte-identically to the
pre-rewrite parser's (`legacyLineError` in `nginx.go`, mirroring
encoding/json's own v1-compat rendering: no `jsontext: ` prefix, no
JSON pointer or byte offset, v1 wording, type errors naming the old
decode target, and v1's whole-line syntax-before-type precedence so
`00` reports the trailing garbage like the old scanner).
`TestParseMalformedLineErrorText` pins the restored text. The error is
still a plain non-FieldError wrapped as `parse nginx json: %w`, so the
same lines drop for the same reason — story 26's letter holds.
Field-level error strings are byte-identical.

**Allocations** (`go test -run=^$ -bench=BenchmarkParse -benchmem
-count=10 ./internal/infra/parse/nginx/`, go1.27.0 linux/amd64,
Intel Core Ultra 9 185H; before = base commit 3adc43b, after = 1d290b4):

| shape | B/op before→after | allocs/op before→after | ns/op before→after |
|---|---|---|---|
| minimal | 696 → 411 (−41%) | 23 → 5 (−78%) | ~1940 → ~740 |
| full | 1544 → 446 (−71%) | 32 → 6 (−81%) | ~3150 → ~1100 |

The 5–6 remaining allocs are the decoded field strings (one per string
field: time/client/method/url/agent) plus the client address parse
(pprof on the after build: 77% `Token.String`, ~20% `Parse`).

**New tests** (`nginx_compat_test.go`, in repo table-test style;
characterized to pass on the pre-rewrite parser first, so they pin
behavior rather than new expectations): agent null = absent; duplicate
names last-wins (incl. agent value/null orderings); bare `null` line =
missing-field `FieldError` on "time"; invalid UTF-8 and lone-surrogate
agent values parse and keep U+FFFD. Full suite green under the race
detector (`make test`).
