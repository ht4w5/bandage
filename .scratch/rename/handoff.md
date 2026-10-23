# Handoff: product trees + the webmedkit rename

For a session whose context still holds the old layout. Everything here is
current as of `0b3f9c1` and describes what is on disk. The checkout directory
is deliberately still `/home/user2/Devel/bandage` — the path was not renamed.

## What happened, in two commits

1. `d796c50` — `internal/domain/` moved to `internal/bandage/` (the package was
   already `package bandage`, so this was paths only, aliases dropped).
   **Superseded by the next commit** — do not look for `internal/bandage/`.
2. `0b3f9c1` — the code split into product trees, and the project, module and
   GitHub repo renamed `bandage` → `webmedkit`.

## Old path → new path

| You remember | It is now |
|---|---|
| `internal/domain/` (or `internal/bandage/`) | `bandage/internal/domain/` |
| `internal/domain/{filter,enrichment,track,evaluation,report}` | `bandage/internal/domain/…` (same subpackages) |
| `internal/app/` | `bandage/internal/app/` |
| `internal/infra/{cache/memory,httpapi,ingest/syslog,parse/nginx,persistence/sqlite}` | `bandage/internal/infra/…` |
| `internal/bench/` | `bandage/internal/bench/` |
| `internal/splint/` | split in two: `splint/internal/domain/` and `splint/internal/app/` (below) |
| `internal/firewall/{nft,firewalltest}` | `splint/internal/firewall/…` |
| `internal/identity/` | `internal/identity/` — unchanged, the one shared tier |
| `cmd/bandage/` | `bandage/cmd/bandage/` |
| `cmd/splint/` | `splint/cmd/splint/` |
| module `github.com/HT4w5/bandage` | `github.com/HT4w5/webmedkit` |

## The splint split (the only non-mechanical change)

`internal/splint` was one package (engine + wire model). It is now two:

- `splint/internal/domain/` (`package domain`) — **what splint knows**: the
  version-0 report document (`wire.go`: Document, Report, Tracker, Sample,
  Penalty, PenaltyAction, ParseDocument), the exclusion policy (`policy.go`:
  Policy, NewPolicy), and ban-rule compilation (`compile.go`: Compile, Skip).
  It imports the seam `splint/internal/firewall` for `BanRule`/`Stance`.
- `splint/internal/app/` (`package app`) — **what splint does**: the update
  cycle (`updater.go`: Updater, New, Update, DryRun, Run, ClampInterval,
  DefaultInterval) and the mTLS fetcher (`fetch.go`). The whole test suite
  (`cycle_test`, `points_test`, `mtls_test`, `fetch_test`) lives here; it drives
  the cycle against `firewalltest.Stub`s and now references the model as
  `domain.X`.

## Naming to unlearn

- The analyzer's core package is `package domain`, **not** `package bandage`:
  qualifiers are `domain.Event`, `domain.Report`, `domain.PenaltyActions`, …
  (a sed of `bandage.X` → `domain.X` was applied repo-wide).
- Both products name their core `domain` and their runtime layer `app`; the
  adapters keep their seam names (`bandage/internal/infra`,
  `splint/internal/firewall`). In imports and prose, qualify by product.
- splint's engine API moved package: `splint.New(...)` → `app.New(...)`, but
  `splint.NewPolicy` → `domain.NewPolicy`.
- The **project** is webmedkit; the **two binaries keep their names** —
  `bandage` (the analyzer) and `splint` (the enforcer); webmedkit is the kit
  they ship in. Tool-scoped names are unchanged and still say "bandage":
  `bandage.yml`, `rules.yml`, `/var/lib/bandage/reports.db`,
  `identity.For("bandage")`, `bin/bandage`, "the bandage report document".
  Only the module path, repo name and doc titles say webmedkit.

## Walls that are now compiler-enforced

Go's `internal` rule does the work the ADR 0011 wall used to only promise:
`bandage/internal/…` is importable only from `bandage/…`, `splint/internal/…`
only from `splint/…`. Cross-product imports do not build. `internal/identity`
is importable by both, and both binaries stamp their version from it.

The two dependency lints moved with the code and were re-scoped:

- `bandage/internal/domain/deps_test.go` — the core imports the stdlib and the
  core only (`domainPath` is `…/webmedkit/bandage/internal/domain`).
- `splint/internal/firewall/deps_test.go` — `app` and `domain` are "core",
  `firewall/{nft,firewalltest}` are "driver": core may import the seam root
  only, drivers never import core, and neither imports the other.

## Also updated (so do not "fix" these)

- `Makefile`: `MODULE := github.com/HT4w5/webmedkit`, `CMD := ./bandage/cmd/bandage`,
  `CMD_SPLINT := ./splint/cmd/splint`.
- `PLAN.md` §3 layout block redrawn for the product trees (with a note on the
  walls); `README.md`, `GLOSSARY.md`, `AGENTS.md` titled `# webmedkit`.
- Test fixtures walk to the repo root from their new depth:
  `docs/reports.md` and `configs/nginx/bandage_log.conf` are reached via
  `../../../…` (and `../../../../../…` from `bandage/internal/infra/parse/nginx`).
  `docs/reports.md`'s tripwire citation is now
  `bandage/internal/app/reportdoc_test.go`.
- `.scratch/` tickets and specs were re-pathed. The raw pprof/bench output
  under `.scratch/v0-benchmarks/{profiles,baseline}` was **left as captured**
  (old package paths and all); `.scratch/v0-hot-path/issues/07` regenerates it.

## Verify before trusting the layout

```sh
go build ./... && go vet ./... && go test -race -count=1 ./...   # green
make build && ./bin/bandage --version && ./bin/splint --version
```

Repo: `git@github.com:ht4w5/webmedkit.git` (renamed from `ht4w5/bandage`; the
old GitHub URL redirects). History is intact — git recorded the moves as
renames in both commits.
