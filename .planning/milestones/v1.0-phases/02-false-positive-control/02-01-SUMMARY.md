---
phase: 02-false-positive-control
plan: 01
status: complete
wave: 1
requirements: [SUP-01, SUP-02, SUP-03, SUP-04]
commits:
  - 79ddc02 feat(02-01): add doublestar/v4 dep and suppress package shell
  - aaf1ec2 feat(02-01): add D-12 suppression fields and D-11/D-13 stats counters
  - 1a2c9f5 test(02-01): add dirty fixture repo + criterion-4 variants
---

## Summary

Established the Phase 2 foundation: the `doublestar/v4` direct dependency, the
`internal/suppress` package shell, the `Finding` D-12 fields, the `scanner.Stats`
D-11/D-13 counters, and the dirty fixture repo plus its two criterion-4 variants.
This is the contract-defining wave — Plans 02–04 now implement against fixed
structs and fixtures instead of inventing them.

## What was built

- **Task 1** — Promoted `github.com/bmatcuk/doublestar/v4 v4.10.0` to a direct
  `require` in `go.mod`. Created `internal/suppress/doc.go` documenting the three
  suppression mechanisms and the load-bearing post-`g.Wait()` decoupling
  constraint (Phase 4 verification slots into the same pipeline position).
- **Task 2** — Added `Finding.Suppressed` (bool) and `Finding.SuppressionReason`
  (string), both `omitempty` so the OUT-02 JSON schema is byte-identical for
  unsuppressed findings. Added `Stats.PathsExcluded` (D-13) and
  `Stats.Suppressed map[string]int` (D-11), initialized to an empty map in
  `Scan`'s return. Added omitempty-marshal tests and a stats-counter test; the
  reflect raw-secret guard still passes.
- **Task 3** — Built `testdata/dirty/` (secret-bearing `src/app.go`, pruned
  `vendor/` + `node_modules/` + `app.min.js` + `package-lock.json`, a blanket
  `mimir:ignore` file, a scoped two-rule `mimir:ignore:aws-access-token` file,
  and a `.mimirignore` with a `**` glob + `!` negation), plus
  `testdata/dirty-moved/` (secret file relocated to `lib/app.go`) and
  `testdata/dirty-shifted/` (blank lines inserted above the secret line). Added
  `internal/suppress/fixtures_test.go` (sanity only — no scanner assertions).

## Key files

- created: `internal/suppress/doc.go`, `internal/suppress/fixtures_test.go`,
  `internal/finding/finding_suppress_test.go`,
  `internal/scanner/scanner_stats_test.go`,
  `testdata/dirty/**`, `testdata/dirty-moved/**`, `testdata/dirty-shifted/**`
- modified: `go.mod`, `go.sum`, `internal/finding/finding.go`,
  `internal/scanner/scanner.go`

## Deviations

- **`go mod tidy` skipped after `go get`.** The plan's Task 1 said to run
  `go get … && go mod tidy`, but `go mod tidy` strips `doublestar` from `go.mod`
  because no package imports it yet — which violates the Task 1 acceptance
  criterion ("doublestar is a *direct* require"). Resolved by adding the dep via
  `go get` and leaving it as a direct require; it becomes naturally tidy-stable
  once Plan 02-03's `pathmatch.go` imports it. `go build`/`go vet`/`go test` are
  all green, so the module graph is valid.
- Secrets reused verbatim from `testdata/fixtures/known-secrets.txt`; no
  fabricated credentials; no semgrep/hook artifacts added (per the
  executor-semgrep-fixture-trap memory).

## Self-Check: PASSED

- `go build ./...` exit 0; `go vet ./...` exit 0.
- `go test ./... -race` all packages ok (finding, scanner, suppress, output,
  config, cmd/mimir).
- `go.mod` lists `github.com/bmatcuk/doublestar/v4 v4.10.0` as a direct require.
- Plan verify command passed: `.mimirignore`, `vendor/`, `dirty-moved/lib/app.go`,
  and `dirty-shifted/src/app.go` all present.
