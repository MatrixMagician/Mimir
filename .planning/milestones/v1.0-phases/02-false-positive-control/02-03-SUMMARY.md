---
phase: 02-false-positive-control
plan: 03
status: complete
wave: 3
requirements: [SUP-02, SUP-04]
---

## Summary

Delivered the path-exclusion vertical slice: a `.mimirignore` at the scan root
(`**` globs + `!negation`) plus shipped default-noisy globs prune paths during
the walk so they are never opened, with a config master toggle and a
`--no-default-excludes` flag. Excluded paths are counted (D-13), not enumerated.

## What was built

- **Task 1** — `internal/suppress/pathmatch.go`: `PathMatcher.Excluded(rel, isDir)`
  (doublestar, gitignore-style last-match-wins so `!negation` re-includes),
  `DefaultPathExcludes` (vendor/node_modules/dist/build/min/map/lockfiles),
  `NewPathMatcher(lines, useDefaults) (*PathMatcher, error)` validating every
  glob with `doublestar.ValidatePattern` (malformed → error), and
  `LoadMimirIgnore`. Directory globs (`vendor/**`) also prune the dir node so the
  subtree is `SkipDir`-skipped. Unit tests cover `**`, negation ordering,
  defaults on/off, backslash normalization, malformed-reject, and nil-safety.
- **Task 2** — Config master toggle `use_default_allowlists` (`extendSection`,
  pointer = default-on) normalized to `Config.UseDefaultExcludes` and carried
  through the extend merge. Scanner walk-prune gate in the WalkDir callback
  (dirs `SkipDir`, files skipped; both counted into `Stats.PathsExcluded`,
  never opened). `--no-default-excludes` flag + `.mimirignore` loading +
  matcher construction in `runScan` (malformed pattern exits 2, fail loud).
  CLI tests: TestDefaultExcludes (criterion 2), TestMimirignoreNegation,
  TestDefaultsToggleOff, TestMalformedMimirignoreFailsLoud; scanner
  TestWalkPruneCount asserts the excluded count.

## Key files

- created: `internal/suppress/pathmatch.go`, `internal/suppress/pathmatch_test.go`
- modified: `internal/scanner/scanner.go` (Matcher field, walk-prune, PathsExcluded),
  `internal/config/config.go` (toggle), `cmd/mimir/scan.go` (flag + matcher),
  `cmd/mimir/scan_test.go` (4 CLI tests), `internal/scanner/scanner_stats_test.go`
  (prune-count test), `internal/output/output_test.go` (WriteHuman 6-arg fix),
  `go.mod`/`go.sum` (doublestar/v4 promoted to direct dep)

## Deviations

- `go.mod`: doublestar/v4 was a `// indirect` after 02-01 (nothing imported it);
  `go mod tidy` promoted it to a direct require here once `pathmatch.go` imports
  it — satisfying the 02-01 acceptance criterion organically.
- Fixed an 02-02 regression: `output_test.go` still called `WriteHuman` with the
  pre-02-02 5-arg signature, breaking `go test ./internal/output/`. Added the
  trailing `verbose=false` arg to restore a green build (committed in 98c1ce7).

## Self-Check: PASSED

- `go build ./...`, `go vet ./...` exit 0.
- `go test ./... -race` all packages ok.
- 02-03 CLI tests + scanner prune-count test pass under `-race`.
- doublestar/v4 v4.10.0 is a direct require; no `path/filepath.Match` used.
