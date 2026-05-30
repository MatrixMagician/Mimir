---
phase: 03-full-source-coverage-git-history-staged-pre-commit
plan: 02
subsystem: scanning
tags: [git, staged, pre-commit, secret-scanning, benchmark, memory, cobra]

# Dependency graph
requires:
  - phase: 03-01
    provides: internal/gitscan package (parsePatch loop, startGit, dedupByFingerprint, attachCommitMeta empty-header guard), --git flag + source-selection branch in runScan, D-08 omitempty commit fields
  - phase: 01-foundation
    provides: detection engine (engine.ScanLine), Finding model + redact-at-boundary, exit-code contract (IFACE-02)
  - phase: 02-false-positive-control
    provides: inline-ignore suppression (suppress.InlineSuppresses/InlineReason)
provides:
  - "internal/gitscan.ScanStaged: streams `git diff --staged` through the shared parsePatch loop; staged findings carry no commit metadata (OUT-02 stable)"
  - "mimir scan --staged source-selection branch + --git/--staged mutual-exclusion (exit 2)"
  - "internal/gitscan/bench_test.go: BenchmarkHistoryMem (criterion-2 bounded-memory gate) + BenchmarkStaged (hook sub-second reference)"
affects: [03-03-precommit-hook, phase-04-verification]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "ScanStaged reuses parsePatch unchanged (zero duplicated OpAdd/inline-ignore logic) — only the git command and error wording differ from ScanHistory"
    - "Benchmark gate as a regression tripwire: fixed byte ceiling independent of commit count, FATALs if the large-N heap delta scales (would mean buffered, not streamed)"

key-files:
  created:
    - internal/gitscan/bench_test.go
  modified:
    - internal/gitscan/command.go
    - internal/gitscan/gitscan.go
    - internal/gitscan/gitscan_test.go
    - cmd/mimir/scan.go
    - cmd/mimir/scan_test.go

key-decisions:
  - "Mutual exclusion (Pitfall 6 / RESEARCH A2): --git + --staged exits 2 with a 'mutually exclusive' message, consistent with the other fail-loud os.Exit(2) calls"
  - "Benchmark ceiling 16 MB / 5 s derived from a measured baseline (A4): 50-commit ~0.79 MB vs 500-commit ~2.0 MB heap/op — 10x history yields only ~2.5x heap, proving streaming"
  - "ScanStaged reuses dedupByFingerprint (a no-op for a single diff) rather than special-casing it — keeps the two source functions structurally identical"

patterns-established:
  - "Source-function template: startGit(<args>) → parsePatch → fail-loud cmd.Wait() → dedup → deterministic File→Line→Column sort"
  - "TB-typed test helpers (newTestEngine/newStagedFixture/initRepo) so benchmarks and tests share fixture construction"

requirements-completed: [SCAN-04]

# Metrics
duration: 12min
completed: 2026-05-30
---

# Phase 3 Plan 02: Staged-Changes Scan + Criterion-2 Benchmark Gate Summary

**`mimir scan --staged` streams the `git diff --staged` patch through Plan 01's shared parse loop to find secrets in what is about to be committed — honoring inline `// mimir:ignore`, attaching no commit metadata (OUT-02 stable), mutually exclusive with `--git` (exit 2), and backed by a criterion-2 benchmark gate proving history-scan memory is streaming-bounded.**

## Performance

- **Duration:** ~12 min
- **Started:** 2026-05-30
- **Completed:** 2026-05-30
- **Tasks:** 3 (Tasks 1–2 TDD)
- **Files modified:** 6 (1 created, 5 modified)

## Accomplishments
- `ScanStaged(ctx, engine, repoRoot, showSuppressed)` added to `internal/gitscan/gitscan.go`: spawns `git diff -U0 --no-ext-diff --no-color --staged` (arg slice, never `sh -c` — T-03-06) and runs the **exact same** `parsePatch` loop as `ScanHistory`. No OpAdd/inline-ignore logic is duplicated — `InlineSuppresses` is called only from `parse.go`.
- Staged findings carry **no commit metadata**: `git diff --staged` has an empty `PatchHeader`, so `attachCommitMeta`'s SHA guard (Pitfall 5, inherited from Plan 01) leaves the omitempty fields unset → staged JSON has no `commit_sha` key (OUT-02 byte-identical). Asserted both at unit level (`CommitSHA` empty) and end-to-end (`TestStagedModeNoCommitJSON`).
- Inline `// mimir:ignore` is honored on staged lines exactly as in the working-tree scanner (criterion 3, reuses SUP-01) — `TestStagedInlineIgnore` / `TestStagedInlineIgnoreCmd` both assert zero findings / exit 0.
- `--staged` wired into `runScan` via a 3-way `switch` (gitMode / stagedMode / default); the downstream baseline/output/exit-code pipeline is untouched, so a staged secret flips exit 1 automatically (IFACE-02) — which is what lets the Plan 03 hook block a commit.
- `--git` + `--staged` are mutually exclusive: passing both prints `error: --git and --staged are mutually exclusive` to stderr and exits 2 (Pitfall 6 / RESEARCH A2).
- Criterion-2 benchmark gate (`BenchmarkHistoryMem`): runs `ScanHistory` over generated 50- and 500-commit histories and FATALs if the large-N heap delta exceeds a fixed 16 MB ceiling or wall time exceeds 5 s. The fixed byte ceiling (independent of commit count) is what makes it a streaming-regression tripwire. `BenchmarkStaged` reports ~0.83 ms/op as the hook's sub-second reference (IFACE-03 criterion 4).

## Task Commits

1. **Task 1: ScanStaged staged-diff source (TDD: tests + impl)** — `b9bbcc2` (feat)
2. **Task 2: wire --staged + --git/--staged mutual exclusion** — `eebe2b1` (feat)
3. **Task 3: criterion-2 benchmark gate** — `dacc16c` (test)

## Files Created/Modified
- `internal/gitscan/command.go` — `stagedArgs` builder (`diff -U0 --no-ext-diff --no-color --staged`, arg slice; T-03-06).
- `internal/gitscan/gitscan.go` — `ScanStaged` orchestration mirroring `ScanHistory` (shared `parsePatch`, fail-loud `cmd.Wait()`, dedup, deterministic sort).
- `internal/gitscan/gitscan_test.go` — `newStagedFixture` helper; `TestStagedSecret` (empty CommitSHA), `TestStagedInlineIgnore`, `TestStagedNonRepoFailsLoud`; helper signatures widened to `testing.TB`.
- `internal/gitscan/bench_test.go` (new) — `BenchmarkHistoryMem` (gate), `BenchmarkStaged`, `buildLargeHistory`, `heapDelta`; measured-baseline comment.
- `cmd/mimir/scan.go` — `--staged` flag, mutual-exclusion guard (`os.Exit(2)`), 3-way source `switch`; exit-code block unchanged.
- `cmd/mimir/scan_test.go` — `newStagedFixtureRepo`; `TestStagedModeFindsSecret`, `TestStagedModeNoCommitJSON`, `TestStagedInlineIgnoreCmd`, `TestGitStagedMutuallyExclusive`.

## Decisions Made
- **Mutual exclusion over precedence** (Pitfall 6 / RESEARCH A2): both source flags select different sources, so passing both is misuse → exit 2, matching IFACE-02's exit-2-on-misuse convention and the other fail-loud paths in `runScan`.
- **Measured benchmark ceilings (A4):** thresholds set from a first measured run, not guessed. 50-commit heap ~0.79 MB/op vs 500-commit ~2.0 MB/op — a 10x history increase yielded only ~2.5x heap (sub-linear), confirming the `git log -p` stream is consumed lazily and not buffered. Ceiling = 16 MB (~8x the measured large-N delta + headroom); wall ceiling = 5 s (tolerant of loaded CI).
- **Reuse dedup unchanged:** `ScanStaged` calls `dedupByFingerprint` even though a single diff rarely has cross-commit duplicates — it is a harmless no-op for distinct secrets and keeps the two source functions structurally identical (easier to maintain).

## Deviations from Plan
None — plan executed exactly as written.

Threat register satisfied: T-03-06 (staged spawn uses `exec.CommandContext` arg slice, no `sh -c` — verified by grep), T-03-07 (findings via `engine.ScanLine`→`finding.New` redaction; empty PatchHeader → no commit metadata leaks), T-03-08 (RE2 linear-time engine reused), T-03-09 (`BenchmarkHistoryMem` asserts heap delta does not scale with history length).

## Issues Encountered
None. (Initial bench-comment baseline numbers were placeholders; corrected to the actual measured figures after the first run, per A4 — measure, do not guess.)

## User Setup Required
None for the build. **Runtime note:** `git >= 2.x` must be on PATH for `--staged` mode (same documented prerequisite as `--git`; absence fails loud with exit 2).

## Next Phase Readiness
- Plan 03 (pre-commit hook) can invoke `mimir scan --staged` directly — it exits 1 on a staged secret (blocking the commit) and 0 when clean, with no commit metadata in output.
- `BenchmarkStaged` (~0.83 ms/op) is the reference for IFACE-03 criterion 4's sub-second hook budget.

## Verification
- `go test -race ./...` — all packages green.
- `go build ./...` — succeeds; `go vet ./...` — clean.
- `go test ./internal/gitscan/ -run 'TestStagedSecret|TestStagedInlineIgnore' -count=1` — pass.
- `go test ./cmd/mimir/ -run 'TestStagedMode|TestStagedInlineIgnoreCmd|TestGitStagedMutuallyExclusive' -count=1` — pass.
- `go test -bench 'BenchmarkHistoryMem|BenchmarkStaged' -benchmem -run '^$' ./internal/gitscan/` — gate passes (large-N heap ~2.0 MB < 16 MB ceiling; staged ~0.83 ms/op).
- OUT-02: `TestStagedModeNoCommitJSON` confirms staged JSON contains no `commit_sha` key.

---
*Phase: 03-full-source-coverage-git-history-staged-pre-commit*
*Completed: 2026-05-30*
