---
phase: 03-full-source-coverage-git-history-staged-pre-commit
plan: 01
subsystem: scanning
tags: [git, history, go-gitdiff, streaming, secret-scanning, cobra]

# Dependency graph
requires:
  - phase: 01-foundation
    provides: detection engine (engine.ScanLine), Finding model + redact-at-boundary, computeFingerprint, scan.go/runScan, exit-code contract (IFACE-02)
  - phase: 02-false-positive-control
    provides: inline-ignore suppression (suppress.InlineSuppresses/InlineReason), omitempty schema-extension discipline, baseline OR-match
provides:
  - "internal/gitscan package: ScanHistory streams git log -p through go-gitdiff into engine.ScanLine"
  - "D-08 commit-provenance fields (CommitSHA/CommitAuthor/CommitDate, omitempty) on Finding"
  - "mimir scan --git source-selection branch in runScan"
  - "D-10 short-SHA human output for history findings; verbose full author/date"
  - "fingerprint-based history dedup keeping earliest-introducing commit (D-09)"
affects: [03-02-staged-scan, 03-03-precommit-hook, phase-04-verification]

# Tech tracking
tech-stack:
  added: ["github.com/gitleaks/go-gitdiff v0.9.1"]
  patterns:
    - "Shell out to system git + stream StdoutPipe through gitdiff.Parse channel (bounded memory)"
    - "Per-OpAdd-line iteration into existing engine.ScanLine (zero engine changes)"
    - "Commit metadata as omitempty Finding fields, never in fingerprint (cross-mode dedup safe)"

key-files:
  created:
    - internal/gitscan/command.go
    - internal/gitscan/parse.go
    - internal/gitscan/gitscan.go
    - internal/gitscan/gitscan_test.go
  modified:
    - internal/finding/finding.go
    - internal/finding/finding_test.go
    - internal/output/human.go
    - cmd/mimir/scan.go
    - cmd/mimir/scan_test.go

key-decisions:
  - "ScanHistory dedups by content fingerprint and keeps the earliest (oldest CommitDate) commit's metadata per RESEARCH A3/D-10"
  - "command.go fails loud via exec.LookPath('git') and non-zero cmd.Wait() so --git on a non-repo / missing git exits 2 (Pitfall 4)"
  - "Only --git registered this plan; --staged is Plan 02's to add (avoids a dead flag)"

patterns-established:
  - "git source pattern: exec.CommandContext arg slice (no sh -c), StdoutPipe, streamed gitdiff.Parse, deferred cmd.Wait()"
  - "Inline-ignore block copied verbatim from scanner.scanFile so the diff-added line honors // mimir:ignore"

requirements-completed: [SCAN-03]

# Metrics
duration: 18min
completed: 2026-05-30
---

# Phase 3 Plan 01: Git History Scanning Summary

**`mimir scan --git` streams current-branch `git log -p` through go-gitdiff into the existing detection engine, finding secrets added in past commits (incl. added-then-deleted) with commit provenance, fingerprint dedup, and a short-SHA one-liner — OUT-02 byte-identical for non-history scans.**

## Performance

- **Duration:** ~18 min
- **Started:** 2026-05-30
- **Completed:** 2026-05-30
- **Tasks:** 3 (all TDD)
- **Files modified:** 11 (4 created, 7 modified incl. go.mod/go.sum)

## Accomplishments
- New `internal/gitscan` package: `ScanHistory(ctx, engine, repoRoot, showSuppressed)` shells out to `git log -p -U0 --full-history --no-color` (D-03, no `--all`), streams the patch through `gitdiff.Parse` (bounded memory), and scans each `OpAdd` line via the unchanged `engine.ScanLine`.
- D-08 commit-provenance fields (`CommitSHA`/`CommitAuthor`/`CommitDate`, omitempty) added to `Finding`; populated only when a real commit SHA exists, so working-tree/staged JSON stays byte-identical (OUT-02). Fingerprint untouched (D-09) — proven by a test that a CommitSHA-set finding hashes identically.
- History findings dedup by content fingerprint, collapsing the same secret across commits to one entry and keeping the earliest-introducing commit's metadata.
- `--git` wired into `runScan` as a source selector; the entire downstream pipeline (baseline, output, exit code) is reused unchanged. D-10 short-SHA (`file:line:col @ abc1234 …`) appended in human output; full author/date under `--verbose`.
- Fail-loud on missing `git` or a non-git directory → exit 2 (Pitfall 4), never a silent clean exit.

## Task Commits

Each task was committed atomically (TDD: RED test + GREEN impl folded per task):

1. **Task 1: D-08 Finding fields + failing history fixture tests** - `30b57dc` (test)
2. **Task 2: internal/gitscan history source** - `4c7e13d` (feat)
3. **Task 3: wire --git into runScan + D-10 short-SHA output** - `95a9469` (feat)

_Note: Task 1 added D-08 fields with passing finding tests (immediate GREEN) plus the gitscan tests written RED; Tasks 2–3 turned the gitscan/cmd tests GREEN._

## Files Created/Modified
- `internal/gitscan/command.go` - `historyArgs` builder + `startGit` (LookPath guard, exec.CommandContext, StdoutPipe)
- `internal/gitscan/parse.go` - streaming gitdiff.Parse loop, OpAdd → ScanLine, verbatim inline-ignore block, `attachCommitMeta` under PatchHeader.SHA guard
- `internal/gitscan/gitscan.go` - `ScanHistory` orchestration, `dedupByFingerprint` (earliest-commit retention), deterministic sort, fail-loud
- `internal/gitscan/gitscan_test.go` - fixture-repo helpers + TestHistoryDeletedSecret/Dedup/NonRepoFailsLoud
- `internal/finding/finding.go` - D-08 omitempty commit fields (computeFingerprint/New unchanged)
- `internal/finding/finding_test.go` - TestCommitMetaOmitempty + D-09 fingerprint-invariance assertion
- `internal/output/human.go` - short-SHA history line (D-10) + verbose commit author/date + `shortSHA` helper
- `cmd/mimir/scan.go` - `--git` flag + source-selection branch to `gitscan.ScanHistory`
- `cmd/mimir/scan_test.go` - TestGitModeFindsHistorySecret (exit 1 + ` @ ` marker) + TestGitModeNonRepoFailsLoud (exit 2)

## Decisions Made
- **Dedup attribution:** earliest (oldest RFC3339 `CommitDate`) commit's metadata is retained on the surviving finding, attributing the leak to where it first appeared (RESEARCH A3/D-10).
- **Flag scope:** only `--git` registered here; `--staged` and the mutually-exclusive precedence check are deferred to Plan 02 so this plan ships no dead flag. The source-selection branch is a simple `if gitMode {…} else {…}` that Plan 02 extends.
- **`--full-history` kept** (RESEARCH A1) for rename following; `--all` omitted per D-03.

## Deviations from Plan
None - plan executed exactly as written. (Threat register T-03-01..T-03-SC all satisfied: exec arg-slice no `sh -c`, RE2 engine reused, redact-at-boundary inherited via finding.New, deferred cmd.Wait() cleanup, commit SHA excluded from fingerprint, `go mod verify` passed.)

## Issues Encountered
None.

## User Setup Required
None for the build. **Runtime note:** `git >= 2.x` must be on PATH for `--git` mode (documented prerequisite; absence fails loud with exit 2). No code/config setup required.

## Next Phase Readiness
- `internal/gitscan` is ready for Plan 02 to add `ScanStaged` (same command/parse/return shape) and the `--staged` flag + mutual-exclusion branch.
- `attachCommitMeta`'s empty-PatchHeader guard (Pitfall 5) already makes staged findings carry no commit metadata — Plan 02 inherits OUT-02 stability for free.
- Plan 03 (pre-commit hook) can rely on the established exec arg-slice + fail-loud patterns.

## Verification
- `go test -race ./...` — all packages green.
- `go build ./...` — succeeds.
- `go mod verify` — all modules verified (go-gitdiff supply-chain gate).
- `go vet ./...` — clean.
- OUT-02: working-tree `scan --format json testdata/fixtures/` contains zero `commit_sha` keys.

## Self-Check: PASSED

All created files present (internal/gitscan/{command,parse,gitscan,gitscan_test}.go, 03-01-SUMMARY.md) and all task commits exist (30b57dc, 4c7e13d, 95a9469, 59eb4a9).

---
*Phase: 03-full-source-coverage-git-history-staged-pre-commit*
*Completed: 2026-05-30*
