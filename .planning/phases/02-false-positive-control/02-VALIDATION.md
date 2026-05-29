---
phase: 2
slug: false-positive-control
status: ready
nyquist_compliant: true
wave_0_complete: false
created: 2026-05-29
---

# Phase 2 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | go test (stdlib + testify v1.11.1 require/assert) |
| **Config file** | none — `go.mod` defines module; tests colocated `*_test.go` |
| **Quick run command** | `go test ./internal/suppress/... -race` (+ touched package) |
| **Full suite command** | `go test -race ./...` |
| **Estimated runtime** | ~15 seconds |

*CLI / exit-code tests live in `cmd/mimir/scan_test.go` and run the COMPILED binary via the existing `TestMain` + `runMimir` os/exec harness — exit codes cannot be unit-tested in-process because `runScan` calls `os.Exit`. The `finding_test.go` reflect raw-secret guard must keep passing after the two new omitempty fields.*

---

## Sampling Rate

- **After every task commit:** `go test ./<changed-package>/... -race`
- **After every plan wave:** `go test -race ./...`
- **Before `/gsd-verify-work`:** Full suite green AND `go vet ./...` / golangci-lint (gosec) clean
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 02-01-T1 | 01 | 1 | SUP-01..04 | T-02-SC | doublestar pinned to verified v4.10.0; package shell only | build | `go build ./... && grep -q 'doublestar/v4 v4.10.0' go.mod` | ❌ Wave 0 (doc.go) | ⬜ pending |
| 02-01-T2 | 01 | 1 | SUP-03 (schema) | T-02-01 | omitempty fields carry no secret; reflect guard intact | unit | `go test ./internal/finding/... ./internal/scanner/... -race` | ✅ (extend) | ⬜ pending |
| 02-01-T3 | 01 | 1 | SUP-01..04 (fixtures) | T-02-02 | fixtures reuse fake Phase-1 secrets only | unit | `go test ./internal/suppress/... -race` | ❌ Wave 0 (fixtures + test) | ⬜ pending |
| 02-02-T1 | 02 | 2 | SUP-01 | T-02-03 | scoped vs blanket; no over-suppression (Pitfall 3) | unit | `go test ./internal/suppress/ -run TestInline -race` | ❌ Wave 0 (inline_test.go) | ⬜ pending |
| 02-02-T2 | 02 | 2 | SUP-01 | T-02-04,T-02-05,T-02-15 | inline-ignored finding doesn't flip exit; no data race; --show-suppressed KEEPS+annotates inline-ignore so it reaches the output stage (D-12 audit) | integration (CLI) | `go test ./cmd/mimir/ -run 'TestInlineIgnore\|TestVerboseHint\|TestShowSuppressedInline' -race` | ❌ Wave 0 (scan_test additions) | ⬜ pending |
| 02-03-T1 | 03 | 3 | SUP-02, SUP-04 | T-02-06 | ValidatePattern reject; ToSlash; negation order | unit | `go test ./internal/suppress/ -run TestPathMatch -race` | ❌ Wave 0 (pathmatch_test.go) | ⬜ pending |
| 02-03-T2 | 03 | 3 | SUP-02, SUP-04 | T-02-07,T-02-08,T-02-09 | defaults quiet first-run; toggle; malformed fail-loud (exit 2); never-opened | integration (CLI) | `go test ./cmd/mimir/ -run 'TestDefaultExcludes\|TestMimirignoreNegation\|TestDefaultsToggleOff' -race` | ❌ Wave 0 (scan_test additions) | ⬜ pending |
| 02-04-T1 | 04 | 4 | SUP-03 | T-02-10,T-02-11 | OR-match criterion 4; no raw secret; malformed-JSON safe | unit | `go test ./internal/suppress/ -run TestBaseline -race` | ❌ Wave 0 (baseline_test.go) | ⬜ pending |
| 02-04-T2 | 04 | 4 | SUP-03 | T-02-12 | baseline filter post-g.Wait(); all-baselined exits 0; --show-suppressed no exit flip; --baseline-out snapshots reportable set | integration (CLI) | `go test ./cmd/mimir/ -run 'TestBaselineNewOnly\|TestBaselineFileMove\|TestBaselineBlankLineShift\|TestSuppressedExitCode\|TestBaselineOutNoRawSecret' -race` | ❌ Wave 0 (scan_test additions) | ⬜ pending |
| 02-04-T3 | 04 | 4 | SUP-03 | T-02-12,T-02-14 | shared --show-suppressed renderer (baseline+inline-ignore+allowlist) reason-tagged; D-11 summary; OUT-02 preserved | integration (CLI) + unit | `go test ./internal/output/... -run 'TestSuppressionSummary' -race && go test ./cmd/mimir/ -run 'TestShowSuppressed' -race` | ❌ Wave 0 (scan_test + output_test) | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

These scaffolds/fixtures land in Plan 01 (Wave 1, foundation) before the slices consume them:

- [ ] `testdata/dirty/` dirty fixture repo: real fixture secret, `vendor/` + `node_modules/`, `*.min.js`, lockfile, inline-`mimir:ignore` file, `.mimirignore` (`**` glob + `!negation`) — Plan 01 Task 3
- [ ] `testdata/dirty-moved/` — dirty fixture with the secret file relocated (criterion-4 file-move) — Plan 01 Task 3
- [ ] `testdata/dirty-shifted/` — dirty fixture with blank lines inserted above the secret line (criterion-4 blank-line) — Plan 01 Task 3
- [ ] `internal/suppress/doc.go` — package shell + decoupling note — Plan 01 Task 1
- [ ] `internal/suppress/fixtures_test.go` — fixtures sanity test — Plan 01 Task 3
- [ ] `internal/suppress/inline_test.go` — SUP-01 blanket + scoped + Pitfall-3 — Plan 02 Task 1
- [ ] `internal/suppress/pathmatch_test.go` — SUP-02/04 `**`, `!negation`, defaults, toggle, ToSlash — Plan 03 Task 1
- [ ] `internal/suppress/baseline_test.go` — SUP-03 OR-match + criterion-4 stability + no-raw-secret — Plan 04 Task 1
- [ ] `internal/output/output_test.go` additions — D-11 summary, D-12 omitempty — Plan 04 Task 3
- [ ] `cmd/mimir/scan_test.go` additions — inline-ignore/verbose-hint/`TestShowSuppressedInline` (Plan 02) and baseline/show-suppressed/exit-code (Plan 04) via os/exec binary — Plans 02 & 04

---

## Manual-Only Verifications

All phase behaviors have automated verification.

*Color/ANSI rendering is covered by the existing `--no-color` test path; no human-only checks required.*

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (fixtures + test scaffolds enumerated)
- [x] No watch-mode flags
- [x] Feedback latency < 30s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** ready
