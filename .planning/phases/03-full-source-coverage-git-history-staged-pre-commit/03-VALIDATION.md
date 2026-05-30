---
phase: 3
slug: full-source-coverage-git-history-staged-pre-commit
status: draft
nyquist_compliant: true
wave_0_complete: false
created: 2026-05-30
---

# Phase 3 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | go test (+ testify v1.11.1) |
| **Config file** | none — Go modules native |
| **Quick run command** | `/usr/local/go/bin/go test ./internal/gitscan/... ./cmd/mimir/...` |
| **Full suite command** | `/usr/local/go/bin/go test -race ./...` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run quick run command for the touched package
- **After every plan wave:** Run `/usr/local/go/bin/go test -race ./...`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

> Tasks map to SCAN-03 (git history, Plan 01), SCAN-04 (staged scan, Plan 02),
> IFACE-03 (pre-commit hook, Plan 03), plus the criterion-2 benchmark gate (Plan 02 T3).
> Each row's test is co-created in the same task (TDD RED→GREEN) — no task lands
> without its automated verify; the first task of each test file is the RED scaffold.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 3-01-01 | 01 | 1 | SCAN-03 | T-03-05 | Commit metadata never enters fingerprint (D-09); reflect-guard covers new fields | unit | `/usr/local/go/bin/go test ./internal/finding/ -run 'TestCommitMetaOmitempty|TestFingerprint|TestNoRawSecretInAnyField' -count=1` | ❌ W0 (RED scaffold here) | ⬜ pending |
| 3-01-02 | 01 | 1 | SCAN-03 | T-03-01,T-03-03,T-03-04,T-03-SC | git arg-slice exec; redact-at-boundary; drain+Wait; go mod verify | integration | `/usr/local/go/bin/go test ./internal/gitscan/ -run 'TestHistoryDeletedSecret|TestHistoryDedup' -count=1 && /usr/local/go/bin/go mod verify` | ❌ W0 | ⬜ pending |
| 3-01-03 | 01 | 1 | SCAN-03 | T-03-01,T-03-03 | --git source branch; short-SHA redacted output; non-repo exit 2 | e2e | `/usr/local/go/bin/go test ./cmd/mimir/ -run 'TestGitMode' -count=1` | ❌ W0 | ⬜ pending |
| 3-02-01 | 02 | 2 | SCAN-04 | T-03-06,T-03-07 | staged arg-slice exec; inline-ignore honored; no commit-meta leak | integration | `/usr/local/go/bin/go test ./internal/gitscan/ -run 'TestStagedSecret|TestStagedInlineIgnore' -count=1` | ❌ W0 | ⬜ pending |
| 3-02-02 | 02 | 2 | SCAN-04 | T-03-06 | --staged branch; --git/--staged mutual exclusion exit 2 | e2e | `/usr/local/go/bin/go test ./cmd/mimir/ -run 'TestStagedMode|TestStagedInlineIgnoreCmd|TestGitStagedMutuallyExclusive' -count=1` | ❌ W0 | ⬜ pending |
| 3-02-03 | 02 | 2 | Criterion 2 | T-03-08,T-03-09 | streaming bounded-memory regression gate + wall-time | benchmark | `/usr/local/go/bin/go test -bench 'BenchmarkHistoryMem|BenchmarkStaged' -benchmem -run '^$' ./internal/gitscan/` | ❌ W0 | ⬜ pending |
| 3-03-01 | 03 | 3 | IFACE-03 | T-03-10,T-03-11,T-03-12,T-03-14 | rev-parse hook dir; no-clobber w/o --force; managed-only uninstall; no --verify | e2e | `/usr/local/go/bin/go test ./cmd/mimir/ -run 'TestHookInstall|TestHookInstallRefusesOverwrite|TestHookUninstallManagedOnly|TestHookStatus|TestHookNonRepoFailsLoud' -count=1` | ❌ W0 | ⬜ pending |
| 3-03-02 | 03 | 3 | IFACE-03 | T-03-13,T-03-14 | block real commit; redacted output; honest bypass; offline | e2e | `/usr/local/go/bin/go test ./cmd/mimir/ -run 'TestHookBlocksCommit|TestHookRespectsInlineIgnore|TestHookBypass|TestHookOffline' -count=1` | ❌ W0 | ⬜ pending |
| 3-03-03 | 03 | 3 | IFACE-03 | — | manifest + documented bypass/prerequisite | doc-check | `test -f .pre-commit-hooks.yaml && grep -q 'pass_filenames: false' .pre-commit-hooks.yaml && grep -q -- '--no-verify' README.md` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

> Nyquist compliance: every task has an `<automated>` verify; no 3 consecutive tasks
> lack automated verification. The RED test scaffolds (gitscan_test.go, finding tests,
> hook_test.go, bench_test.go) are authored inside the first task that needs them,
> satisfying the Wave-0-creates-the-test rule.

---

## Wave 0 Requirements

- [ ] `internal/gitscan/gitscan_test.go` — fixture-repo helper + SCAN-03 (history) + SCAN-04 (staged) tests (created in 3-01-01 / 3-02-01)
- [ ] history/staged fixture-repo construction helper (added-then-deleted secret, staged secret, inline-ignore variant)
- [ ] `internal/gitscan/bench_test.go` — `BenchmarkHistoryMem` (criterion-2 memory gate) + `BenchmarkStaged` (created in 3-02-03)
- [ ] `internal/finding/finding_test.go` — commit-metadata omitempty + fingerprint-unchanged assertions (created in 3-01-01)
- [ ] `cmd/mimir/hook_test.go` — install/uninstall/status + block-commit + bypass e2e (created in 3-03-01 / 3-03-02)

*Each scaffold is authored inside the task that first exercises it (TDD), not a separate Wave 0 plan.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Pre-commit hook blocks a real commit end-to-end | IFACE-03 | Exercises real `git commit` + installed hook in `.git/hooks` | Install hook via `mimir hook install`, stage a secret, run `git commit`, confirm non-zero exit + finding; confirm `--no-verify` and `git config hooks.mimir false` bypass it |

*Automated coverage (`TestHookBlocksCommit`/`TestHookBypass`) exercises the live git-commit path via the test binary on PATH; this row is the human confirmation sign-off.*

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 30s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved (planner, 2026-05-30)
