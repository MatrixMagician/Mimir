---
phase: 3
slug: full-source-coverage-git-history-staged-pre-commit
status: draft
nyquist_compliant: false
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

> Populated by gsd-planner during planning. One row per task, mapping to
> SCAN-03 (git history), SCAN-04 (staged scan), IFACE-03 (pre-commit hook),
> plus the criterion-2 benchmark gate.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 3-01-01 | 01 | 0 | SCAN-03 | — | N/A | unit | `/usr/local/go/bin/go test ./internal/gitscan/...` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `internal/gitscan/gitscan_test.go` — stubs for SCAN-03 (history) + SCAN-04 (staged)
- [ ] history/staged fixture-repo construction helper (added-then-deleted secret, staged secret)
- [ ] benchmark harness for criterion-2 (peak memory + wall time gate)

*Planner refines exact files during planning.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Pre-commit hook blocks a real commit end-to-end | IFACE-03 | Exercises real `git commit` + installed hook in `.git/hooks` | Install hook via `mimir hook install`, stage a secret, run `git commit`, confirm non-zero exit + finding; confirm `--no-verify` bypass documented |

*Automated coverage exists for hook script logic; the live git-commit integration is the manual confirmation.*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
