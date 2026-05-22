---
phase: 1
slug: usable-end-to-end-scanner
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-22
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Detailed per-task map is populated by the planner from RESEARCH.md §Validation Architecture.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `go test` + `stretchr/testify` (require/assert) |
| **Config file** | none — `go.mod` test deps installed in Wave 0 |
| **Quick run command** | `go test ./...` |
| **Full suite command** | `go test -race ./...` |
| **Estimated runtime** | ~10–30 seconds (greenfield; grows with suite) |

---

## Sampling Rate

- **After every task commit:** Run `go test ./...`
- **After every plan wave:** Run `go test -race ./...`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

> Populated by the planner. Each task that delivers detection, redaction, output,
> config, or exit-code behavior must map to an automated `go test` command or a
> Wave 0 fixture/test-stub dependency. Derived from RESEARCH.md §Validation Architecture.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| TBD | — | — | — | — | — | — | — | — | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `go.mod` / `go.sum` — module init + testify dependency
- [ ] `testdata/` fixtures — files containing known synthetic secrets (AWS/GitHub/Stripe/PEM/JWT/connection-string) for true-positive assertions, plus clean files for false-positive assertions
- [ ] Self-scan validation harness — assert `mimir scan` over Mimir's own output/source never reveals a fixture's raw secret value (redaction guarantee)

*Planner refines this list against the actual package layout.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Human-readable color/formatting appearance | OUT-01 | ANSI/TTY rendering is visual | Run `mimir scan testdata/` in a real terminal; confirm compact `path:line:col rule-id redacted` layout + summary line |

*All other phase behaviors have automated verification (see RESEARCH.md §Validation Architecture).*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
