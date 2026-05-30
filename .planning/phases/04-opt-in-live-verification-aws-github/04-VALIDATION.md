---
phase: 4
slug: opt-in-live-verification-aws-github
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-30
---

# Phase 4 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Go stdlib `testing` + `stretchr/testify` v1.11.1 (already used) |
| **Config file** | none — standard `go test` |
| **Quick run command** | `/usr/local/go/bin/go test ./internal/verify/... -count=1` |
| **Full suite command** | `/usr/local/go/bin/go test -race ./... -count=1` |
| **Estimated runtime** | ~25 seconds (full `-race`) |

---

## Sampling Rate

- **After every task commit:** Run `/usr/local/go/bin/go test ./internal/verify/... -count=1`
- **After every plan wave:** Run `/usr/local/go/bin/go test -race ./... -count=1`
- **Before `/gsd-verify-work`:** Full `-race` suite green + `go vet` + golangci-lint (gosec)
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| raw-carry | engine/scanner | 1 | (carry) | T-side-channel | Raw secret never on Finding/JSON; side channel off-struct, never marshalled | unit | `go test ./internal/finding -run TestNoRawSecretInAnyField -count=1` | ✅ existing | ⬜ pending |
| aws-classify | verify | 1 | VERIFY-02 | T-false-active | InvalidClientTokenId/SignatureDoesNotMatch/ExpiredToken→inactive; net/timeout→unknown | unit (table) | `go test ./internal/verify -run TestAWSClassify -count=1` | ❌ W0 | ⬜ pending |
| aws-no-ambient | verify | 1 | VERIFY-02 | T-false-active | AWS verifier ignores ambient `AWS_*` env (static creds only) | unit | `go test ./internal/verify -run TestNoAmbientCreds -count=1` | ❌ W0 | ⬜ pending |
| gh-classify | verify | 1 | VERIFY-02 | T-ratelimit | 200→active, 401→inactive, 403/429+Retry-After→unknown, timeout→unknown | unit (httptest) | `go test ./internal/verify -run TestGitHubClassify -count=1` | ❌ W0 | ⬜ pending |
| registry | verify | 1 | VERIFY-02 | — | Rule IDs map to correct verifier; non-AWS/GH findings left unlabeled | unit | `go test ./internal/verify -run TestRegistry -count=1` | ❌ W0 | ⬜ pending |
| cache-dedup | verify | 2 | VERIFY-03 | — | A secret in many findings verified at most once (per-(provider,secret) cache) | unit | `go test ./internal/verify -run TestCacheDedup -count=1` | ❌ W0 | ⬜ pending |
| retry-once | verify | 2 | VERIFY-03 | T-ratelimit | Retry-After honored once, then unknown (no retry loop) | unit (httptest) | `go test ./internal/verify -run TestRetryAfterOnce -count=1` | ❌ W0 | ⬜ pending |
| no-secret-in-error | verify | 2 | VERIFY-03 | T-leak | Secret value never appears in any verifier error/log string | unit | `go test ./internal/verify -run TestNoSecretInError -count=1` | ❌ W0 | ⬜ pending |
| verify-off-default | cmd | 3 | VERIFY-01 | T-hook-online | `--verify` off by default; zero network calls without the flag | integration | `go test ./cmd/... -run TestScanNoVerifyNoNetwork -count=1` | ❌ W0 | ⬜ pending |
| hook-offline | cmd/hook | 3 | VERIFY-01 | T-hook-online | Installed pre-commit hook template never contains `--verify` | unit | `go test ./... -run TestHookOffline -count=1` | ❌ W0 | ⬜ pending |
| json-omit-default | output | 3 | VERIFY-01 | — | Non-`--verify` JSON byte-identical to OUT-02 (verification omitted) | unit | `go test ./internal/output -run TestVerifyOmittedByDefault -count=1` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `internal/verify/verify_test.go` — registry, cache dedup, three-state mapping, no-secret-in-error (VERIFY-02/03)
- [ ] `internal/verify/aws_test.go` — error-code→status table; no-ambient-creds (VERIFY-02; Pitfall: false-active)
- [ ] `internal/verify/github_test.go` — httptest 200/401/403+Retry-After/timeout; Retry-After-once (VERIFY-02/03)
- [ ] `cmd/mimir/*verify_test.go` — `--verify` off-by-default no-network; OUT-02 omit-default (VERIFY-01)
- [ ] hook-offline assertion in the existing hook-installer test file (VERIFY-01)
- [ ] No new framework install — testify already present.

*Existing infrastructure (`go test`, testify) covers all phase requirements; only test files are new.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Real live AWS/GitHub credential returns `active` | VERIFY-02 | Requires real live credentials + live network; cannot run in CI without leaking real secrets | Optional smoke: run `mimir scan --verify` against a throwaway repo containing a known-live test token; confirm `ACTIVE` label. Not part of automated suite. |

*All deterministic phase behaviors have automated verification via httptest/error-injection; only the real-network end-to-end is manual.*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
