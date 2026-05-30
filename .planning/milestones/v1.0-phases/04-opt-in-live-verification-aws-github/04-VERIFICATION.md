---
phase: 04-opt-in-live-verification-aws-github
verified: 2026-05-30T00:00:00Z
status: passed
score: 5/5 must-haves verified
overrides_applied: 0
re_verification:
  previous_status: none
  previous_score: none
human_verification:
  - test: "Live AWS verification against a real, active access-key + secret-key pair"
    expected: "mimir scan --verify labels the finding ACTIVE; a revoked/expired key labels INACTIVE; an offline run (network down) labels UNKNOWN, never INACTIVE"
    why_human: "Requires real AWS credentials and a live STS endpoint; the automated suite covers the classification table and ambient-free construction via injected/fake errors and httptest, but cannot hit sts.amazonaws.com"
  - test: "Live GitHub verification against a real, active PAT"
    expected: "mimir scan --verify labels the finding ACTIVE; a revoked token labels INACTIVE; a rate-limited/offline run labels UNKNOWN"
    why_human: "Requires a real GitHub token and a live api.github.com; automated coverage uses httptest for 200/401/403/429/timeout but cannot exercise the production host"
---

# Phase 4: Opt-in Live Verification (AWS + GitHub) Verification Report

**Phase Goal:** A developer can opt in with `--verify` to confirm whether found AWS/GitHub credentials are actually live — turning "is this real?" noise into actionable findings — without risking lockouts, rate-limit bans, or leaked credentials, and with no changes to the detection engine.
**Verified:** 2026-05-30
**Status:** passed (all automated criteria verified; two live-network checks routed to human as label-only confirmations, not blockers)
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | VERIFY-01: `--verify` exists, off by default, ZERO network when absent, never in the installed hook, label-only (exit codes unchanged) | ✓ VERIFIED | `cmd/mimir/scan.go:38` registers `Bool("verify", false, ...)`; `:168-174` calls `verify.Run` only inside `if doVerify`; exit-code block untouched (verify.Run runs before output, never touches `os.Exit`). Hook template `cmd/mimir/hook.go:28` execs `mimir scan --staged` with NO `--verify`. Exactly one `func TestHookOffline` (`hook_test.go:275`) asserting `NotContains "--verify"`. `TestScanNoVerifyNoNetwork` + `TestHookOffline` PASS. |
| 2 | VERIFY-02: AWS via STS GetCallerIdentity with STATIC creds (no LoadDefaultConfig); GitHub via GET api.github.com/user; three-state; network failure → unknown | ✓ VERIFIED | `internal/verify/aws.go:86-94` builds `sts.New(sts.Options{...})` with `NewStaticCredentialsProvider` + pinned `BaseEndpoint`; `grep LoadDefaultConfig(` in `internal/verify/` → NO CALL. `classifyAWSError` (`aws.go:108`): nil→Active, definitive code→Inactive, else→Unknown. `github.go:104-148`: GET `/user`, 200→Active/401→Inactive/403+429→rate-limit/default→Unknown; network+timeout→Unknown (`:114-121`). `TestAWSClassify`, `TestNoAmbientCreds`, `TestGitHubClassify`, `TestGitHubTimeout`, `TestGitHubNetworkError` PASS. |
| 3 | VERIFY-03: per-secret cache (verify once), rate-limit backoff (Retry-After once → unknown), per-call timeout, secret never in log/error/field/JSON | ✓ VERIFIED | `verify.go:106-148` cache keyed by `(provider, secret)` under mutex, in-flight reservation via `done` channel; `g.SetLimit(5)` (`:70`); `context.WithTimeout(ctx, 5s)` (`:137`). GitHub honors Retry-After once then Unknown (`github.go:63-87`, no loop). `sanitizedError{provider, reason}` only; no `%w`/`%v` of SDK/HTTP error. `TestCacheDedup`, `TestRetryAfterOnce`, `TestNoSecretInError`, `TestNoRawSecretInAnyField` PASS. |
| 4 | Detection engine unchanged in behavior (side channel additive only) | ✓ VERIFIED | `engine.go:155` is the sole change: `raw[f.Fingerprint] = rawSecret` AFTER `finding.New(...)`; no detection/entropy/allowlist logic altered. Raw map threaded out of Scan/ScanHistory/ScanStaged (raw before Stats) and only ever passed to `verify.Run` — never to `json.Encode` (`output/json.go:51` encodes `result`, not raw). `internal/detect` tests PASS. |
| 5 | CR-01 (deadlock-on-panic) and CR-02 (scanRoot path resolution) genuinely fixed | ✓ VERIFIED | CR-01: `verify.go:130-140` wraps compute in closure with unconditional `defer close(entry.done)` + `recover()→Unknown`; `TestPanicDoesNotDeadlock` (20 findings, shared secret) PASS. CR-02: `aws.go:80` resolves `filepath.Join(scanRoot, filepath.FromSlash(f.File))`; scanRoot threaded `Run→runWithRegistry→Verify`; `TestAWSVerifyResolvesScanRoot` (nested path + wrong-root→false) PASS. |

**Score:** 5/5 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `internal/finding/finding.go` | `Verification` type + `*Verification` omitempty field | ✓ VERIFIED | Pointer omitempty field (`:69`); `Verification` struct two enum strings only (`:79-84`); not in `computeFingerprint`/`New` |
| `internal/verify/verify.go` | Verifier interface, Status enum, registry, Run + cache + errgroup | ✓ VERIFIED | All present; 238 lines, substantive; registry maps 6 AWS/GitHub rule IDs |
| `internal/verify/aws.go` | static-cred STS, ambient-free, secret-key pairing, scanRoot | ✓ VERIFIED | 204 lines; no LoadDefaultConfig; pairing requires hint (WR-02), anchored regex (WR-06), line-boundary truncation (WR-03) |
| `internal/verify/github.go` | net/http GET /user + status/rate-limit classification | ✓ VERIFIED | 198 lines; token only in Authorization header; Retry-After parsed (delta + HTTP-date, WR-04); 403 rate-limit signal gate (WR-05) |
| `cmd/mimir/scan.go` | `--verify` flag + verify.Run on newFindings | ✓ VERIFIED | Flag off by default; verify.Run on post-suppression `newFindings`; WR-01 back-propagation under `--show-suppressed`; exit codes untouched |
| `internal/output/human.go` | colored verification tag + tally | ✓ VERIFIED (WIRED) | `TestHumanVerificationTag` + `TestHumanVerifiedTally` PASS |
| `cmd/mimir/hook.go` | unchanged, offline | ✓ VERIFIED | Execs `mimir scan --staged`; no `--verify` |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `engine.ScanLine` | raw sink map | `raw[f.Fingerprint] = rawSecret` | ✓ WIRED | `engine.go:155` at the redact boundary |
| `scanner.Scan` / `gitscan.ScanHistory`/`ScanStaged` | raw map return | threaded before Stats | ✓ WIRED | `scanner.go:203`, gitscan signatures updated; `cmd/mimir/scan.go:115-119` capture `raw` |
| `cmd/mimir/scan.go runScan` | `verify.Run` | post-suppression, flag-guarded, scanRoot passed | ✓ WIRED | `:174` `verify.Run(ctx, scanRoot, newFindings, raw)` |
| `verify.Run` | `finding.Verification` | `findings[i].Verification = &finding.Verification{...}` | ✓ WIRED | `verify.go:99-103`, `:143-146` |
| `aws.go` | static STS client | `sts.New(sts.Options{...})` no LoadDefaultConfig | ✓ WIRED | `aws.go:86-90` |
| `github.go` | `api.github.com/user` | net/http GET, Authorization Bearer | ✓ WIRED | `github.go:104-111` |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| `finding.Verification` (JSON/human) | `findings[i].Verification` | `verify.Run` → real STS/HTTP call result (or Unknown) | Yes (label) | ✓ FLOWING — populated from live verifier result; raw secret carried off-struct via `rawByFP` keyed by fingerprint, never serialized |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Repo builds | `go build ./...` | BUILD_OK | ✓ PASS |
| Static analysis clean | `go vet ./...` | VET_OK | ✓ PASS |
| Full suite under race | `go test -race ./... -count=1` | all packages ok | ✓ PASS |
| Critical guards | `go test -race -run 'TestPanicDoesNotDeadlock\|TestAWSVerifyResolvesScanRoot\|TestNoAmbientCreds\|TestCacheDedup\|TestNoSecretInError\|TestRetryAfterOnce\|TestNoRawSecretInAnyField\|TestScanNoVerifyNoNetwork\|TestHookOffline'` | all PASS | ✓ PASS |
| AWS modules verified | `go mod verify` | all modules verified | ✓ PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| VERIFY-01 | 04-03 | Opt-in `--verify`, off by default, never in pre-commit | ✓ SATISFIED | Truth 1; TestScanNoVerifyNoNetwork, TestHookOffline PASS |
| VERIFY-02 | 04-01, 04-02, 04-03 | AWS STS + GitHub /user read-only calls, three-state | ✓ SATISFIED | Truth 2; AWS/GitHub classify tests PASS |
| VERIFY-03 | 04-01, 04-02, 04-03 | Per-secret cache, rate-limit backoff, no secret logged | ✓ SATISFIED | Truth 3; TestCacheDedup, TestRetryAfterOnce, TestNoSecretInError PASS |

All three requirement IDs from PLAN frontmatter are accounted for and SATISFIED. No orphaned VERIFY-* IDs in REQUIREMENTS.md (all three map to Phase 4 and are covered).

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| — | — | No debt markers (TBD/FIXME/XXX) in phase-modified production files | — | None |

`LoadDefaultConfig` appears only in explanatory comments (aws.go, verify.go) and a test comment — never as a call. The `--no-verify` strings in hook.go are git's flag in documentation, not mimir `--verify`. No stub/placeholder/empty-return anti-patterns in the verify package. IN-03 (`AccessDenied` in definitiveRejectCodes) was deliberately deferred in REVIEW-FIX as a product/security policy call, not a defect — does not block the goal.

### Human Verification Required

These are live-network label-only confirmations. The automated suite fully covers the classification logic, cache, rate-limit handling, ambient-free construction, and no-leak guards via httptest and injected errors; only a hit against the real provider hosts cannot be automated. They are NOT blockers — every automated criterion passes.

1. **Live AWS verification** — Run `mimir scan --verify` over a file containing a real active AWS access key + co-located secret key.
   - Expected: finding tagged ACTIVE; a revoked key → INACTIVE; an offline run → UNKNOWN (never INACTIVE).

2. **Live GitHub verification** — Run `mimir scan --verify` over a file containing a real active GitHub PAT.
   - Expected: finding tagged ACTIVE; a revoked token → INACTIVE; a rate-limited/offline run → UNKNOWN.

### Gaps Summary

No gaps. All five observable truths are verified in code with passing automated guards, the build/vet/race suite is fully green, both code-review blockers (CR-01 deadlock-on-panic, CR-02 scanRoot resolution) are genuinely fixed with regression tests, the detection engine change is purely additive, the raw secret is provably carried off-struct and never serialized, and the pre-commit hook stays offline. The only non-automatable items are two live-network label confirmations, surfaced for human testing.

---

_Verified: 2026-05-30_
_Verifier: Claude (gsd-verifier)_
