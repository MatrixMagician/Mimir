---
phase: 04-opt-in-live-verification-aws-github
fixed_at: 2026-05-30T00:00:00Z
review_path: .planning/phases/04-opt-in-live-verification-aws-github/04-REVIEW.md
iteration: 1
findings_in_scope: 12
fixed: 11
skipped: 1
status: partial
---

# Phase 4: Code Review Fix Report

**Source review:** `.planning/phases/04-opt-in-live-verification-aws-github/04-REVIEW.md`
**Iteration:** 1

**Summary:**
- Findings in scope: 12 (2 critical, 6 warning, 4 info)
- Fixed: 11 (both criticals, all six warnings, IN-01/IN-02/IN-04)
- Deferred: 1 (IN-03, with rationale)

**Verification gate (all green):**
`/usr/local/go/bin/go build ./... && /usr/local/go/bin/go vet ./... && /usr/local/go/bin/go test -race ./... -count=1`

Security invariants preserved throughout: the raw secret never lands in a log,
error, exported field, or JSON; all SDK/HTTP errors stay reduced to
`sanitizedError{provider, reason}` (no `%w`/`%v`); AWS still builds its STS
client from static creds only (no `config.LoadDefaultConfig`); network / timeout
/ throttle still classify as `unknown`, never `inactive`. All new tests use
`httptest` / injected errors — no real network.

## Fixed Issues

### CR-01: Panicking verifier deadlocked the whole scan
**Files:** `internal/verify/verify.go`, `internal/verify/verify_test.go`
**Commit:** `4abd8a2`
Wrapped the cache owner's compute in a closure with `defer close(entry.done)`
and a `recover()` that classifies a panicking secret as `Unknown`. The channel
close is now unconditional, so a panic in `v.Verify` can no longer park every
waiter on `<-entry.done` and hang `g.Wait()`. Added `TestPanicDoesNotDeadlock`
(shared secret across 20 findings, 10s watchdog) as the regression guard.

### CR-02: AWS verification read the wrong path when scan target != CWD
**Files:** `internal/verify/verify.go`, `internal/verify/aws.go`,
`internal/verify/github.go`, `cmd/mimir/scan.go`, plus tests
**Commit:** `6cf0ca2`
Threaded `scanRoot` through `verify.Run` → `runWithRegistry` →
`Verifier.Verify`. The AWS verifier now resolves
`filepath.Join(scanRoot, filepath.FromSlash(f.File))` instead of reading the
repo-relative path against the process CWD. `--git`/`--staged` findings (no
on-disk counterpart) fail the read gracefully → `Unknown`, never a false
`inactive`. Converted `TestAWSPairingMissingSecretKey` to the relative-path +
scanRoot form and added `TestAWSVerifyResolvesScanRoot`.
**Note:** logic-bearing — recommend a manual confirm that the scanRoot resolves
correctly for a file-target scan (where `resolveScanRoot` returns the file's
directory).

### WR-01: `--verify` tags vanished under `--show-suppressed`
**File:** `cmd/mimir/scan.go`
**Commit:** `e24e6b9`
After `verify.Run`, when `--show-suppressed` is set, back-propagate each
`Verification` from the `newFindings` copies onto the matching original
`findings` entries by fingerprint, so the displayed (original) slice carries the
tags. Logic-bearing — recommend a manual confirm.

### WR-02 / WR-06: arbitrary 40-char pairing and unanchored secret-key regex
**Files:** `internal/verify/aws.go`, `internal/verify/aws_test.go`
**Commit:** `29440ba`
WR-02: `findSecretKey` now refuses to pair when no secret-key hint line is
present (returns `("", false)` → `Unknown`), instead of sending the file's first
40-char base64 token to STS and risking a `SignatureDoesNotMatch` that would
report a live key as `inactive`. WR-06: anchored `secretKeyRE` with
token-boundary guards + capture group 1 so a 40-char prefix of a longer base64
blob is no longer a spurious candidate. Added `TestAWSPairingRequiresHint` and
`TestAWSPairingIgnoresLongerBlob`.

### WR-03: 1 MiB truncation could split a UTF-8 rune / the secret key
**File:** `internal/verify/aws.go`
**Commit:** `6093366`
The pairing read now truncates at the last newline before the cap (via
`bytes.LastIndexByte`) rather than a raw byte offset, keeping every retained
line intact and well-formed.

### WR-04 / WR-05: Retry-After HTTP-date and 403 classification
**Files:** `internal/verify/github.go`, `internal/verify/github_test.go`
**Commit:** `0902319`
WR-04: `parseRetryAfter` now falls back to `http.ParseTime` for the HTTP-date
form, treats a past date as immediate retry, and treats a truly unparseable
value as wait-the-cap (not retry-now). WR-05: a 403 is only treated as a
secondary rate-limit (and retried once) when it carries a rate-limit signal
(`Retry-After` or `X-RateLimit-Remaining: 0`); a signal-less 403 is `Unknown`
with no retry. Added `TestForbiddenWithRateLimitSignalRetries`,
`TestForbiddenNoSignalNoRetry`, and `TestParseRetryAfter`.

### IN-01 / IN-02 / IN-04: redundant loop-variable shadows under go 1.25
**Files:** `internal/verify/verify.go`, `internal/scanner/scanner.go`
**Commit:** `ebed428`
Dropped the pre-1.22 `i := i` / `root := root` capture shadows and their
misleading "capture loop variable" comments (go.mod pins `go 1.25`, where each
iteration already has its own variable). Kept `f := findings[i]` in verify.go as
a deliberate value copy and documented the intent (IN-02).

## Deferred Issues

### IN-03: `definitiveRejectCodes` includes `AccessDenied`
**File:** `internal/verify/aws.go:40-46`
**Reason for deferral:** The review frames this as a *consideration*
("Consider mapping `AccessDenied` to `unknown`"), not a defect. Changing it is a
semantic classification shift with a real tradeoff: `AccessDenied` on
`GetCallerIdentity` is rare for a genuinely-dead key, but mapping it to
`unknown` would weaken a definitive-reject signal that the existing
`TestAWSClassify` case explicitly pins (`AccessDenied` → `Inactive`). This is a
product/security policy call best made deliberately rather than folded into a
review-fix pass; flagging for human decision. No code change applied.

---

_Fixed: 2026-05-30_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
