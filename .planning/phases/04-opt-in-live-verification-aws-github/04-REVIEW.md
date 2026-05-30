---
phase: 04-opt-in-live-verification-aws-github
reviewed: 2026-05-30T00:00:00Z
depth: deep
files_reviewed: 10
files_reviewed_list:
  - cmd/mimir/scan.go
  - internal/detect/engine.go
  - internal/finding/finding.go
  - internal/gitscan/gitscan.go
  - internal/gitscan/parse.go
  - internal/output/human.go
  - internal/scanner/scanner.go
  - internal/verify/verify.go
  - internal/verify/aws.go
  - internal/verify/github.go
findings:
  critical: 2
  warning: 6
  info: 4
  total: 12
status: issues_found
---

# Phase 4: Code Review Report

**Reviewed:** 2026-05-30
**Depth:** deep
**Files Reviewed:** 10
**Status:** issues_found

## Summary

Phase 4 adds opt-in live verification of AWS access keys and GitHub tokens. The
security architecture is largely sound: the secret never lands in an exported
`Finding` field (reflect-guard test passes), the `sanitizedError` type structurally
cannot carry a token, AWS builds its STS client from static creds only (no
`config.LoadDefaultConfig`, no ambient resolution), GitHub sends the token only in
the `Authorization` header, verification is strictly off-by-default and label-only,
and the three-state classifier correctly maps network/timeout/throttle to `unknown`.

However, two BLOCKER-level defects undermine the feature's correctness and
robustness:

1. **A panicking verifier deadlocks the entire scan** — the per-secret cache uses
   `close(entry.done)` without `defer`, so any panic inside `Verify` leaves waiters
   blocked forever and `g.Wait()` never returns.
2. **AWS verification silently fails (always `unknown`) whenever the scan target is
   not the process CWD** — the verifier resolves the finding's *repo-relative* path
   against the current working directory, with no scanRoot threaded through.

The remaining findings concern best-effort pairing heuristics, an inconsistency
between `--verify` and `--show-suppressed`, a UTF-8 truncation edge, and redundant
Go 1.22+ loop-variable shadowing.

## Critical Issues

### CR-01: Panicking verifier deadlocks the whole scan (no `defer close`)

**File:** `internal/verify/verify.go:100-124`
**Issue:** The cache owner computes its result and then closes the done channel
in sequence:

```go
entry = &cacheEntry{done: make(chan struct{})}
cache[key] = entry
mu.Unlock()

callCtx, cancel := context.WithTimeout(ctx, perCallTimeout)
entry.status = v.Verify(callCtx, raw, f)   // <-- if this panics...
cancel()
close(entry.done)                          // <-- ...this never runs
```

If `v.Verify` panics (a malformed regex pairing edge, an SDK bug on adversarial
input, a future verifier), `close(entry.done)` is skipped. Every other goroutine
waiting on that key blocks on `<-entry.done` forever, so `g.Wait()` on line 129
never returns and the **entire `mimir scan --verify` invocation hangs** — a
denial-of-availability triggered by scanned repository content, which is exactly
the threat surface this tool is built to withstand. `errgroup` does not recover
panics, so the panic also crashes the process, but only after the goroutine
unwinds — waiters stay parked.

**Fix:** Make the channel close unconditional, and recover so one bad secret
yields `unknown` instead of aborting the run:

```go
entry = &cacheEntry{done: make(chan struct{})}
cache[key] = entry
mu.Unlock()

func() {
    defer close(entry.done)
    defer func() {
        if r := recover(); r != nil {
            entry.status = Unknown
        }
    }()
    callCtx, cancel := context.WithTimeout(ctx, perCallTimeout)
    defer cancel()
    entry.status = v.Verify(callCtx, raw, f)
}()
```

### CR-02: AWS verification reads the wrong path when scan target ≠ CWD

**File:** `internal/verify/aws.go:63-64,112-113` (and call site `cmd/mimir/scan.go:170`)
**Issue:** `awsVerifier.Verify` pairs the access key by reading the finding's file:

```go
secretKey, ok := findSecretKey(f.File)   // aws.go:64
...
data, err := os.ReadFile(path)           // aws.go:113
```

`f.File` is the **repo-relative, forward-slash path** assembled in
`scanner.go:256-262` (`filepath.Rel(scanRoot, filePath)`), e.g. `config/creds.txt`.
The verifier resolves it with `os.ReadFile` against the process's current working
directory. `verify.Run` is never given the `scanRoot`. Therefore, whenever the user
runs `mimir scan /path/to/repo --verify` from any directory other than
`/path/to/repo`, `os.ReadFile("config/creds.txt")` fails, `findSecretKey` returns
`("", false)`, and **every AWS finding is labelled `unknown`** — the verifier
silently never makes a network call. The existing tests pass only because they pass
an absolute `f.File` (`aws_test.go:88` uses `filepath.Join(dir, ...)`), masking the
real-world relative-path case.

For `--git`/`--staged` scans this is worse: the path is repo-relative to the git
root and the historical content may not exist in the working tree at all, so the
pairing reads unrelated current content (or nothing).

**Fix:** Thread the scan root into verification and join it before reading, or carry
an absolute path on the finding for the verifier's use. Minimal form — pass
`scanRoot` to `verify.Run` and into the verifier, then:

```go
func (awsVerifier) Verify(ctx context.Context, raw string, f finding.Finding) Status {
    secretKey, ok := findSecretKey(filepath.Join(scanRoot, filepath.FromSlash(f.File)))
    ...
}
```

At minimum, document that `--verify` for AWS requires running from the scan root,
and fail loud (verbose log) when the pairing read errors so the silent-`unknown`
is observable.

## Warnings

### WR-01: `--verify` tags vanish under `--show-suppressed`

**File:** `cmd/mimir/scan.go:153-185`
**Issue:** `newFindings` is built by value-copying finding structs out of `findings`
(lines 153-158). `verify.Run` writes `Verification` onto the `newFindings` copies
(line 170). But when `--show-suppressed` is set, `display = findings` (line 184) —
the original slice, whose elements never received the `Verification` pointer.
Result: `mimir scan --verify --show-suppressed` runs verification (network calls
happen) but the human/JSON output shows **no verification tags at all**, because the
displayed slice is the un-verified original. Silent loss of the feature's output.
**Fix:** Either run verify on the displayed slice, or back-propagate the
`Verification` from `newFindings` onto the matching `findings` entries (match by
fingerprint) before choosing `display`.

### WR-02: `findSecretKey` pairs the access key with an arbitrary 40-char token

**File:** `internal/verify/aws.go:112-154`
**Issue:** When no `secretKeyHintRE` line is present, the helper returns
`candidates[0].value` — the **first** 40-char `[A-Za-z0-9/+]{40}` token anywhere in
the file (line 143-144). Any base64 blob, hash, JWT segment, or vendored key of
exactly 40 chars gets sent to STS as the secret. Because a wrong pairing produces
`SignatureDoesNotMatch`, which is in `definitiveRejectCodes` (aws.go:42), the
verifier will report a genuinely-live access key as **`inactive`** — a false
negative on the highest-severity outcome (a real, active leaked credential reported
as dead). This directly contradicts the three-state intent that only the *credential
pair* being rejected means inactive.
**Fix:** Require a hint line to pair (return `("", false)` when `hintLines` is
empty), or treat `SignatureDoesNotMatch` as `unknown` rather than `inactive` since
it conflates "wrong secret key" with "tampered access key". Given the heuristic
pairing, `SignatureDoesNotMatch` cannot distinguish the two.

### WR-03: 1 MiB truncation can split a UTF-8 rune / bisect the secret key

**File:** `internal/verify/aws.go:117-119`
**Issue:** `data = data[:maxPairingReadBytes]` cuts at a raw byte offset. If a secret
key straddles the 1 MiB boundary it is bisected and never matched (acceptable), but
the truncation can also slice a multi-byte UTF-8 sequence; `string(data)` then
yields a replacement rune at the boundary. This is benign for the regex but is a
latent correctness smell. **Fix:** Cap to the last newline before the limit, or
read with `io.LimitReader` and accept the partial-final-line semantics explicitly.

### WR-04: `parseRetryAfter` ignores HTTP-date form, returns immediate retry

**File:** `internal/verify/github.go:141-155`
**Issue:** `Retry-After` may legitimately be an HTTP-date (RFC 7231 allows both
delta-seconds and a date). `strconv.Atoi` fails on a date string, falling into the
`err != nil` branch (line 147) which returns `time.Nanosecond` — i.e. an *immediate*
retry. GitHub primarily uses delta-seconds, but if it (or a proxy) returns a date,
the verifier ignores the requested backoff and retries instantly, then gives up
`unknown`. Low impact (bounded to one retry), but the comment claims "HTTP-date form
is not honored" without noting it degrades to immediate-retry. **Fix:** Parse
`http.ParseTime` as a fallback, clamp to `retryAfterCap`, or at least treat an
unparseable value as "wait the cap" rather than "retry now."

### WR-05: GitHub 403 without rate-limit signal is misclassified as a retryable rate-limit

**File:** `internal/verify/github.go:129-131`
**Issue:** `http.StatusForbidden` is unconditionally treated as a rate-limit and
triggers the single retry path. GitHub returns 403 for many non-rate-limit reasons
(missing User-Agent — though that is set here, token lacks scope, SAML enforcement,
IP allowlist). For those, the token is often *valid* (`active`) but the endpoint is
forbidden; classifying as a retried `unknown` is defensible, but conflating all 403s
with rate-limiting and burning a retry is imprecise. **Fix:** Distinguish secondary
rate-limit 403s (presence of `Retry-After` or `X-RateLimit-Remaining: 0`) from other
403s; treat a 403 with no rate-limit headers as `unknown` without a retry.

### WR-06: `findSecretKey` returns first candidate on hint-distance ties non-deterministically-ordered

**File:** `internal/verify/aws.go:146-153`
**Issue:** The nearest-hint selection keeps the first candidate seen on a tie
(`d < bestDist`, strict), which is deterministic by file order — acceptable. But the
secret-key regex `[A-Za-z0-9/+]{40}` will also match inside a *longer* base64 string
(e.g. a 60-char blob yields a 40-char prefix), and `FindAllString` returns
non-overlapping matches, so a long key can produce a wrong 40-char slice that gets
paired. This compounds WR-02's false-`inactive` risk. **Fix:** Anchor the secret-key
match to token boundaries (`(?:^|[^A-Za-z0-9/+])([A-Za-z0-9/+]{40})(?:[^A-Za-z0-9/+]|$)`)
so only true 40-char tokens are candidates.

## Info

### IN-01: Redundant loop-variable shadowing (Go 1.25)

**File:** `internal/verify/verify.go:78-79`, `internal/scanner/scanner.go:86`, `internal/gitscan/...`
**Issue:** `i := i` and `f := findings[i]` re-declarations exist to defeat the
pre-1.22 loop-variable capture footgun. `go.mod` pins `go 1.25.0`, where each
iteration already has its own variable, so these are dead/no-op shadows. Harmless
but misleading (implies a capture hazard that no longer exists). **Fix:** Drop the
redundant `i := i` / `root := root` shadows now that the floor is 1.25.

### IN-02: `f := findings[i]` copies the struct but only `provider`/`raw` are used

**File:** `internal/verify/verify.go:79`
**Issue:** Line 79 copies the entire `Finding` by value into `f`, then the closure
captures it solely to pass to `v.Verify(callCtx, raw, f)`. The AWS verifier only
reads `f.File`. The full-struct copy per finding is unnecessary; passing `f.File`
(or the relevant fields) would be leaner and make the data dependency explicit.
**Fix:** Capture only what `Verify` needs, or document that the whole finding is
intentionally available to future verifiers.

### IN-03: `definitiveRejectCodes` includes `AccessDenied` — credential may be live

**File:** `internal/verify/aws.go:40-46`
**Issue:** `AccessDenied` is treated as a definitive `inactive`. But STS
`GetCallerIdentity` is unusual in that it succeeds for *any* valid credential; an
`AccessDenied` typically means an explicit deny policy or SCP, not an invalid key —
the credential can be **active** yet blocked from this call. Reporting it as
`inactive` is a potential false negative on a live secret. **Fix:** Consider mapping
`AccessDenied` to `unknown` (cannot determine liveness) rather than `inactive`,
since `GetCallerIdentity` rarely returns `AccessDenied` for a genuinely-dead key.

### IN-04: Comment claims `i := i`/`f := f` guards capture, but inaccurate post-1.22

**File:** `internal/scanner/scanner.go:85-86`, `cmd` closures
**Issue:** Comments like `// capture loop variable` (scanner.go:86) document a
pre-1.22 hazard that no longer applies under `go 1.25.0`. Documentation drift; not a
correctness issue. **Fix:** Update or remove the comments alongside IN-01.

---

_Reviewed: 2026-05-30_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: deep_
