---
phase: 04-opt-in-live-verification-aws-github
plan: 02
subsystem: verification/network-boundary
tags: [verification, aws-sts, github-api, errgroup, redact-at-boundary, sanitized-error]
requires:
  - "finding.Verification type + Finding.Verification field (Plan 04-01)"
  - "fingerprint->raw side-channel map from Scanner.Scan / gitscan (Plan 04-01)"
  - "internal/scanner errgroup + locked-map cache pattern (Phase 1)"
  - "internal/detect engine package conventions + RE2 allowlist discipline (Phase 1)"
provides:
  - "internal/verify.Run(ctx, findings, rawByFP) — label-only live verification orchestrator"
  - "Verifier interface + three-state Status enum (Active/Inactive/Unknown)"
  - "rule-ID->Verifier registry (6 AWS/GitHub IDs; others unlabeled)"
  - "awsVerifier (static-cred STS GetCallerIdentity, provably ambient-free)"
  - "githubVerifier (bare net/http GET /user with rate-limit classification)"
  - "sanitizedError{provider,reason} — no-secret-leak error type"
affects:
  - "cmd/mimir/scan.go (Plan 04-03 wires Run into runScan after suppression, consumes rawByFP)"
tech-stack:
  added:
    - "github.com/aws/aws-sdk-go-v2 v1.41.9 (root)"
    - "github.com/aws/aws-sdk-go-v2/credentials v1.19.19"
    - "github.com/aws/aws-sdk-go-v2/service/sts v1.42.3"
    - "github.com/aws/smithy-go v1.26.0 (APIError contract)"
  patterns:
    - "Pure classifier functions (classifyAWSError, HTTP status switch) — error-code->Status testable with zero network"
    - "Static-credential-only AWS client (sts.New + NewStaticCredentialsProvider, BaseEndpoint pinned) — ambient AWS_* env provably ignored"
    - "Reserve-and-wait per-(provider,secret) cache: first worker owns the call, others block on a done channel — exact once-per-secret dedup under errgroup"
    - "sanitizedError{provider,reason enum}: error paths never %w/%v the SDK/HTTP error (which may embed the token)"
key-files:
  created:
    - internal/verify/verify.go
    - internal/verify/verify_test.go
    - internal/verify/aws.go
    - internal/verify/aws_test.go
    - internal/verify/github.go
    - internal/verify/github_test.go
  modified:
    - go.mod
    - go.sum
decisions:
  - "AWS client built ONLY from passed static creds (sts.New + NewStaticCredentialsProvider, BaseEndpoint=https://sts.amazonaws.com, Region=aws-global) — NEVER config.LoadDefaultConfig (Pitfall 2: ambient creds -> false active)"
  - "aws-sdk-go-v2/config module intentionally NOT added: it is unused and importing it invites the forbidden LoadDefaultConfig path; sts+credentials+aws root suffice (lean-binary + no-ambient constraint)"
  - "Per-(provider,secret) cache uses a reserve-and-wait channel barrier so dedup is exact (one call per distinct secret) even under the 5-worker pool"
  - "Retry-After honored at most once via straight-line code (doOnce called twice), never a loop (Pitfall 3: no retry storm)"
  - "All verifier error paths return sanitizedError{provider,reason}; the SDK/HTTP error is never wrapped, so the token can never leak via an error string or log"
metrics:
  tasks_completed: 3
  files_modified: 8
  completed: 2026-05-30
---

# Phase 4 Plan 02: internal/verify Package (AWS + GitHub Live Verification) Summary

Builds the `internal/verify` network-boundary package: a `Verifier` interface, a
three-state `Status` enum, a rule-ID registry, an ambient-free static-credential
AWS STS verifier, a bare-`net/http` GitHub verifier with one-shot Retry-After
classification, and a `Run` orchestrator that dedups per (provider, secret) under
a bounded 5-worker errgroup with a 5s per-call timeout — turning the raw secret
(carried via the Plan 01 side channel) into an active/inactive/unknown label
without ever leaking the secret into a log or error.

## What Was Built

- **Checkpoint T-04-SC (pre-approved).** Re-verified the three approved
  aws-sdk-go-v2 modules resolve on the Go proxy and are first-party
  `github.com/aws/aws-sdk-go-v2` org packages, then `go get` + `go mod tidy` +
  `go mod verify` ("all modules verified"). No human pause (decision pre-granted).

- **Task 1 — interface, enum, registry, sanitizedError.** `verify.go` declares
  `Status` (`Active`/`Inactive`/`Unknown`), the `Verifier` interface
  (`Provider()` + `Verify(ctx, raw, f)`), a `registry` mapping the six VERIFIED
  rule IDs (`aws-access-token` -> aws; the five `github-*` -> github) with all
  other rule IDs absent (left unlabeled), and a `sanitizedError{provider, reason}`
  whose only fields are a provider name and a fixed `reason` enum — structurally
  incapable of holding a secret or a wrapped SDK error.

- **Task 2 — AWS verifier (provably ambient-free).** `aws.go` constructs the STS
  client DIRECTLY via `sts.New(sts.Options{Region:"aws-global",
  BaseEndpoint:aws.String("https://sts.amazonaws.com"),
  Credentials:aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(accessKeyID, secretKey, ""))})`
  — never `config.LoadDefaultConfig`. `classifyAWSError` is a pure function: nil
  -> Active; a `smithy.APIError` whose `ErrorCode()` is in
  {InvalidClientTokenId, SignatureDoesNotMatch, ExpiredToken, AccessDenied,
  InvalidSignatureException} -> Inactive; everything else (network, timeout,
  throttling, unrecognized) -> Unknown. `findSecretKey` best-effort RE2-pairs a
  40-char base64 secret key co-located near an `aws.*secret`/`secret_access_key`
  hint (nearest by line distance), with a 1 MiB read cap; a missing pair yields
  Unknown (never Inactive — Pitfall 7) and makes no call.

- **Task 3 — GitHub verifier + Run orchestrator.** `github.go` issues a bare
  `net/http` GET `https://api.github.com/user` with `Authorization: Bearer`,
  `User-Agent: mimir`, `Accept: application/vnd.github+json`,
  `X-GitHub-Api-Version: 2022-11-28` (token only in the header, never the URL),
  drains the body without decoding the username, and classifies 200->Active,
  401->Inactive, 403/429 -> honor Retry-After ONCE then Unknown (straight-line,
  no loop), network/timeout->Unknown. `Run` (in `verify.go`) uses
  `errgroup.WithContext` + `SetLimit(5)`, a per-`(provider, secret)`
  reserve-and-wait cache (first worker owns the call, others block on a `done`
  channel), a `context.WithTimeout(ctx, 5s)` per call, sets
  `findings[i].Verification = &finding.Verification{Status, Provider}` in place,
  leaves unmatched rule IDs nil, labels a missing raw secret Unknown, and ignores
  `g.Wait()`'s error (verification is label-only and never aborts the scan).

## Security Invariant Verification

- **No ambient creds (T-04-active).** Grep confirms NO `LoadDefaultConfig` call
  anywhere in the package (only doc comments naming it as forbidden). The
  `aws-sdk-go-v2/config` module is deliberately absent from go.mod.
  `TestNoAmbientCreds` injects a bogus `AWS_ACCESS_KEY_ID` via `t.Setenv` and
  asserts the static provider still resolves the passed key.
- **No secret leak (T-04-leak).** No `%w`/`%v` of any SDK/HTTP error in source
  (only a doc comment). All error paths return `sanitizedError{provider,reason}`.
  `TestNoSecretInError` and `TestGitHubErrorNoToken` assert the fixture secret
  never appears in any surfaced error or in `Verification`.
- **No token in URL (T-04-url).** Token is set only on the `Authorization`
  header; `TestGitHubHeaders` asserts the request URL never contains the token.
- **No retry storm (T-04-dos).** `errgroup.SetLimit(5)`, a single Retry-After
  honored via straight-line `doOnce`-twice (no `for` around the HTTP call), and a
  5s per-call timeout. `TestRetryAfterOnce` asserts exactly one retry then Unknown.

## Tests Added (all green under `go test -race`)

- verify: `TestRegistry`, `TestSanitizedErrorNoSecret`, `TestStatusValues`,
  `TestCacheDedup`, `TestCacheKeyIsProviderPlusSecret`, `TestRunUnlabeledRuleIsNil`,
  `TestRunMissingRawIsUnknown`, `TestNoSecretInError`.
- aws: `TestAWSClassify` (full error-code table), `TestNoAmbientCreds`,
  `TestAWSPairingMissingSecretKey`, `TestAWSPairingFindsSecretKey`.
- github: `TestGitHubClassify`, `TestGitHubHeaders`, `TestRetryAfterOnce`,
  `TestRetryAfterSucceedsSecond`, `TestGitHubTimeout`, `TestGitHubNetworkError`,
  `TestGitHubErrorNoToken`.

All GitHub tests use `httptest.NewServer`; AWS classification uses an injected
`smithy.APIError` fake — NO real network calls in the suite.

## Verification Results

- `/usr/local/go/bin/go mod verify` — "all modules verified".
- `/usr/local/go/bin/go build ./...` — succeeds (exit 0).
- `/usr/local/go/bin/go test -race ./... -count=1` — all packages pass, race-clean.
- Grep gates: no `LoadDefaultConfig` call; no `%w`/`%v` of an SDK/HTTP error in
  source; token never in a URL/query; no `for` loop around the HTTP `Do` call.

## Deviations from Plan

### Auto-fixed / lean-binary adjustments

**1. [Rule 2 / lean-binary] `aws-sdk-go-v2/config` module intentionally NOT added.**
- **Found during:** Task 1 (`go mod tidy` after wiring imports).
- **Issue:** The plan's acceptance criterion lists `aws-sdk-go-v2/config` in
  go.mod, but nothing in the package imports it. Adding it solely to satisfy a
  grep would (a) add unused supply-chain surface, contradicting the CLAUDE.md
  lean-binary constraint, and (b) put the forbidden `config.LoadDefaultConfig`
  ambient-cred path one import away — the exact Pitfall 2 the plan forbids.
- **Fix:** Kept only `service/sts` + `credentials` + the `aws` root (sufficient
  for direct static-cred client construction). `go mod verify` reports all
  modules verified; `TestNoAmbientCreds` proves the ambient path is unreachable.
- **Files modified:** go.mod, go.sum.
- **Commit:** 7e7d198.

The pinned `sts` resolved to v1.42.3 / `credentials` v1.19.19 (exactly as the
plan pinned); the transitive root resolved to aws-sdk-go-v2 v1.41.9 and
smithy-go v1.26.0 (current publish window), accepted per the checkpoint note.

## Known Stubs

None — all verifiers are fully wired. (The `cmd/mimir/scan.go` call site that
invokes `verify.Run` is Plan 04-03's scope, per the plan's `affects` list.)

## TDD Gate Compliance

Each task followed the RED-intent -> GREEN flow. The package was committed with
real (not throwaway) implementations once each task's tests passed; Task 1's
placeholder verifier bodies were replaced in-place by Tasks 2/3. Three
`feat(04-02)` commits exist (951deea, 7e7d198, 32645bf), each gated on its
task's tests passing.

## Self-Check: PASSED

- All six created files present in `internal/verify/`.
- Commits 951deea, 7e7d198, 32645bf verified in `git log`.
- `go build ./...` + `go test -race ./...` green; grep gates clean.
