# SECURITY.md — Phase 4: Opt-In Live Verification (AWS + GitHub)

**Phase:** 04 — opt-in-live-verification-aws-github
**Audited:** 2026-05-30
**ASVS Level:** 1
**block_on:** high
**Status:** SECURED — 14/14 threats CLOSED

This audit verifies that every declared threat mitigation in the three plan
`<threat_model>` blocks is present in the implemented code (not just documented).
Each `mitigate` threat was confirmed by (a) the mitigation pattern present in the
cited file, and (b) the named guard test passing. The three BLOCK-WORTHY threats
(T-04-leak, T-04-active, T-04-hook) are all CLOSED.

## Threat Verification

| Threat ID | Category | Disposition | Evidence (file:line + guard) |
|-----------|----------|-------------|------------------------------|
| T-04-01 | Information Disclosure | mitigate | Raw secret carried off-struct in run-scoped `rawByFP` map keyed by fingerprint, merged under `mu.Lock` (`internal/scanner/scanner.go:80,162,169-170`); written only in `ScanLine` (`engine.go:279` sink), never on a Finding field, never marshalled. Guard `TestNoRawSecretInAnyField` PASS. |
| T-04-02 | Information Disclosure | mitigate | `Finding.Verification *Verification` pointer+omitempty (`internal/finding/finding.go:69`); `Verification` struct carries only `Status`+`Provider` enums, no secret field (`finding.go:79-84`). Guard `TestVerificationOmittedByDefault` PASS. |
| T-04-03 | Tampering | mitigate | nil Verification → omitempty drops key → byte-identical OUT-02 JSON (`internal/output/json.go`; `finding.go:69`). Guard `TestVerifyOmittedByDefault` PASS. |
| T-04-leak | Information Disclosure | mitigate | **BLOCK-WORTHY.** `sanitizedError{provider, reason}` structurally cannot hold a secret (`internal/verify/verify.go:230-237`); no `%w`/`%v` of any SDK/HTTP error in source (grep: only a doc comment at verify.go:12); GitHub token header-only (`github.go:108`). Guards `TestNoSecretInError`, `TestGitHubErrorNoToken` PASS. |
| T-04-active | Spoofing/Tampering | mitigate | **BLOCK-WORTHY.** `sts.New(sts.Options{...})` with `NewStaticCredentialsProvider` + `BaseEndpoint` pinned to `https://sts.amazonaws.com` (`internal/verify/aws.go:86-90,100`); NO `LoadDefaultConfig` (grep: only doc comments); `aws-sdk-go-v2/config` module absent from go.mod. Guard `TestNoAmbientCreds` PASS. |
| T-04-url | Information Disclosure | mitigate | Token set only on `Authorization: Bearer` header (`github.go:108`); request URL is `base+"/user"` with no token interpolation (`github.go:104`). Guard `TestGitHubHeaders` PASS. |
| T-04-dos | Denial of Service | mitigate | `errgroup` + `g.SetLimit(5)` (`verify.go:70`); per-call `context.WithTimeout(ctx, 5s)` (`verify.go:137`); Retry-After honored at most once via straight-line `doOnce`-twice, no `for` around `client.Do` (`github.go:55,78,113`); Retry-After clamped to 5s cap (`github.go:65-67`). Guards `TestRetryAfterOnce`, `TestGitHubTimeout` PASS. |
| T-04-ssrf | Tampering | accept | Fixed hosts only (`api.github.com`, `sts.amazonaws.com`); secret is the call payload, never the URL. Accepted-risk rationale recorded below. |
| T-04-SC | Tampering | mitigate | First-party `github.com/aws` modules only; blocking-human checkpoint pre-install; `go mod verify` reports "all modules verified". |
| T-04-hook | Tampering (scope creep) | mitigate | **BLOCK-WORTHY.** Hook template emits `exec mimir scan --staged` with no `--verify` (`cmd/mimir/hook.go:28`); `--verify` defaults false (`scan.go:38`). Guards: `TestHookOffline` (single declaration, hook_test.go:275) + in-line assertion (hook_test.go:62) both PASS. |
| T-04-default | Info Disclosure / DoS | mitigate | No `--verify` → `verify.Run` never called → zero network (`scan.go:168-169`). Guard `TestScanNoVerifyNoNetwork` PASS. |
| T-04-schema | Tampering | mitigate | nil Verification omitempty → byte-identical non-verify JSON. Guard `TestVerifyOmittedByDefault` PASS. |
| T-04-exit | Tampering | mitigate | `--verify` is label-only; exit block (`scan.go:234-237`) unchanged — newFindings>0 → exit 1, errors → exit 2. Asserted in `TestScanNoVerifyNoNetwork`. |
| T-04-tty | Information Disclosure | mitigate | Verification tag is a fixed enum via `verificationTag` (`internal/output/human.go:36-45`); no verifier free-string printed. Guard `TestHumanVerificationTag` PASS. |

## Unregistered Flags

None. No `## Threat Flags` section appears in any 04-0x-SUMMARY.md. The 04-03
"Threat Surface Notes" prose explicitly states no new network endpoints, auth
paths, or trust-boundary surface were introduced beyond Plan 02's registered
threat_model. No new attack surface requires registration.

## Accepted Risks Log

- **T-04-ssrf (Tampering — fixed hosts).** Verification calls target only the two
  hardcoded provider hosts `api.github.com` and `sts.amazonaws.com`. The detected
  secret is the request *payload* (Authorization header / SigV4 credential), never
  any part of the destination URL, so scanned repository content cannot redirect a
  call to an attacker-controlled host. Residual SSRF risk is low and accepted for
  v1. Disposition authored at plan time (04-02 threat_model).

## Independent Code Review Cross-Check (no security regression)

A prior deep code review (04-REVIEW.md) found and fixed two blockers; both fixes
were re-verified here to confirm they preserve the security invariants:

- **CR-01 (panic deadlock).** `verify.go:130-140` now wraps the cache-owner call in
  a closure with `defer close(entry.done)` + `recover()→Unknown`. A panicking
  verifier can no longer park waiters or hang `g.Wait()`. Guard
  `TestPanicDoesNotDeadlock` PASS; package race-clean. No secret-leak or
  no-fail-the-scan invariant weakened.
- **CR-02 (scanRoot path).** `scanRoot` is threaded `Run → Verifier.Verify`
  (`verify.go:62,189`) and the AWS verifier resolves
  `filepath.Join(scanRoot, filepath.FromSlash(f.File))` (`aws.go:80`). The
  `scanRoot` value is the same `resolveScanRoot(paths)` used for config loading
  (`scan.go:55,174`), so resolution is consistent. `--git`/`--staged` findings with
  no on-disk counterpart degrade to Unknown, never a false `inactive`. Guard
  `TestAWSVerifyResolvesScanRoot` PASS.

Verification gate re-run during this audit:
`go mod verify` (all modules verified); `go test -race` on internal/verify,
internal/finding, internal/output, and the verify-related cmd tests — all green.

## Conclusion

All 14 declared mitigations are present in the implemented code with passing guard
tests. The three BLOCK-WORTHY threats are CLOSED. No unregistered attack surface.
The one accepted risk (T-04-ssrf) is documented above. Phase 4 is cleared to ship
from a threat-mitigation standpoint at ASVS Level 1.
