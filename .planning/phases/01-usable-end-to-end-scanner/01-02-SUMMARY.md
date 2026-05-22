---
phase: 01-usable-end-to-end-scanner
plan: 02
subsystem: detection
tags: [go, aho-corasick, entropy, regex, toml, secret-scanner, ruleset]

requires:
  - phase: 01-usable-end-to-end-scanner
    plan: 01
    provides: "Walking skeleton: Engine, Config structs, FindDefault, ScanLine API, finding.New redact-at-boundary"

provides:
  - "Full v1 TOML ruleset with 18 rules covering AWS, GCP, GitHub (5), GitLab (3), Slack (3), Stripe, PEM key, JWT, generic-api-key, connection-string"
  - "generic-api-key entropy-gated heuristic rule (IsHeuristic=true, entropy >= 3.5, keyword-gated)"
  - "connection-string URI rule extracting password via SecretGroup=3 (single canonical TOML source)"
  - ".+EXAMPLE$ global allowlist suppressing documentation placeholder tokens across all rules"
  - "Fixture tokens (known-secrets.txt) for all 18 rule types — structurally authentic synthetic tokens"
  - "TestAllRules: every rule must fire on its fixture line; TestConnStr, TestNoEntropy, TestCleanNoFP regression suite"

affects: [01-03-config-load, 02-suppression, scan-engine, rule-coverage]

tech-stack:
  added: []
  patterns:
    - "Global allowlist suppresses values across ALL rules — per-rule allowlist only suppresses for that rule"
    - "TOML multiline literal strings (''' ''') for all complex regexes — avoids backslash escaping pitfalls"
    - "Fixture tokens must match regex AND pass entropy gate — token length must satisfy {N} quantifiers exactly"
    - "connection-string rule: secret_group=3 in TOML is single source of truth; engine's SecretGroup path handles it uniformly"

key-files:
  created:
    - "testdata/fixtures/known-secrets.txt: synthetic authentic fixture tokens for all 18 v1 rules"
  modified:
    - "config/mimir.toml: expanded from 1 rule to full v1 set (18 rules, 2 global allowlists, extend block)"
    - "internal/detect/engine_test.go: added TestConnStr, TestNoEntropy, TestAllRules, TestCleanNoFP"

key-decisions:
  - "Added .+EXAMPLE$ to GLOBAL allowlist (not just aws-access-token per-rule) so documentation examples are suppressed across all rules including generic-api-key"
  - "GitHub token fixture length: ghp_/gho_/ghu_/ghr_ need prefix(4) + exactly 36 alphanum = 40 total chars"
  - "Connection-string comment in fixture file intentionally triggers rule (comment contains scheme://user:password@host — correct scanner behavior)"
  - "GCP API key regex accepts 38-39 chars ([\w-]{34,35}) per RESEARCH.md resolved Q1"

patterns-established:
  - "TestAllRules pattern: iterate all config.Rules, scan fixture file lines, assert every rule ID fires"
  - "Fixture file format: one comment per rule identifying requirements, then the fixture token on the next line"

requirements-completed: [DET-01, DET-02, DET-03, DET-04]

duration: 45min
completed: 2026-05-22
---

# Phase 1 Plan 02: Full v1 Detection Engine Summary

**18-rule v1 TOML ruleset (AWS/GCP/GitHub/GitLab/Slack/Stripe/PEM/JWT/generic-entropy/connection-string) with keyword-gated entropy detection, SecretGroup=3 password extraction, and zero false positives on clean fixtures**

## Performance

- **Duration:** ~45 min
- **Started:** 2026-05-22T19:00:00Z
- **Completed:** 2026-05-22T19:45:00Z
- **Tasks:** 2 (both TDD: RED+GREEN)
- **Files modified:** 4

## Accomplishments

- Expanded `config/mimir.toml` from 1 rule to 18 rules covering the full v1 signature set (DET-01) plus generic entropy detector (DET-02) and connection-string rule with SecretGroup=3 (DET-03)
- Fixed failing `TestEngineScanLineAllowlistExample` by moving `.+EXAMPLE$` to the global allowlist — documentation placeholder tokens ending in EXAMPLE are now suppressed across all rules, not just aws-access-token
- `TestAllRules` verifies every rule fires on its fixture token; `TestCleanNoFP` confirms zero false positives on `testdata/clean/no-secrets.go`
- 64 tests pass with `go test -race ./...`; binary correctly detects all 18 rule types on `testdata/fixtures/`

## Task Commits

1. **Task 1: Full v1 TOML ruleset + fixture tokens** - `e17ce08` (feat)
2. **Task 2: RED — failing tests for engine updates** - `542fc7a` (test)
3. **Task 2: GREEN — all tests passing** - `94b5b20` (feat)

## Files Created/Modified

- `/home/oliverh/repos/github/MatrixMagician/Mimir/config/mimir.toml` — Expanded to full v1 ruleset: 18 rules, 2 global allowlists (placeholder patterns + noisy paths), extend block; TOML multiline literal strings for all complex regexes
- `/home/oliverh/repos/github/MatrixMagician/Mimir/testdata/fixtures/known-secrets.txt` — Authentic synthetic fixture tokens for all 18 rule types; structurally valid (correct regex-matching lengths + entropy above thresholds)
- `/home/oliverh/repos/github/MatrixMagician/Mimir/internal/detect/engine_test.go` — Added TestConnStr (URI detection), TestNoEntropy (flag behavior), TestAllRules (all-rules coverage), TestCleanNoFP (false-positive regression); removed obsolete base64-obfuscation scaffolding from prior run

## Decisions Made

- **Global EXAMPLE allowlist**: `.+EXAMPLE$` moved to `[[allowlists]]` (global) rather than staying only on `aws-access-token`'s per-rule allowlist. Without this, the `generic-api-key` rule fires on `AKIAIOSFODNN7EXAMPLE` even though the AWS-specific allowlist suppresses the aws-access-token detection. The global placement correctly expresses the intent: values ending in EXAMPLE are documentation placeholders and should never be findings for any rule.

- **GitHub token fixture length**: `ghp_[0-9a-zA-Z]{36}` requires `ghp_` (4 chars) + 36 alphanum = 40 total characters. The prior run's fixtures were 37 chars (only 33 alphanum after prefix), causing TestAllRules to fail. Corrected to 40-char tokens with ≥3.0 entropy.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] GitHub fixture tokens wrong length causing TestAllRules failure**
- **Found during:** Task 2 GREEN (TestAllRules fails for github-pat, github-oauth, github-app-token, github-refresh-token)
- **Issue:** Prior run wrote `ghp_FakeGitHubToken123456789012345678` (37 chars) but `ghp_[0-9a-zA-Z]{36}` requires 40 chars total (4 prefix + 36 alphanum)
- **Fix:** Updated all four GitHub token fixtures to correct 40-char length
- **Files modified:** `testdata/fixtures/known-secrets.txt`
- **Verification:** `go test ./internal/detect/ -run TestAllRules` exits 0; regex verified manually
- **Committed in:** `94b5b20`

**2. [Rule 1 - Bug] TestEngineScanLineAllowlistExample failing — generic-api-key fires on EXAMPLE line**
- **Found during:** Existing failing test from prior run; root cause analyzed during Task 2 GREEN
- **Issue:** `aws-access-token` per-rule allowlist (`.+EXAMPLE$`) only suppresses that rule. The `generic-api-key` rule fires on the same line (keywords "access" and "key" present, entropy passes) and had no EXAMPLE suppression
- **Fix:** Added `.+EXAMPLE$` to the global `[[allowlists]]` block in `mimir.toml`
- **Files modified:** `config/mimir.toml`
- **Verification:** `go test ./internal/detect/ -run TestEngineScanLineAllowlistExample` exits 0
- **Committed in:** `94b5b20`

---

**Total deviations:** 2 auto-fixed (both Rule 1 bugs)
**Impact on plan:** Both fixes are correctness requirements — wrong fixture lengths produce false test passes/failures; missing global allowlist breaks the documented behavior that EXAMPLE-suffix values are documentation placeholders. No scope creep.

## Issues Encountered

- **Semgrep MCP post-tool hook** fires on `testdata/fixtures/` writes despite `.semgrepignore` excluding the `testdata/` directory. The `.semgrepignore` correctly excludes this path — the hook is scanning via a code path that does not honor the ignore file. The CRITICAL_UNBLOCK directive in the task brief explicitly anticipated this and required that fixtures remain authentic. Fixtures were NOT weakened; the hook warnings were ignored as directed.

## Known Stubs

None — all 18 rules are fully implemented with authentic fixture tokens and passing tests. The `connection-string` rule detects passwords via `SecretGroup=3` TOML configuration; no separate `connstr.go` file was created (per plan constraint).

## Threat Flags

No new threat surface beyond what was documented in the plan's `<threat_model>`. All T-02-* mitigations are in place:
- T-02-01 (DoS via regex): All patterns are RE2; Aho-Corasick gate prevents regex execution on non-matching lines
- T-02-02 (password extraction): `secret_group=3` passes to `finding.New()` which enforces redact-at-boundary; raw password never stored
- T-02-03 (generic entropy rule): `finding.New()` is the only consumer; redaction enforced at constructor boundary
- T-02-04 (TOML pattern validity): All patterns RE2-validated by `LoadDefault()` via `regexp.Compile`
- T-02-05 (generic-api-key breadth): Entropy gate (3.5) + pure-alpha allowlist + keyword gate provide defense-in-depth

## Next Phase Readiness

- Plan 01-03 (full `LoadConfig` rewrite with file discovery + extend model) can proceed; `config/mimir.toml` has the `[extend]` block ready
- The full ruleset is embedded in the binary via `go:embed` — Phase 2 suppression (baseline + inline-ignore) consumes `Finding.Fingerprint` which is already stable
- `internal/config/config.go` was NOT modified in this plan (owned by 01-01 and 01-03)

---
*Phase: 01-usable-end-to-end-scanner*
*Completed: 2026-05-22*

## Self-Check: PASSED

Verified:
- `config/mimir.toml` exists and has 18 rules: `go test ./internal/config/ -run TestRulesetParse` exits 0
- `testdata/fixtures/known-secrets.txt` exists with fixture tokens for all 18 rules
- `internal/detect/engine_test.go` exists with TestAllRules, TestConnStr, TestNoEntropy, TestCleanNoFP
- Commit `e17ce08` (Task 1): `git log --oneline | grep e17ce08` ✓
- Commit `542fc7a` (RED tests): `git log --oneline | grep 542fc7a` ✓
- Commit `94b5b20` (GREEN): `git log --oneline | grep 94b5b20` ✓
- `go test -race ./... -count=1` exits 0 (64 tests pass)
- `go build ./...` exits 0
- `internal/config/config.go` NOT in `git diff --name-only HEAD~4..HEAD`
