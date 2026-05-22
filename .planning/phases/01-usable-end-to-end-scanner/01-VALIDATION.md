---
phase: 1
slug: usable-end-to-end-scanner
status: planned
nyquist_compliant: true
wave_0_complete: false
created: 2026-05-22
updated: 2026-05-22
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `go test` + `stretchr/testify` (require/assert) |
| **Config file** | none — `go.mod` test deps installed in Wave 1 (Plan 01-01 Task 1) |
| **Quick run command** | `go test ./... -count=1 -timeout 60s` |
| **Full suite command** | `go test -race ./... -count=1 -timeout 120s` |
| **Estimated runtime** | ~10–30 seconds (greenfield; grows with suite) |

---

## Sampling Rate

- **After every task commit:** Run `go test ./...`
- **After every plan wave:** Run `go test -race ./...`
- **Before `/gsd:verify-work`:** Full suite must be green + `go vet ./...` clean
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 01-01-T1 | 01-01 | 1 | SUP-05, OUT-03 | T-01-02 | RedactSecret() enforces prefix+last4 or [REDACTED]; no raw value in any Finding field | unit | `go test ./internal/finding/ -run TestRedact -v` | ❌ Wave 0 | ⬜ pending |
| 01-01-T2 | 01-01 | 1 | DET-01, DET-04, SCAN-01, SCAN-05 | T-01-01, T-01-02 | Aho-Corasick gate + RE2 match + binary skip + .git skip; findings redacted at boundary | unit+integration | `go test ./internal/detect/ ./internal/scanner/ -v` | ❌ Wave 0 | ⬜ pending |
| 01-01-T3 | 01-01 | 1 | IFACE-01, IFACE-02, OUT-01, OUT-03 | T-01-02, T-01-03 | Human output: compact format; raw secret not in stdout; exit codes 0/1/2 correct | smoke | `go build -o /tmp/mimir-test ./cmd/mimir && /tmp/mimir-test scan testdata/fixtures/ ; echo $?` | ❌ Wave 0 | ⬜ pending |
| 01-02-T1 | 01-02 | 2 | DET-01, DET-04 | T-02-04 | Full TOML ruleset parses cleanly; all rules RE2-validated; >= 15 rules loaded | unit | `go test ./internal/config/ -run TestRulesetParse -v` | ❌ Wave 0 | ⬜ pending |
| 01-02-T2 | 01-02 | 2 | DET-01, DET-02, DET-03, DET-04 | T-02-01, T-02-02 | All rules detect their fixture; connection-string extracts password group; --no-entropy bypass; 0 FP on clean files | unit | `go test ./internal/detect/ -run 'TestAllRules\|TestConnStr\|TestNoEntropy\|TestCleanNoFP' -v` | ❌ Wave 0 | ⬜ pending |
| 01-03-T1 | 01-03 | 2 | DET-05, CFG-01, CFG-02 | T-03-01, T-03-02 | LoadConfig precedence; extend model; RE2 rejection names offending rule; disabled_rules filter | unit | `go test ./internal/config/ -run 'TestLoadConfig\|TestExtend\|TestREValidation\|TestDiscovery' -v` | ❌ Wave 0 | ⬜ pending |
| 01-03-T2 | 01-03 | 2 | OUT-02, OUT-03, IFACE-02 | T-03-02, T-01-02 | JSON schema has fingerprint; no raw secrets in JSON; --no-color removes ANSI; all flags wired | unit+integration | `go test ./internal/output/ -v && go build -o /tmp/mimir-test ./cmd/mimir && /tmp/mimir-test scan --format json testdata/fixtures/ > /tmp/out.json ; echo $?` | ❌ Wave 0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

All of the following must be created by Plan 01-01 Task 1 before any subsequent task can run:

- [ ] `go.mod` / `go.sum` — module github.com/MatrixMagician/mimir + all deps installed
- [ ] `testdata/fixtures/known-secrets.txt` — synthetic tokens for aws-access-token (Task 1); stubs for all other rules (expanded in Plan 01-02)
- [ ] `testdata/clean/no-secrets.go` — clean Go source for FP regression testing
- [ ] `internal/finding/finding_test.go` — redaction + fingerprint stability tests
- [ ] `internal/detect/engine_test.go` — Aho-Corasick, entropy, ScanLine tests
- [ ] `internal/scanner/scanner_test.go` — binary skip, .git skip, fixture scan tests
- [ ] `internal/output/output_test.go` — human format + JSON schema + self-scan tests
- [ ] `internal/config/config_test.go` — ruleset parse, extend model, RE2 validation tests
- [ ] `cmd/mimir/scan_test.go` or integrated in `cmd/` package — exit code contract tests

Self-scan validation harness (OUT-03):
- Run scanner on `testdata/fixtures/known-secrets.txt` → capture JSON output
- Scan the JSON output as a string/file for known fixture secret values
- Assert 0 raw secrets found (all values are redacted in output)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Human-readable color/formatting appearance | OUT-01 | ANSI/TTY rendering is visual | Run `mimir scan testdata/` in a real terminal; confirm compact `path:line:col rule-id redacted` layout + color (cyan for signature rules, yellow for heuristic) + summary line |

*All other phase behaviors have automated verification.*

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify commands
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references in test commands
- [x] No watch-mode flags in any verify command
- [x] Feedback latency < 30s (all commands use `go test` with bounded timeouts)
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** pending (will be signed off after Wave 1 + Wave 2 execution)
