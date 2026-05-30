---
phase: 01-usable-end-to-end-scanner
plan: "01"
subsystem: scanner
tags: [go, cobra, aho-corasick, re2, entropy, cli, secret-scanning]

requires: []
provides:
  - Walking Skeleton: full end-to-end secret-scan pipeline (file walk -> Aho-Corasick -> RE2 -> entropy -> redacted Finding -> human output -> exit codes)
  - finding.New() redact-at-boundary constructor with fingerprint (sha256 prefix)
  - Detection engine with keyword pre-filter, regex match, Shannon entropy gate, allowlists
  - Concurrent file scanner with errgroup worker pool; binary/.git/oversized-file skip
  - Human formatter: compact path:line:col  rule-id  secret output + stats summary
  - Exit-code contract: 0 clean / 1 findings / 2 error; --exit-zero soft mode; --quiet flag
  - go test ./... coverage for finding, detect, scanner, output, and cmd packages
affects: [02-ruleset-expansion, 03-config, plan-02, plan-03]

tech-stack:
  added:
    - github.com/spf13/cobra v1.10.2 (CLI subcommands)
    - github.com/pelletier/go-toml/v2 v2.3.1 (TOML config parsing)
    - github.com/BobuSumisu/aho-corasick v1.0.3 (keyword pre-filter)
    - golang.org/x/sync v0.20.0 (errgroup worker pool)
    - github.com/fatih/color v1.19.0 (ANSI output; NO_COLOR aware)
    - github.com/stretchr/testify v1.11.1 (test assertions)
  patterns:
    - Redact-at-boundary: raw secret used only for fingerprint + redaction in finding.New(), never stored in any exported field
    - Aho-Corasick keyword gate before RE2 regex: fast-path skip lines with no rule keywords
    - errgroup.WithContext + SetLimit(GOMAXPROCS) for bounded-concurrency file scanning
    - go:embed for zero-dep embedded default ruleset (config/mimir.toml -> config.DefaultConfig)
    - SilenceErrors+SilenceUsage on root cobra command; os.Exit(2) on fatal errors
    - Black-box cmd tests via TestMain-built binary + os/exec; avoids os.Exit interference
    - Findings sorted deterministically (File -> Line -> Column) before output

key-files:
  created:
    - internal/finding/finding.go
    - internal/finding/finding_test.go
    - internal/detect/engine.go
    - internal/detect/entropy.go
    - internal/detect/engine_test.go
    - internal/scanner/scanner.go
    - internal/scanner/binary.go
    - internal/scanner/scanner_test.go
    - internal/config/config.go
    - internal/output/human.go
    - internal/output/output_test.go
    - cmd/mimir/scan.go
    - cmd/mimir/scan_test.go
    - cmd/mimir/root.go
    - cmd/mimir/version.go
    - config/embed.go
    - config/mimir.toml
    - main.go
    - testdata/fixtures/known-secrets.txt
    - testdata/clean/no-secrets.go
  modified: []

key-decisions:
  - "Binary is built from root main.go (package main), not ./cmd/mimir (package cmd) — cmd/ is a library package; go build . produces the executable"
  - "cmd tests use TestMain to build binary + os/exec for black-box testing — in-process testing is blocked by os.Exit calls in runScan"
  - "go:embed in config/ package (not internal/config) to avoid cross-package embed restriction"
  - "ScanLine operates on the original (not lowercased) line for regex matching; only the trie query uses lowercased input"
  - "formatDuration uses sub-100ms display in ms and >=100ms display in decimal seconds"

patterns-established:
  - "Redact-at-boundary: finding.New() is the ONLY entry point to create a Finding; rawSecret never stored"
  - "Aho-Corasick pre-filter: ScanLine returns nil immediately if no keyword matched (fast path)"
  - "Deterministic output: sort findings by File/Line/Column before WriteHuman"
  - "Error routing: findings + summary to stdout; diagnostics to stderr; os.Exit(2) for fatal errors"

requirements-completed: [DET-01, DET-04, SCAN-01, SCAN-02, SCAN-05, IFACE-01, IFACE-02, OUT-01, OUT-03, SUP-05]

duration: ~45min
completed: 2026-05-22
---

# Phase 01 Plan 01: Walking Skeleton Summary

**Go secret scanner pipeline: Aho-Corasick keyword gate + RE2 aws-access-token rule + redact-at-boundary Finding constructor + concurrent file scanner + human output formatter + exit-code contract (0/1/2)**

## Performance

- **Duration:** ~45 min
- **Started:** 2026-05-22
- **Completed:** 2026-05-22
- **Tasks:** 3
- **Files modified:** 19

## Accomplishments

- Full end-to-end walking skeleton: `mimir scan testdata/fixtures/` produces a redacted finding and exits 1; clean scan exits 0
- Redact-at-boundary invariant enforced at finding.New() and tested with reflect-inspection; no raw secret ever reaches any output channel
- Aho-Corasick keyword pre-filter gates all RE2 regex evaluation for performance; Shannon entropy check rejects low-entropy matches
- Concurrent scanner with errgroup worker pool (capped at GOMAXPROCS); binary/. git/oversized-file skip
- Human formatter: compact `path:line:col  rule-id  redacted-secret` + stats summary; --quiet suppresses summary; fatih/color with NO_COLOR support
- Exit-code contract: 0=clean / 1=findings / 2=error; --exit-zero soft mode for CI pipelines
- go test ./... with 52 tests all passing (race-free)

## Task Commits

1. **Task 1: Project scaffold + Finding data model + test fixtures** - `d6ec422` (feat)
2. **Task 2: Detection engine + file scanner + entropy** - `0cb0fff` (feat)
3. **Task 3: CLI wire-up + human output + exit-code tests** - `8211b13` (feat)

## Files Created/Modified

- `main.go` - Entry point calling cmd.Execute()
- `cmd/mimir/root.go` - rootCmd with SilenceErrors/SilenceUsage + --no-color flag
- `cmd/mimir/scan.go` - scan subcommand: path resolution, scanner invocation, output, exit codes
- `cmd/mimir/scan_test.go` - Black-box exit-code contract tests via TestMain-built binary
- `cmd/mimir/version.go` - version subcommand
- `config/embed.go` - //go:embed mimir.toml -> DefaultConfig []byte
- `config/mimir.toml` - Embedded TOML: aws-access-token rule + global allowlists
- `internal/finding/finding.go` - Finding struct + RedactSecret() + computeFingerprint() + New()
- `internal/finding/finding_test.go` - Redaction + fingerprint stability + reflect raw-secret scan
- `internal/detect/engine.go` - Engine with Aho-Corasick trie + ScanLine()
- `internal/detect/entropy.go` - shannonEntropy(string) float64
- `internal/detect/engine_test.go` - Engine unit tests
- `internal/scanner/scanner.go` - Scanner.Scan() with errgroup pool + WalkDir
- `internal/scanner/binary.go` - isBinary() NUL-byte heuristic
- `internal/scanner/scanner_test.go` - Scanner integration tests
- `internal/config/config.go` - Rule/Config structs + LoadDefault()
- `internal/output/human.go` - WriteHuman() formatter
- `internal/output/output_test.go` - WriteHuman unit tests
- `testdata/fixtures/known-secrets.txt` - Synthetic AWS key fixtures
- `testdata/clean/no-secrets.go` - Clean file for false-positive regression

## Decisions Made

- **Binary entrypoint at root main.go, not ./cmd/mimir**: cmd/ is `package cmd` (library). `go build .` produces the executable. Prior executor runs tried `go build ./cmd/mimir` and got an ar archive — this was the root cause of the test failures discovered and fixed in this run.
- **Black-box cmd tests via TestMain + os/exec**: runScan calls `os.Exit()` directly, making in-process testing unreliable. TestMain builds the binary once; all tests use os/exec with a compile-time constant path `/tmp/mimir-cmd-test`.
- **go:embed in config/ not internal/config**: The embed directive must be in the same package as the file being embedded. config/embed.go and config/mimir.toml coexist as `package config`.
- **ScanLine uses original line for regex, lowercased only for trie**: Trie query uses `strings.ToLower(line)` for case-insensitive keyword matching; regex applied to original line to correctly extract the token.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Build target was ./cmd/mimir (package archive) not . (executable)**
- **Found during:** Task 3 verification
- **Issue:** cmd/mimir is `package cmd`, not `package main`. `go build ./cmd/mimir` produces an ar archive, not an executable binary. This blocked all integration tests and the smoke-test verification steps.
- **Fix:** Changed build target to `.` (root main.go is `package main`). Updated scan_test.go TestMain to build from `.`.
- **Files modified:** cmd/mimir/scan_test.go
- **Verification:** `go build -o /tmp/mimir-real .` produces ELF executable; `go test ./cmd/... -count=1` passes 8 tests.
- **Committed in:** 8211b13 (Task 3 commit)

---

**Total deviations:** 1 auto-fixed (Rule 3 - blocking)
**Impact on plan:** Essential fix for test infrastructure. No scope creep.

## Issues Encountered

- semgrep hook rejected scan_test.go for using a variable path in exec.Command (CWE-94). Fixed by making the binary path a compile-time constant (`const mimirTestBin = "/tmp/mimir-cmd-test"`).
- Build cache contained a stale ar archive entry for the binary path; `go clean -cache` and cache deletion did not help because the root issue was the wrong build target, not cache corruption.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Walking Skeleton complete: full pipeline proven end-to-end with aws-access-token rule
- Plan 02 can add more signature rules to config/mimir.toml and engine_test.go without architectural changes
- Plan 03 can wire full config discovery (LoadConfig with project config file support)
- Known limitation: only aws-access-token rule active; Plan 02 adds the full ruleset

---
*Phase: 01-usable-end-to-end-scanner*
*Completed: 2026-05-22*
