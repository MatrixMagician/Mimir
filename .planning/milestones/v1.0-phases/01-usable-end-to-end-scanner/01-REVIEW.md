---
phase: 01-usable-end-to-end-scanner
reviewed: 2026-05-22T00:00:00Z
depth: deep
files_reviewed: 16
files_reviewed_list:
  - main.go
  - cmd/mimir/root.go
  - cmd/mimir/scan.go
  - cmd/mimir/scan_test.go
  - cmd/mimir/version.go
  - config/embed.go
  - config/mimir.toml
  - internal/config/config.go
  - internal/config/config_test.go
  - internal/detect/engine.go
  - internal/detect/engine_test.go
  - internal/detect/entropy.go
  - internal/finding/finding.go
  - internal/finding/finding_test.go
  - internal/output/human.go
  - internal/output/json.go
  - internal/output/output_test.go
  - internal/scanner/binary.go
  - internal/scanner/scanner.go
  - internal/scanner/scanner_test.go
findings:
  critical: 0
  warning: 6
  info: 4
  total: 10
status: issues_found
---

# Phase 01: Code Review Report

**Reviewed:** 2026-05-22
**Depth:** deep
**Files Reviewed:** 20
**Status:** issues_found

## Summary

Phase 1 delivers a solid foundation. The redact-at-boundary invariant is correctly
implemented and well-tested: `finding.New()` uses rawSecret only to compute the
fingerprint and the redacted representation, never stores it, and the reflect-based
regression test in `finding_test.go` enforces this contract across all exported string
fields. The detection pipeline (Aho-Corasick keyword gate → RE2 regex → entropy →
allowlist → `finding.New()`) is correctly structured and the engine never logs or
stores the raw secret. The locked stack (cobra, go-toml/v2, x/sync errgroup, stdlib
regexp, fatih/color) is respected; no viper, no regexp2, no go-git.

The issues found are correctness defects and quality gaps — none rise to a security
vulnerability. The most impactful are the goroutine leak on multi-path error and the
silent acceptance of unknown `--format` values. Both are fixable in a few lines.

---

## Warnings

### WR-01: Goroutine leak when multi-path scan fails mid-walk

**File:** `internal/scanner/scanner.go:127-129`

**Issue:** `Scan()` iterates `paths` in a `for` loop, calling `filepath.WalkDir` for
each. The WalkDir callback submits file-scan tasks to an `errgroup` via `g.Go()`. If
the walk of `paths[N]` returns a fatal error (e.g. path does not exist), the function
returns early at line 128 — skipping `g.Wait()`. Goroutines already submitted by
`paths[0..N-1]` continue to run, writing to `allFindings` through the mutex closure
they captured. Those goroutines are orphaned: the caller receives an error and no
findings, while background goroutines hold file descriptors and CPU until they
naturally complete.

For the CLI (where `os.Exit(2)` terminates the process immediately), this is
inconsequential. For programmatic / test use of `scanner.Scan()` with multiple paths,
it is a real goroutine and resource leak. The multi-path scenario is not unit-tested,
so the leak is invisible in the current test suite.

**Fix:**
```go
// Option A: cancel the errgroup context on early return
// (errgroup context is already g's derived context — pass it to scanFile via ctx)
// In Scan(), before the multi-path loop:
g, gCtx := errgroup.WithContext(ctx)
g.SetLimit(runtime.GOMAXPROCS(0))

// On early walkErr return, call g.Wait() to drain the pool:
if walkErr != nil {
    _ = g.Wait() // drain in-flight goroutines before returning
    return nil, Stats{}, walkErr
}
```

Calling `g.Wait()` after a `walkErr` drains in-flight goroutines (they all return
`nil` since file-scan errors are non-fatal) before the function returns, eliminating
the leak.

---

### WR-02: Unknown `--format` value silently falls through to human output

**File:** `cmd/mimir/scan.go:79`

**Issue:** The `format` flag is documented as accepting `"human"` or `"json"`. Any
other value (e.g. `--format sarif`, `--format xml`, typo `--format jsn`) is silently
treated as human output instead of returning exit code 2. A CI pipeline passing
`--format` to a future-format that has not shipped yet would get human output piped
to a JSON parser — a hard-to-diagnose failure mode.

```go
// current code:
if format == "json" {
    // ...
} else {
    output.WriteHuman(os.Stdout, findings, stats, noColor, quiet)
}
```

**Fix:**
```go
switch format {
case "json":
    if err := output.WriteJSON(os.Stdout, findings, stats); err != nil {
        fmt.Fprintln(os.Stderr, "error encoding JSON:", err)
        os.Exit(2)
    }
case "human":
    output.WriteHuman(os.Stdout, findings, stats, noColor, quiet)
default:
    fmt.Fprintf(os.Stderr, "error: unknown output format %q (valid: human, json)\n", format)
    os.Exit(2)
}
```

---

### WR-03: `os.Exit()` called inside cobra `RunE` prevents unit-testing and deferred cleanup

**File:** `cmd/mimir/scan.go:48, 69, 83, 93`

**Issue:** `runScan` (the cobra `RunE` handler) calls `os.Exit()` directly on error
rather than returning an error to cobra. This has two consequences:
1. `defer` statements in any caller above `runScan` do not execute (not a current
   issue since the call chain has no defers, but a landmine for future code).
2. The function cannot be unit-tested without subprocess execution (`exec.Command`),
   which is why `scan_test.go` builds and forks the binary rather than calling
   `runScan` directly.

The correct cobra pattern is to return errors from `RunE` and let `Execute()` handle
printing + exit code. Exit codes other than 0/1/2 can be handled by wrapping the
cobra error type or using `cobra.Command.SilenceErrors`.

**Fix:** Use a sentinel exit-code error type:
```go
type exitCodeError struct{ code int }
func (e exitCodeError) Error() string { return fmt.Sprintf("exit code %d", e.code) }

// In Execute():
if err := rootCmd.Execute(); err != nil {
    var ec exitCodeError
    if errors.As(err, &ec) {
        os.Exit(ec.code)
    }
    fmt.Fprintln(os.Stderr, "error:", err)
    os.Exit(2)
}

// In runScan — return errors instead of os.Exit():
if err := cfg err; err != nil {
    return fmt.Errorf("config: %w", exitCodeError{2})
}
```

This is a refactor, not a blocker for v1 CLI use, but should be addressed before the
scanner is used as a library or before more complex cobra middleware is added.

---

### WR-04: `color.NoColor` global permanently mutated in `WriteHuman`

**File:** `internal/output/human.go:30`

**Issue:** `WriteHuman` mutates the package-level global `color.NoColor = true` when
`noColor` is true, but never resets it. This mutation is permanent for the process
lifetime. Consequences:

1. If `WriteHuman(w, findings, stats, noColor=true, ...)` is called first, any
   subsequent call with `noColor=false` will still produce colorless output because
   the global was permanently flipped.
2. Tests that set `color.NoColor = true` directly at test-level (as done in
   `output_test.go`) will bleed that state into any test running concurrently in the
   same package (though currently no tests use `t.Parallel()`, so this is latent).

**Fix:**
```go
func WriteHuman(w io.Writer, findings []finding.Finding, stats scanner.Stats, noColor bool, quiet bool) {
    // Honor caller's noColor without mutating the global permanently
    prevNoColor := color.NoColor
    if noColor {
        color.NoColor = true
    }
    defer func() { color.NoColor = prevNoColor }()
    // ... rest of function
}
```

---

### WR-05: `Finding.Description` and `Finding.Entropy` fields declared but never populated

**File:** `internal/finding/finding.go:27,34` and `internal/detect/engine.go:144`

**Issue:** The `Finding` struct declares two fields that appear in the JSON schema but
are never set by `finding.New()` or the engine:

- `Description string` — always `""` (omitted from JSON due to `omitempty`). The
  matched rule's description (`config.Rule.Description`) is available in the engine
  but not passed to `finding.New()`.
- `Entropy float32` — always `0.0` (omitted from JSON due to `omitempty`). The
  computed Shannon entropy of the matched secret is not stored despite being
  calculated in the engine.

Both fields appear in the documented JSON schema (`"description,omitempty"`,
`"entropy,omitempty"`), creating a schema promise that is never fulfilled. Downstream
tools relying on these fields for triage (e.g. filtering on entropy > 4.0) will see
only zero values.

**Fix:** Pass description and entropy through `finding.New()`:
```go
// finding.go — extend signature:
func New(ruleID, description, file string, line, col int, rawSecret, matchContext string,
         entropy float32, isHeuristic bool) Finding {
    // ...
    return Finding{
        // ...
        Description: description,
        Entropy:     entropy,
    }
}

// engine.go — call site:
entropyVal := float32(shannonEntropy(rawSecret))
f := finding.New(rule.ID, rule.Description, filePath, lineNum, col,
                 rawSecret, fullMatch, entropyVal, rule.IsHeuristic)
```

---

### WR-06: Production dependencies classified as `// indirect` in `go.mod`

**File:** `go.mod:8-18`

**Issue:** All production dependencies except `testify` are marked `// indirect` in
`go.mod`. These packages are imported directly by production source files:

| Package | Used in |
|---------|---------|
| `github.com/BobuSumisu/aho-corasick` | `internal/detect/engine.go` |
| `github.com/fatih/color` | `internal/output/human.go` |
| `github.com/pelletier/go-toml/v2` | `internal/config/config.go` |
| `github.com/spf13/cobra` | `cmd/mimir/root.go`, `scan.go`, `version.go` |
| `golang.org/x/sync` | `internal/scanner/scanner.go` |

`go mod tidy` would promote these to direct dependencies. As-is, `go mod tidy` in CI
will modify `go.mod`, causing a diff that may fail CI checks enforcing `go mod tidy`
compliance.

**Fix:** Run `go mod tidy` to correct the classification.

---

## Info

### IN-01: `string(rune('0'+lineNum))` produces garbage for `lineNum >= 10` in test error messages

**File:** `internal/detect/engine_test.go:265`

**Issue:** The error-message builder in `TestCleanNoFP` uses:
```go
"line " + string(rune('0'+lineNum)) + " rule " + finding.RuleID
```
This converts lineNum to a single digit character by adding its value to the rune
`'0'` (ASCII 48). This only produces a valid decimal digit for `lineNum` 1–9. For
`lineNum = 10`, `rune('0'+10) = ':'` (ASCII 58); for 11 → `';'`; etc. Any finding on
line 10 or beyond in `no-secrets.go` would produce an error message like `"line : rule
..."`.

The assertion logic (`assert.Empty(t, allFindings)`) is correct and unaffected — this
is purely an error-message quality defect that makes test failures harder to diagnose.

**Fix:**
```go
// Use fmt.Sprintf instead of rune arithmetic:
allFindings = append(allFindings, fmt.Sprintf("line %d rule %s", lineNum, finding.RuleID))
```

---

### IN-02: `loadFromBytes` duplicates `loadFromFileBytes` logic and is only used in tests

**File:** `internal/config/config.go:266-274`

**Issue:** `loadFromBytes` (unexported) is used only by `config_test.go`. It performs
`parseBytes(data)` + `compile(raw)` — the same two steps as the body of
`loadFromFileBytes` when `UseDefault` is false. The duplicate function exists alongside
`loadFromFileBytes` without adding any new behavior.

**Fix:** Replace the one call-site in `config_test.go` with `loadFromFileBytes`:
```go
// config_test.go:90 — currently:
_, err := loadFromBytes(invalidTOML)
// Change to:
_, err := loadFromFileBytes(invalidTOML)
```
Then delete `loadFromBytes`. `loadFromFileBytes` handles the same case (non-extend
TOML bytes → parse + compile).

---

### IN-03: JWT keyword `"ey"` causes excessive Aho-Corasick trie hits

**File:** `config/mimir.toml:143`

**Issue:** The JWT rule uses keyword `"ey"` which is a suffix or substring of common
English words: "key", "they", "every", "monkey", "money", "grey", etc. Every line
containing these words will pass the Aho-Corasick gate and trigger the JWT regex match
attempt. The regex itself is well-anchored (`\b(ey[a-zA-Z0-9]{17,}\. ...)\b`) and
will correctly reject non-JWT matches, so there are no false-positive findings.
However, the keyword is so broad that the pre-filter provides little benefit for JWT:
a large fraction of all lines in source files will trigger it.

**Fix:** Use a more specific keyword. JWT headers always begin with `eyJ` (base64 of
`{"`) or `eyI` (base64 of `{"`). Replace `"ey"` with `"eyj"` to reduce trie hit rate
by an order of magnitude without missing real JWTs:
```toml
keywords = ["eyj"]
```

---

### IN-04: Default `config/mimir.toml` contains a self-referential `[extend]` block that is silently ignored

**File:** `config/mimir.toml:170-172`

**Issue:** The embedded default config ends with:
```toml
[extend]
use_default = true
disabled_rules = []
```
When `LoadDefault()` is called, it invokes `parseBytes()` then `compile()`. The
`compile()` function does not examine the `extend` block, so `use_default = true` here
has no effect. This is correct behavior (avoiding infinite self-reference), but the
block is confusing: it looks like the default config extends itself. A developer
reading the file might expect this triggers the extend mechanism.

**Fix:** Remove the `[extend]` block from `config/mimir.toml` — it serves no purpose
in the default config and will not be processed by `LoadDefault()`. Document the
extend mechanism only in user-facing config examples.

---

## Redaction Correctness Assessment

The redact-at-boundary invariant is correctly implemented. Audited paths:

- **`finding.New()`:** rawSecret used only for `computeFingerprint()` (hashes it,
  stores only 16-hex prefix) and `RedactSecret()`. Not stored in any field.
- **`RedactSecret()`:** D-05 guardrail (`len < 16 → "[REDACTED]"`) is correct. The
  threshold check uses byte length (`len(secret)`), which is appropriate for
  predominantly ASCII secret formats (AWS keys, GitHub tokens, etc.).
- **Match context redaction:** `strings.ReplaceAll(matchContext, rawSecret, ...)` is a
  literal string replacement — immune to regex injection from rawSecret content.
- **JSON output (`WriteJSON`):** uses `encoding/json` on already-redacted `Finding`
  structs. No raw value present.
- **Human output (`WriteHuman`):** prints `f.Secret` (always redacted). No raw value
  present.
- **Error messages:** no error path in the codebase passes rawSecret to `fmt.Errorf`
  or `os.Stderr`.
- **`TestNoRawSecretInAnyField`:** the reflect-inspection test is a solid regression
  guard covering all exported string fields.

No raw secret escape path was found.

## Exit-Code Contract Assessment (IFACE-02)

- Exit 0 (clean): `len(findings) == 0` → `runScan` returns nil → cobra exits 0. Correct.
- Exit 1 (findings): `len(findings) > 0 && !exitZero` → `os.Exit(1)`. Correct.
- Exit 2 (error): config load error, scan error, JSON write error → `os.Exit(2)`. Correct.
- `--exit-zero`: suppresses exit 1 when findings present. Correct.
- Bad path: `filepath.WalkDir` returns error when root path doesn't exist → `os.Exit(2)`. Correct.
- Bad config: `regexp.Compile` failure in `compile()` → `LoadConfig` returns error → `os.Exit(2)`. Correct.

## RE2 Safety Assessment

All regexes compile with stdlib `regexp`. The test `TestInvalidRegexRejected` and
`TestLoadConfigREValidation` verify that RE2-incompatible patterns (lookaheads) are
rejected at config load time with a descriptive error message. No use of
`dlclark/regexp2` anywhere. Confirmed clean.

## Concurrency Assessment

The worker pool pattern is correct: `errgroup.WithContext` + `g.SetLimit(GOMAXPROCS)`,
`sync.Mutex` protecting `allFindings`, `atomic.Int64` for `filesScanned`. The
`Engine.ScanLine()` method is stateless (reads-only from `e.trie`, `e.rules`,
`e.cfg`) and safe for concurrent calls. The `Engine` struct fields are set once at
construction and never mutated. No data races on shared state were identified, aside
from the goroutine leak scenario described in WR-01.

---

_Reviewed: 2026-05-22_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: deep_
