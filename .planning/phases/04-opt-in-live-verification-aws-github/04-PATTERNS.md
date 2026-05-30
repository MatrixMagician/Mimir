# Phase 4: Opt-in Live Verification (AWS + GitHub) - Pattern Map

**Mapped:** 2026-05-30
**Files analyzed:** 11 (4 new verify files + 1 new test-trio counted as 3 + 6 modified)
**Analogs found:** 11 / 11 (every new/modified file has an in-repo analog)

All analogs are in `/home/oliverh/repos/github/MatrixMagician/Mimir`. Line numbers are from the
files as read on the mapping date. Code excerpts below show the established convention to copy.

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `internal/verify/verify.go` (NEW) | service (orchestrator + registry + cache) | request-response (bounded fan-out) | `internal/scanner/scanner.go` (errgroup pool) + `internal/detect/engine.go` (NewEngine/registry shape) | role-match |
| `internal/verify/aws.go` (NEW) | service (network verifier) | request-response | `internal/gitscan/command.go` (external-call isolation) | role-match |
| `internal/verify/github.go` (NEW) | service (network verifier) | request-response | `internal/gitscan/command.go` | role-match |
| `internal/verify/verify_test.go` (NEW) | test | — | `internal/output/output_test.go` (table + buffer) | role-match |
| `internal/verify/aws_test.go` (NEW) | test (table) | — | `internal/output/output_test.go` | role-match |
| `internal/verify/github_test.go` (NEW) | test (httptest) | — | `internal/gitscan/gitscan_test.go` (real-server harness) | partial |
| `internal/finding/finding.go` (MODIFY) | model | — | `Finding.CommitSHA` omitempty field, same file (lines 56-58) | exact |
| `internal/detect/engine.go` (MODIFY: `ScanLine`) | service (detection) | transform | `ScanLine` itself, same file (raw-secret site line 114) | exact (self) |
| `internal/scanner/scanner.go` (MODIFY: `Scan`/`scanFile`) | service (walk) | request-response | `Scan`/`scanFile` return-tuple + mutex merge, same file | exact (self) |
| `internal/gitscan/gitscan.go` (MODIFY: `ScanHistory`/`ScanStaged`) | service (git source) | streaming | `ScanHistory`/`ScanStaged` return tuples + `parsePatch`, same package | exact (self) |
| `cmd/mimir/scan.go` (MODIFY: flag + invoke) | controller (CLI) | request-response | `init()` flag block + `runScan` post-suppression stage, same file | exact (self) |
| `internal/output/json.go` + `human.go` (MODIFY) | view (render) | transform | `CommitSHA` omitempty render (json.go ScanSummary; human.go lines 64-70) | exact |

---

## Pattern Assignments

### `internal/finding/finding.go` (MODIFY — additive `*Verification` field)

**Analog:** `Finding.CommitSHA` / `Suppressed` omitempty fields in the SAME file. This is the
authoritative pattern: additive omitempty fields carrying only non-secret enums, populated AFTER
`New()` returns, never touching the fingerprint, preserving OUT-02 byte-identical JSON.

**Omitempty additive-field pattern** (finding.go lines 43-58):
```go
	// Suppressed and SuppressionReason (D-12) ... Both are omitempty so the Phase 1
	// OUT-02 schema is byte-identical for findings that are not suppressed.
	Suppressed        bool   `json:"suppressed,omitempty"`
	SuppressionReason string `json:"suppression_reason,omitempty"`

	// CommitSHA ... populated by internal/gitscan AFTER New() returns — never inside
	// New() and never by computeFingerprint ... All three are omitempty ...
	CommitSHA    string `json:"commit_sha,omitempty"`
	CommitAuthor string `json:"commit_author,omitempty"`
	CommitDate   string `json:"commit_date,omitempty"`
```

**What to add (mirroring research Code Examples §"Additive Finding field"):**
```go
type Verification struct {
	Status   string `json:"status"`   // "active" | "inactive" | "unknown"
	Provider string `json:"provider"` // "aws" | "github"
}
// on Finding:
	Verification *Verification `json:"verification,omitempty"`
```

**Why a pointer (not string):** Research Pitfall 5 — a non-pointer struct serializes as
`"verification":{...}` (or zero values) on every finding, breaking the frozen schema. Pointer +
omitempty → nil unless verified.

**Reflection-guard interaction** (finding_test.go lines 178-188): `TestNoRawSecretInAnyField`
walks `fv.Kind() == reflect.String` exported fields only. `Verification` is a pointer field →
untouched by the existing guard. It MUST carry no secret-bearing string. Add a complementary test
mirroring `TestCommitMetaOmitempty` (finding_test.go around line 154) asserting nil-by-default
omits `"verification"` from JSON:
```go
// from finding_test.go ~line 154 — the omitempty-default assertion pattern to copy:
assert.NotContains(t, js, "commit_author", "default-scan JSON must omit commit_author")
```

---

### `internal/detect/engine.go` (MODIFY — `ScanLine` raw-secret side channel)

**Analog:** `ScanLine` itself (self). The raw value lives at line 114 (`rawSecret := line[...]`)
and is consumed by `finding.New` at line 144 — the ONE site where the raw value still exists.

**Capture point — extend the signature to accept a caller-provided sink map** (research Pattern 1,
"preferred — avoids allocating a map per line"). Current signature (line 56):
```go
func (e *Engine) ScanLine(line, filePath string, lineNum int) []finding.Finding {
```

**Existing redact-boundary call site to capture beside** (lines 142-145):
```go
		// Call finding.New() — this is the ONLY place rawSecret is used further.
		f := finding.New(rule.ID, filePath, lineNum, col, rawSecret, fullMatch, rule.IsHeuristic)
		findings = append(findings, f)
```
Add `raw[f.Fingerprint] = rawSecret` immediately after `f` is built (where `rawSecret` is still in
scope). `f.Fingerprint` is the safe key — `computeFingerprint` (finding.go lines 87-94) is
`path:ruleID:sha256[:16](rawSecret)`, unique per (path, rule, secret).

**Critical:** the map is written here and threaded out; it is NEVER stored on `Finding` and NEVER
serialized (research Anti-Pattern: storing raw on Finding).

---

### `internal/scanner/scanner.go` (MODIFY — thread side-channel through `Scan`/`scanFile`)

**Analog:** the existing return-tuple + mutex-merge pattern in `Scan`/`scanFile` (self). The
side-channel map rides the same path `allFindings` and `suppressedCounts` already travel.

**errgroup pool (the concurrency analog reused by `verify.Run`)** (lines 70-71):
```go
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(runtime.GOMAXPROCS(0))
```
(verify.Run uses the SAME primitive with `g.SetLimit(5)` per CONTEXT.)

**Mutex critical-section merge — the exact site to merge per-file raw maps** (lines 154-161):
```go
			if len(findings) > 0 || len(fileSuppressed) > 0 {
				mu.Lock()
				allFindings = append(allFindings, findings...)
				for reason, n := range fileSuppressed {
					suppressedCounts[reason] += n
				}
				mu.Unlock()
			}
```
Add a `rawByFP` merge (`for k, v := range fileRaw { rawByFP[k] = v }`) inside this same locked
block. `scanFile` (line 214) returns `([]finding.Finding, map[string]int, error)` today; extend it
to also return the per-file raw map, populated where it calls `s.engine.ScanLine` (line 262).

**Return signature to extend** (line 67):
```go
func (s *Scanner) Scan(ctx context.Context, paths []string) ([]finding.Finding, Stats, error) {
```
becomes `(..., map[string]string, Stats, error)` (fingerprint→raw). The `Stats` struct (lines
26-37) is the analog for "additive run-scoped metadata threaded out of Scan."

---

### `internal/gitscan/gitscan.go` (MODIFY — thread side-channel through `ScanHistory`/`ScanStaged`)

**Analog:** `ScanHistory`/`ScanStaged` return tuples (self) + `parsePatch` in `parse.go`.

**Both functions return** `([]finding.Finding, scanner.Stats, error)` (lines 29, 89) and build the
slice from `parsePatch` (lines 39, 98):
```go
	findings, suppressed, parseErr := parsePatch(stdout, engine, showSuppressed)
```
`parsePatch` (parse.go lines 26, 52) calls `engine.ScanLine(line, f.NewName, lineNum)` — the same
capture point. Thread the raw map out of `parsePatch` → `ScanHistory`/`ScanStaged` → `runScan`,
mirroring how `suppressed` already rides these returns.

**Dedup interaction** (`dedupByFingerprint`, gitscan.go lines 138-164): dedup collapses by
`f.Fingerprint`. Since the raw map is ALSO keyed by fingerprint, a deduped finding's fingerprint
still resolves its raw value — no extra bookkeeping. Build the raw map BEFORE or alongside dedup;
collapsed duplicates share the same key harmlessly.

---

### `cmd/mimir/scan.go` (MODIFY — register `--verify`, invoke post-suppression)

**Analog:** the `init()` flag block + the `runScan` post-suppression stage (self).

**Flag registration pattern** (init(), lines 27-40) — copy the bool-flag idiom of `--git`/`--staged`:
```go
	scanCmd.Flags().Bool("git", false, "Scan current-branch git history ...")
	scanCmd.Flags().Bool("staged", false, "Scan the staged diff ...")
```
Add `scanCmd.Flags().Bool("verify", false, "Live-verify AWS/GitHub findings (off by default; makes network calls; never used by the pre-commit hook)")`.

**Flag read + source dispatch** (lines 99-117) — `runScan` reads flags then dispatches; the new
`findings, raw, stats, err = ...` tuple flows from each source:
```go
	gitMode, _ := cmd.Flags().GetBool("git")
	stagedMode, _ := cmd.Flags().GetBool("staged")
	...
	switch {
	case gitMode:
		findings, stats, err = gitscan.ScanHistory(...)
	case stagedMode:
		findings, stats, err = gitscan.ScanStaged(...)
	default:
		findings, stats, err = s.Scan(cmd.Context(), paths)
	}
```

**THE invocation slot — `newFindings` post-suppression set** (lines 148-155):
```go
	// newFindings is the reportable set: everything not suppressed by any layer.
	var newFindings []finding.Finding
	for _, f := range findings {
		if !f.Suppressed {
			newFindings = append(newFindings, f)
		}
	}
```
Insert, immediately after this loop and before output (line 171): `if verify { verify.Run(cmd.Context(), newFindings, raw) }`.
Run on `newFindings` ONLY (research Anti-Pattern: verifying full set).

**Fail-loud convention** (e.g. lines 104-107) — already-present mutual-exclusion idiom. `--verify`
is label-only and does NOT add a fail-loud branch; the exit-code contract (lines 191-197) stays
UNCHANGED — `--verify` never flips the exit code.

---

### `internal/verify/verify.go` (NEW — Verifier interface, registry, Run orchestrator, cache)

**Analog (structure):** `internal/detect/engine.go` for the "stateless service + constructor +
registry-of-rules" package shape; `internal/scanner/scanner.go` lines 70-71 for the errgroup pool.

**Package-shape conventions to copy from engine.go:**
- Package doc comment + "stateless after construction, goroutine-safe" note (engine.go lines 11-12).
- Import grouping: stdlib block, blank line, then `github.com/MatrixMagician/mimir/internal/...`
  (engine.go lines 3-9; scanner.go lines 3-23).
- A registry built once at construction (engine.go `NewEngine` collects rule keywords into a map —
  the analog for `registry map[ruleID]Verifier`).

**errgroup bounded fan-out — copy from scanner.go lines 70-71** (use limit 5 per CONTEXT):
```go
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(5)
```

**Per-secret cache + mutex** — copy the `var mu sync.Mutex` + locked-map idiom from scanner.go
lines 73-75 / 155-160. Cache keyed by `(provider, secret)` (research Open Question 3) to avoid
cross-provider collision; run-scoped, in-memory only, never persisted (research Runtime State
Inventory: "in-memory only").

**Rule-ID → Verifier registry** (research Code Examples; rule IDs VERIFIED in `config/mimir.toml`):
- `aws-access-token` (line 27) → AWS verifier
- `github-pat` (50), `github-oauth` (57), `github-app-token` (64), `github-refresh-token` (71),
  `github-fine-grained-pat` (78) → GitHub verifier
- `gcp-api-key`, `gitlab-*`, `slack-*`, `stripe-access-token`, etc. → NO verifier (left unlabeled).

**Status set on finding (in-memory only):** `findings[i].Verification = &finding.Verification{...}`
— mirrors how `parse.go`'s `attachCommitMeta` (parse.go lines 86-97) mutates a `*finding.Finding`
in place after the finding exists. Same post-hoc, by-pointer mutation discipline.

---

### `internal/verify/aws.go` (NEW — AWS STS GetCallerIdentity verifier)

**Analog (isolation discipline):** `internal/gitscan/command.go` / the external-call isolation in
`gitscan.go` — all process/network boundary code lives in one file with sanitized error returns.

**Implementation is research-specified** (Pattern 2): direct `sts.New(sts.Options{...})` with
`credentials.NewStaticCredentialsProvider(id, secret, "")`, `BaseEndpoint:
aws.String("https://sts.amazonaws.com")`, classify via `errors.As(&smithy.APIError)` +
`ErrorCode()`. NEVER `config.LoadDefaultConfig` (Pitfall 2 — ambient-cred leak).

**Co-located secret-key pairing helper** uses stdlib `regexp` (RE2) to re-read the finding's `File`
for a `[A-Za-z0-9/+]{40}` near `aws.*secret` — same RE2 + allowlist discipline as engine.go's
`isAllowlisted` (engine.go lines 153-169). Cap file read size (research V5).

**Error sanitization (Pitfall 1):** return only `(Status, sanitizedErr{provider, reasonEnum})` —
NEVER `%w`/`%v` of the SDK error. Contrast with gitscan.go lines 43/50 which DO wrap git errors
with `%w` — that is acceptable there (no secret in a git path) but FORBIDDEN here (SDK errors can
embed request context). This is the one place the repo's usual `%w` convention is deliberately not
followed.

---

### `internal/verify/github.go` (NEW — GitHub GET /user verifier)

**Analog:** `internal/gitscan/command.go` (external-call isolation) + the `net/http` request shape
in research Pattern 3.

**Implementation is research-specified** (Pattern 3): bare `net/http` GET
`https://api.github.com/user`, `Authorization: Bearer <token>`, `User-Agent: mimir` (REQUIRED —
omitting yields 403), `X-GitHub-Api-Version: 2022-11-28`. Classify: 200→Active, 401→Inactive,
403/429→honor `Retry-After` ONCE then Unknown, network/timeout→Unknown.

**Timeout:** `context.WithTimeout(ctx, 5*time.Second)` per call (CONTEXT). The repo already uses
`context.Context` threading throughout (scanner.go `Scan(ctx, ...)`, gitscan.go `ScanHistory(ctx,
...)`), so ctx-first signatures are the established convention.

**Error sanitization:** same Pitfall-1 rule as aws.go — no token in URL/query/log; sanitized
reason enum only.

---

### `internal/verify/{verify,aws,github}_test.go` (NEW)

**Analog (table + buffer assertions):** `internal/output/output_test.go` lines 1-55 — `package
X_test` external test, testify `assert`/`require`, table-driven `t.Run` subtests, build a real
engine/finding from `config.LoadDefault()`.

**Build-real-engine helper to copy** (gitscan_test.go lines 24-29):
```go
func newTestEngine(tb testing.TB) *detect.Engine {
	tb.Helper()
	cfg, err := config.LoadDefault()
	require.NoError(tb, err)
	return detect.NewEngine(cfg)
}
```

**httptest harness analog (github_test.go):** gitscan_test.go uses a real-process harness
(`exec.Command("git", ...)`, lines 31-45) — mirror that discipline with `httptest.NewServer`
returning 200/401/403+`Retry-After`/hanging-for-timeout, asserting status mapping.

**No-ambient-creds test (aws_test.go, Pitfall 2):** set bogus `AWS_ACCESS_KEY_ID` via
`t.Setenv(...)` and assert the verifier uses only the passed pair. `t.Setenv` is the stdlib idiom
(no existing analog in repo, but standard testing).

**Fixture-secret convention** (gitscan_test.go lines 16-19): use a fixture token that matches a
rule but is NOT auto-allowlisted:
```go
const fixtureSecret = "AKIAFAKEKEYABCDE2345"
```

---

### `internal/output/json.go` + `human.go` (MODIFY — render verification)

**JSON analog:** `ScanSummary` additive-omitempty fields (json.go lines 21-27) + `emptyToNil`
(lines 57-62). The `Verification` field is already omitempty on `Finding` itself, so `WriteJSON`
(lines 32-52) needs NO change beyond the struct — the encoder drops nil pointers automatically.
Add a test mirroring `TestVerifyOmittedByDefault` against the existing OUT-02 golden assertions.

**Human analog — the CommitSHA conditional-tag render** (human.go lines 64-70):
```go
		if f.CommitSHA != "" {
			fmt.Fprintf(w, "%s:%d:%d @ %s  %s  %s\n",
				sanitizeForTTY(f.File), f.Line, f.Column, sanitizeForTTY(shortSHA(f.CommitSHA)), ruleStr, sanitizeForTTY(f.Secret))
		} else {
			fmt.Fprintf(w, "%s:%d:%d  %s  %s\n", ...)
		}
```
Mirror this `if f.Verification != nil` branch to append a colored tag. Use the existing color-style
vars (human.go lines 17-22):
```go
	sigRuleStyle = color.New(color.FgCyan)
	heuStyle     = color.New(color.FgYellow)
	warnStyle    = color.New(color.FgYellow, color.Bold)
	okStyle      = color.New(color.FgGreen, color.Bold)
```
Add `verifyActiveStyle = color.New(color.FgRed, color.Bold)` (ACTIVE), reuse a dim/`FgHiBlack`
style (INACTIVE, as used for the suppressed section, line 91), `heuStyle`/yellow (UNKNOWN).

**Tally line analog** (human.go lines 105-117): the suppression-count tally loop is the exact
pattern for the one-line `Verified: N active, M inactive, K unknown` summary:
```go
	for _, reason := range []string{"inline-ignore", "allowlist", "baseline"} {
		if n := stats.Suppressed[reason]; n > 0 {
			fmt.Fprintf(w, "  (%d %s)\n", n, reason)
		}
	}
```

**TTY-sanitization invariant:** all repo-sourced strings pass through `sanitizeForTTY` (human.go
lines 146-177). The verification tag is a fixed enum (active/inactive/unknown) so it needs no
sanitization, but do NOT print any verifier-sourced string raw.

---

## Shared Patterns

### errgroup bounded concurrency
**Source:** `internal/scanner/scanner.go` lines 70-71
**Apply to:** `internal/verify/verify.go` `Run` orchestrator
```go
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(runtime.GOMAXPROCS(0)) // verify.Run uses SetLimit(5) per CONTEXT
```
`golang.org/x/sync` v0.20.0 already in go.mod (line 12).

### Redact-at-boundary / no-secret-in-output
**Source:** `internal/finding/finding.go` package doc (lines 1-7), `New` (lines 110-128),
`TestNoRawSecretInAnyField` (finding_test.go lines 171-189)
**Apply to:** ALL new verify files + the side-channel carry.
- Raw secret captured ONLY at engine.go:114 (where `finding.New` also briefly sees it).
- Off-struct map (research Pattern 1) — never a `Finding` field, never serialized.
- Verifier errors carry `{provider, reason}` enums only — NEVER `%w`/`%v` of an SDK/HTTP error
  (this is the one deliberate exception to the repo's normal `%w`-wrap convention used in gitscan.go).

### Additive omitempty field (OUT-02 byte-identical)
**Source:** `internal/finding/finding.go` `CommitSHA`/`Suppressed` (lines 43-58),
`emptyToNil` (json.go lines 57-62)
**Apply to:** the new `*Verification` field + JSON render.
- Pointer + `omitempty` → nil unless verified → non-`--verify` JSON stays byte-identical (Pitfall 5).
- Populated AFTER `New()` returns (like `attachCommitMeta`, parse.go lines 86-97); never enters
  `computeFingerprint`.

### Fail-loud on misuse / exit-code contract
**Source:** `cmd/mimir/scan.go` mutual-exclusion (lines 104-107), exit contract (lines 191-197)
**Apply to:** `runScan`. `--verify` is LABEL-ONLY — it adds NO fail-loud branch and does NOT alter
exit codes (0 clean / 1 findings / 2 error). Network failure → `unknown`, never an error, never
exit 2.

### ctx-first signatures + per-call timeout
**Source:** `Scan(ctx, ...)` (scanner.go:67), `ScanHistory(ctx, ...)` (gitscan.go:29)
**Apply to:** `Verify(ctx, ...)` and `Run(ctx, ...)`. Each network call wraps a fresh
`context.WithTimeout(ctx, 5*time.Second)` (CONTEXT).

### Test conventions
**Source:** `internal/output/output_test.go` (lines 1-21), `internal/gitscan/gitscan_test.go`
(lines 1-45)
**Apply to:** all new `_test.go`. `package X_test`, testify `assert`/`require`, table `t.Run`
subtests, `config.LoadDefault()` real-engine helper, `color.NoColor = true` for deterministic
human-output assertions, fixture secret `AKIAFAKEKEYABCDE2345`.

### Hook stays offline (already enforced)
**Source:** `cmd/mimir/hook.go` template (`exec mimir scan --staged`, line 28),
`cmd/mimir/hook_test.go` line 62: `assert.NotContains(t, s, "--verify", ...)`
**Apply to:** confirm the hook template is NOT touched; the offline assertion ALREADY EXISTS
(Pitfall 6 / VERIFY-01 partly satisfied). No new hook test needed beyond verifying this still passes.

---

## No Analog Found

None. Every new and modified file maps to an in-repo analog. Two implementation details have NO
direct in-repo analog and must follow RESEARCH.md verbatim instead:

| Detail | Role | Reason | Use Instead |
|--------|------|--------|-------------|
| aws-sdk-go-v2 `sts.New` static-cred call | service | No AWS SDK usage exists in the repo yet | RESEARCH Pattern 2 (exact code) |
| `httptest.NewServer` mock harness | test | Repo uses real-process (git) harnesses, not httptest | RESEARCH Validation §github_test + stdlib `net/http/httptest` |

---

## Metadata

**Analog search scope:** `internal/` (finding, detect, scanner, gitscan, output, suppress, config),
`cmd/mimir/`, `config/mimir.toml`, `go.mod`
**Files scanned:** 11 source files read in full + 3 test files (output_test, gitscan_test,
finding_test) + config/mimir.toml rule-ID grep + hook_test.go assertion grep
**Pattern extraction date:** 2026-05-30
