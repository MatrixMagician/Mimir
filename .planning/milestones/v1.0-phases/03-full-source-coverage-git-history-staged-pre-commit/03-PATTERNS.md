# Phase 3: Full Source Coverage (Git History + Staged + Pre-commit) - Pattern Map

**Mapped:** 2026-05-30
**Files analyzed:** 7 (4 new, 3 modified)
**Analogs found:** 7 / 7

## File Classification

| New/Modified File | New/Mod | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|---------|------|-----------|----------------|---------------|
| `internal/gitscan/gitscan.go` | NEW | source / service | streaming (git stdout → findings) | `internal/scanner/scanner.go` | role-match (source emitting `[]finding.Finding`) |
| `internal/gitscan/command.go` | NEW | utility (process spawn) | streaming (exec pipe) | *(no analog — see No Analog Found)* | research pattern |
| `internal/gitscan/parse.go` | NEW | service (diff→line) | transform (OpAdd → ScanLine) | `internal/scanner/scanner.go` `scanFile` (lines 214-283) | role-match (per-line loop + inline-ignore) |
| `internal/gitscan/gitscan_test.go` | NEW | test | integration (temp-repo fixture) | `cmd/mimir/scan_test.go` + `internal/scanner/scanner_test.go` | exact (testify + temp dirs) |
| `cmd/mimir/scan.go` | MOD | controller (cobra cmd) | request-response | *(self — extend existing `runScan`)* | exact |
| `cmd/mimir/hook.go` | NEW | controller (cobra group) | request-response | `cmd/mimir/version.go` + `cmd/mimir/scan.go` `init()` | role-match (cobra `AddCommand` shape) |
| `cmd/mimir/hook_test.go` | NEW | test (e2e) | request-response | `cmd/mimir/scan_test.go` (`TestMain` + `runMimir`) | exact |
| `internal/finding/finding.go` | MOD | model | — | *(self — extend `Finding` struct + `New`)* | exact |
| `internal/finding/finding_*_test.go` | MOD | test | — | `internal/finding/finding_test.go` (reflect guard) | exact |
| `internal/output/human.go` | MOD | reporter | transform | *(self — extend `WriteHuman` line 59)* | exact |
| `.pre-commit-hooks.yaml` | NEW | config (manifest) | — | *(no analog — D-07 framework manifest)* | none |

## Pattern Assignments

### `internal/gitscan/gitscan.go` + `parse.go` (source, streaming → transform)

**Analog:** `internal/scanner/scanner.go` — specifically the `scanFile` per-line loop and the `Scan` deterministic-sort + Stats return.

**Constructor / engine-injection pattern** (`scanner.go` lines 58-61) — gitscan source funcs should take the same `*detect.Engine` (do NOT rebuild it; engine is goroutine-safe and stateless per `engine.go` line 13):
```go
func New(engine *detect.Engine, cfg *config.Config) *Scanner {
	return &Scanner{engine: engine, cfg: cfg}
}
```
The gitscan source funcs are `ScanHistory(ctx, engine *detect.Engine, repoRoot string, ...) ([]finding.Finding, Stats, error)` and `ScanStaged(...)` — same return shape as `Scanner.Scan` so `runScan` can swap sources transparently.

**Engine call — the exact signature gitscan must invoke** (`engine.go` lines 56, and call site `scanner.go` line 262):
```go
// engine.ScanLine(line, filePath string, lineNum int) []finding.Finding
lineFindings := s.engine.ScanLine(line, relPath, lineNum)
```
`line` is the raw line content (NOT lowercased, NOT including a trailing `\n` — see Pitfall 1 in RESEARCH). `filePath` is repo-relative forward-slash. `lineNum` is 1-indexed. The engine internally calls `finding.New` (redact-at-boundary) so gitscan inherits redaction for free — never construct a `Finding` literal with a raw secret.

**Inline-ignore per-line pattern — COPY VERBATIM** (`scanner.go` lines 262-276). The staged scan + hook must honor `// mimir:ignore` (criterion 3); the diff-added line *is* the source line, so the exact same call applies:
```go
lineFindings := s.engine.ScanLine(line, relPath, lineNum)
for i := range lineFindings {
	if suppress.InlineSuppresses(line, lineFindings[i].RuleID) {
		suppressed[suppress.InlineReason]++
		if !s.ShowSuppressed {
			continue // drop: do not append
		}
		lineFindings[i].Suppressed = true
		lineFindings[i].SuppressionReason = suppress.InlineReason
	}
	findings = append(findings, lineFindings[i])
}
```
`suppress.InlineSuppresses(line, ruleID) bool` (`inline.go` line 29) and `suppress.InlineReason` (= `"inline-ignore"`, `inline.go` line 10) are the exact symbols to reuse.

**Per-line OpAdd → ScanLine glue** (the only Mimir-original logic — from RESEARCH Pattern 2; line-number counter starts at `TextFragment.NewPosition`, `OpAdd`/`OpContext` advance, `OpDelete` does not):
```go
for _, tf := range f.TextFragments {
	lineNum := int(tf.NewPosition)
	for _, l := range tf.Lines {
		switch l.Op {
		case gitdiff.OpAdd:
			line := strings.TrimSuffix(l.Line, "\n") // Pitfall 1: strip trailing newline
			lineFindings := engine.ScanLine(line, f.NewName, lineNum)
			// ... inline-ignore block above ...
			// attach commit metadata only when f.PatchHeader has a SHA (Pitfall 5)
			lineNum++
		case gitdiff.OpContext:
			lineNum++
		case gitdiff.OpDelete:
		}
	}
}
```

**Commit-metadata attach (D-08) — guard against empty staged PatchHeader** (Pitfall 5; PatchHeader fields verified in module cache `patch_header.go`: `SHA string`, `Author *PatchIdentity`, `AuthorDate time.Time`, `Title string`):
```go
if f.PatchHeader != nil && f.PatchHeader.SHA != "" {
	out[i].CommitSHA = f.PatchHeader.SHA
	if f.PatchHeader.Author != nil {
		out[i].CommitAuthor = f.PatchHeader.Author.Name // or Email
	}
	out[i].CommitDate = f.PatchHeader.AuthorDate.Format(time.RFC3339)
}
```

**Deterministic sort + Stats return** — mirror `scanner.go` lines 178-196. Sort File → Line → Column (extend with commit order for history per CONTEXT D-10/RESEARCH A3 dedup-to-earliest). Return `scanner.Stats` (or a gitscan-local equivalent with the same fields) so `runScan`'s downstream stages are unchanged.

**Fail-loud on bad input** — mirror `scanner.go` lines 82-90 (root-path error is fatal) and `runScan`'s `os.Exit(2)` pattern: if `exec.LookPath("git")` fails or `cmd.Wait()` returns non-zero (not a git repo), return an error that surfaces as exit 2 (Pitfall 4). Do NOT silently return `nil, exit 0`.

---

### `cmd/mimir/scan.go` (controller — MODIFIED, add `--git`/`--staged` source branch)

**Analog:** self. The source-selection branch goes between flag-resolution (after line 90, where `s.Matcher` is set) and the existing `s.Scan` call (line 93). Everything from line 99 onward (baseline filter, `newFindings`, output, exit code) is **shared and unchanged** across all three sources.

**Flag registration pattern** (`scan.go` lines 26-36) — add the mode flags alongside the existing surface:
```go
scanCmd.Flags().Bool("git", false, "Scan current-branch git history for secrets (added-then-deleted included)")
scanCmd.Flags().Bool("staged", false, "Scan the staged diff (git diff --staged) — used by the pre-commit hook")
```

**Source-selection branch** (insert at `runScan` ~line 92, replacing the single `s.Scan` call). Mutually-exclusive precedence is the RESEARCH A2 recommendation (`os.Exit(2)` if both set, matching the existing fail-loud `os.Exit(2)` calls at lines 54/83/87/96):
```go
gitMode, _ := cmd.Flags().GetBool("git")
stagedMode, _ := cmd.Flags().GetBool("staged")
if gitMode && stagedMode {
	fmt.Fprintln(os.Stderr, "error: --git and --staged are mutually exclusive")
	os.Exit(2)
}
var findings []finding.Finding
var stats scanner.Stats
switch {
case gitMode:
	findings, stats, err = gitscan.ScanHistory(cmd.Context(), engine, scanRoot, ...)
case stagedMode:
	findings, stats, err = gitscan.ScanStaged(cmd.Context(), engine, scanRoot, ...)
default:
	findings, stats, err = s.Scan(cmd.Context(), paths) // unchanged working-tree walk
}
if err != nil {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(2)
}
```
The `ShowSuppressed` flag (line 68-73) must be threaded into the gitscan sources too so `--show-suppressed` behaves identically across modes.

**Exit-code contract — DO NOT TOUCH** (`scan.go` lines 167-173). Staged findings flip exit 1 to block a commit automatically because they flow through the same `newFindings`/`os.Exit(1)` path. This is the IFACE-02 reuse the whole phase depends on.

---

### `cmd/mimir/hook.go` (controller — NEW cobra group)

**Analog:** `cmd/mimir/version.go` (whole file — minimal cobra command + `rootCmd.AddCommand` in `init()`) for the group shape, and `cmd/mimir/scan.go` `init()` (lines 24-39) for sub-flag registration.

**Command + AddCommand pattern** (`version.go` lines 14-24):
```go
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the mimir version",
	Run:   func(cmd *cobra.Command, args []string) { fmt.Println(version) },
}
func init() { rootCmd.AddCommand(versionCmd) }
```
For `mimir hook` (D-02 noun-verb group): a parent `hookCmd` with `hookCmd.AddCommand(hookInstallCmd, hookUninstallCmd, hookStatusCmd)`, then `rootCmd.AddCommand(hookCmd)` in `init()`. The `install` subcommand gets a `--force` flag registered exactly like `scan.go`'s `scanCmd.Flags().Bool(...)`.

**Fail-loud + git-shell-out** — reuse the `runScan` `os.Exit(2)` discipline (`scan.go` lines 54/83/87) for: git absent, not a git repo, existing pre-commit hook without `--force` (D-05). Resolve hook dir via `git rev-parse --git-path hooks` (RESEARCH Code Examples), NOT hardcoded `.git/hooks`. The written hook script execs `mimir scan --staged` and honors `git config --type=bool --get hooks.mimir` (D-06; RESEARCH Pattern 3).

**`SilenceErrors`/`SilenceUsage`** are already set on `rootCmd` (`root.go` lines 16-17) — hook subcommands inherit the print-once error behavior; return errors from `RunE` rather than printing+exiting where possible, matching `scanCmd` (`scan.go` line 21 `RunE: runScan`).

---

### `internal/finding/finding.go` (model — MODIFIED, add D-08 commit fields)

**Analog:** self. The `Suppressed`/`SuppressionReason` `omitempty` fields (lines 43-44) are the exact precedent — additive, omitempty, never reshape existing fields, preserving OUT-02 byte-identical schema for non-history scans.

**Existing omitempty precedent to mirror** (lines 43-44):
```go
Suppressed        bool   `json:"suppressed,omitempty"`
SuppressionReason string `json:"suppression_reason,omitempty"`
```

**D-08 additive fields** (append to the `Finding` struct after line 44; RESEARCH Code Examples):
```go
CommitSHA    string `json:"commit_sha,omitempty"`
CommitAuthor string `json:"commit_author,omitempty"`
CommitDate   string `json:"commit_date,omitempty"` // RFC3339 from PatchHeader.AuthorDate
```

**`computeFingerprint` — DO NOT MODIFY** (lines 67-80). D-09: fingerprint stays `path:rule_id:sha256[:16]`, commit-independent. Adding commit fields to the struct must NOT touch `computeFingerprint` or `New` (lines 96-114) — the commit fields are populated by gitscan *after* `New` returns, never inside it. This is what makes cross-mode baseline/dedup work.

---

### `internal/output/human.go` (reporter — MODIFIED, D-10 short-SHA on history findings)

**Analog:** self. The finding line is emitted at lines 59-60:
```go
fmt.Fprintf(w, "%s:%d:%d  %s  %s\n",
	f.File, f.Line, f.Column, ruleStr, f.Secret)
```
D-10: when `f.CommitSHA != ""`, append the short SHA (e.g. `path:42 @ abc1234  rule  redacted`). Keep the no-SHA branch byte-identical for working-tree/staged (the field is empty there, so the existing format is preserved). Full author/date go under the existing `verbose` branch (lines 64-66), alongside the suppression hint.

JSON output (`json.go`) needs **no change** — `finding.Finding` is embedded directly (`json.go` line 14), so the new omitempty fields serialize automatically and stay absent when empty (the `emptyToNil` discipline at lines 54-62 is the same omitempty philosophy).

---

### Tests — `internal/gitscan/gitscan_test.go` + `cmd/mimir/hook_test.go`

**Analog (gitscan unit/integration):** `internal/scanner/scanner_test.go` — `newTestScanner` helper (lines 16-22) builds an engine from `config.LoadDefault()`; reuse it to get a real `*detect.Engine`. Use `t.TempDir()` + `git init` scripted commits/stages (RESEARCH Wave 0 fixture helper). Assertion style: `require`/`assert` from testify.
```go
func newTestScanner(t *testing.T) *Scanner {
	cfg, err := config.LoadDefault()
	require.NoError(t, err)
	eng := detect.NewEngine(cfg)
	return New(eng, cfg)
}
```

**Analog (hook e2e):** `cmd/mimir/scan_test.go` — `TestMain` (lines 19-39) builds the binary once to `/tmp/mimir-cmd-test`; `runMimir(t, args...)` (lines 49-68) runs it and returns `(stdout, stderr, exitCode)`. The hook block-commit test reuses this harness: `git init` a temp repo, `mimir hook install`, stage a secret, attempt `git commit`, assert it is blocked (exit non-zero), then assert `--no-verify` / `git config hooks.mimir false` bypass it. Exit-code assertions follow `TestExitCodeFindings` (lines 79-84).

**Analog (finding omitempty + fingerprint-unchanged):** `internal/finding/finding_test.go` `TestNoRawSecretInAnyField` (lines 124-143) is the reflect security guard — it auto-covers the new string fields. Add: (a) a test that a `Finding` with `CommitSHA` set still produces the SAME fingerprint as one without (D-09), extending `TestFingerprint` (lines 91-120); (b) an omitempty test that default-scan JSON omits `commit_sha` (mirror `scan_test.go` `TestShowSuppressed` lines 286-289 which asserts `NotContains(def, "suppression_reason")`).

## Shared Patterns

### Engine reuse (zero detection changes)
**Source:** `internal/detect/engine.go` — `func (e *Engine) ScanLine(line, filePath string, lineNum int) []finding.Finding` (line 56). Stateless, goroutine-safe (line 13).
**Apply to:** Both gitscan sources. Pass the *same* `*detect.Engine` that `runScan` builds at `scan.go` line 69; do not construct a new one.
```go
lineFindings := s.engine.ScanLine(line, relPath, lineNum)
```

### Inline-ignore suppression (criterion 3)
**Source:** `internal/suppress/inline.go` — `InlineSuppresses(line, ruleID string) bool` (line 29), `InlineReason` const (line 10).
**Apply to:** gitscan parse loop (per-OpAdd-line), copied verbatim from `scanner.go` lines 266-276.

### Redact-at-boundary (security invariant)
**Source:** `internal/finding/finding.go` `New` (lines 96-114) — redacts inside construction; raw secret never stored. Reflect guard in `finding_test.go` lines 124-143.
**Apply to:** All gitscan findings (inherited via `engine.ScanLine` → `finding.New`). NEVER log `l.Line` verbatim in verbose mode (RESEARCH Security V7); commit author/date/message are non-secret and safe.

### Fail-loud on bad input → exit 2
**Source:** `cmd/mimir/scan.go` lines 52-55, 80-89, 94-97 (`fmt.Fprintln(os.Stderr, ...); os.Exit(2)`) and `scanner.go` lines 82-90 (fatal root-path error).
**Apply to:** gitscan (git missing / not a repo — Pitfall 4) and `hook install` (existing hook without `--force`, git absent).

### omitempty schema extension (OUT-02 stability)
**Source:** `internal/finding/finding.go` lines 43-44; `internal/output/json.go` `emptyToNil` lines 54-62.
**Apply to:** D-08 commit fields on `Finding` — additive omitempty only, populated only when a real commit SHA exists (Pitfall 5).

### cobra command registration
**Source:** `cmd/mimir/version.go` lines 14-24 (`rootCmd.AddCommand` in `init()`); `cmd/mimir/scan.go` lines 24-39 (per-command flag `init()`).
**Apply to:** new `mimir hook` group and the `--git`/`--staged` flags on `scanCmd`.

### exec.Command arg-slice (no shell injection)
**Source:** RESEARCH Security V12 — `exec.CommandContext(ctx, "git", args...)` with `-C <repoRoot>`, never `sh -c` with interpolated paths. `exec.CommandContext` (not `exec.Command`) so context-cancel kills the git process (Pitfall 2).
**Apply to:** `gitscan/command.go`, hook-dir resolution in `hook.go`.

## No Analog Found

Files with no close match in the codebase (planner should use RESEARCH.md patterns instead):

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `internal/gitscan/command.go` | utility (process spawn) | streaming (exec pipe) | No existing code shells out to an external process or streams `StdoutPipe()` → `gitdiff.Parse`. Use RESEARCH Pattern 1 (verified probe) + Pitfall 2 (drain/`cmd.Wait()` cleanup). |
| `.pre-commit-hooks.yaml` | config manifest | — | No framework manifest exists. Use RESEARCH "Don't Hand-Roll" row (gitleaks `.pre-commit-hooks.yaml`: `id`/`name`/`entry`/`language: golang`/`pass_filenames: false`). |
| go-gitdiff streaming consume | — | streaming | First use of `github.com/gitleaks/go-gitdiff` in the repo — no in-repo analog; RESEARCH Patterns 1+2 (empirically verified) are the reference. |

## Metadata

**Analog search scope:** `internal/scanner/`, `internal/detect/`, `internal/finding/`, `internal/suppress/`, `internal/output/`, `cmd/mimir/`; go-gitdiff module cache (`patch_header.go` field verification).
**Files scanned:** 11 source/test files read in full + 1 module-cache header.
**Pattern extraction date:** 2026-05-30
```
