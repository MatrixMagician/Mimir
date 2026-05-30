# Phase 2: False-Positive Control (Suppression + Baseline) - Pattern Map

**Mapped:** 2026-05-29
**Files analyzed:** 11 (4 new, 7 modified)
**Analogs found:** 11 / 11 (all in-repo Phase 1 source)

Module path: `github.com/MatrixMagician/mimir`. Go floor `go 1.25.0` (go.mod).
`doublestar/v4` is NOT yet a direct dep — `go get github.com/bmatcuk/doublestar/v4@v4.10.0 && go mod tidy` promotes it (RESEARCH.md §Installation).

## File Classification

| New/Modified File | New? | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|------|-----------|----------------|---------------|
| `internal/suppress/inline.go` | NEW | utility (directive parser) | transform (string → bool) | `internal/detect/engine.go` `isAllowlisted` | role-match (pure predicate) |
| `internal/suppress/pathmatch.go` | NEW | utility (glob matcher) | transform (path → bool) | `internal/config/config.go` `Allowlist` compile + `engine.isAllowlisted` path loop | role-match |
| `internal/suppress/baseline.go` | NEW | service (load/write/match) | file-I/O + CRUD (lookup) | `internal/output/json.go` (envelope + `encoding/json`) + `internal/finding/finding.go` (fingerprint) | role+flow match |
| `internal/suppress/*_test.go` | NEW | test | — | `internal/config/config_test.go` (`t.TempDir`+testify) ; `internal/detect/engine_test.go` | role-match |
| `internal/scanner/scanner.go` | MOD | service (walk orchestration) | event-driven (WalkDir callback) | self — `Scan` `.git` SkipDir prune + `scanFile` line loop + `Stats` | exact (extend in place) |
| `internal/finding/finding.go` | MOD | model | transform | self — `Finding` struct + JSON tags | exact (add 2 omitempty fields) |
| `internal/config/config.go` | MOD | config | transform (decode) | self — `extendSection` + `compile` | exact (add toggle key) |
| `internal/output/human.go` | MOD | utility (writer) | request-response (render) | self — `WriteHuman` summary line | exact (extend summary) |
| `internal/output/json.go` | MOD | utility (writer) | request-response (render) | self — `ScanSummary` struct | exact (extend summary) |
| `cmd/mimir/scan.go` | MOD | controller (CLI command) | request-response | self — `runScan` + `init()` flags | exact (add flags + post-scan stage + exit-code fix) |
| `cmd/mimir/scan_test.go` | MOD | test (CLI/exit-code) | — | self — `TestMain` + `runMimir` os/exec helper | exact |
| `config/mimir.toml` | MOD (optional) | config (embedded ruleset) | — | self — `[[allowlists]] paths` block | exact (Open Q2 — keep or migrate) |

**Detection engine note:** `internal/detect/engine.go` is read-as-analog only — RESEARCH.md anti-pattern explicitly forbids teaching `ScanLine` about inline ignore. Do NOT modify it; inline suppression attaches at the `scanFile` line loop.

## Pattern Assignments

### `internal/suppress/inline.go` (NEW — utility, transform)

**Analog:** `internal/detect/engine.go` `isAllowlisted` (a pure boolean predicate over a value+path; same shape as the needed `InlineSuppresses(line, ruleID) bool`).

**Predicate-style pattern to mirror** (`internal/detect/engine.go:153-169`):
```go
// isAllowlisted returns true if rawSecret or filePath matches any allowlist entry.
func (e *Engine) isAllowlisted(rawSecret, filePath string, allowlists []config.Allowlist) bool {
	for _, al := range allowlists {
		for _, re := range al.CompiledRegexes {
			if re.MatchString(rawSecret) {
				return true
			}
		}
		...
	}
	return false
}
```

**Implementation (from RESEARCH.md Pattern 1, D-01..D-03):** package-level `const directiveToken = "mimir:ignore"`; `strings.Index` to find token, parse optional `:rule-id` suffix terminating at whitespace; bare token = blanket (all rules on line), `:rule-id` = scoped to that exact rule. `strings` only — no comment parsing (D-03 substring, language-agnostic).

**Caller wiring** is in `scanFile` (see scanner.go assignment). The engine stays a pure detector.

**Pitfalls (RESEARCH.md):** Pitfall 3 — naive `strings.Contains(line, "mimir:ignore")` makes `mimir:ignore:other-rule` over-suppress; the literal token in docs/test code must not self-flag. Fixture: line with two rules + `mimir:ignore:rule-a` suppresses only rule-a.

---

### `internal/suppress/pathmatch.go` (NEW — utility, transform)

**Analog:** `internal/config/config.go` `Allowlist` + `compile` (pattern-set held in a struct, built once at load; loop-and-match) AND the scanner's existing `.git` prune (the consumer).

**Construction pattern to mirror** (compile-once into a struct — `config.go:198-220`): build a `PathMatcher{ordered []string}` with defaults prepended unless toggled off, then `.mimirignore` lines in file order (last-match-wins, D-07).

**`.git` SkipDir prune (the integration analog)** (`internal/scanner/scanner.go:76-87`):
```go
// Skip .git directory
if d.IsDir() {
	if d.Name() == ".git" {
		return filepath.SkipDir
	}
	return nil
}
// Only process regular files
if !d.Type().IsRegular() {
	return nil
}
```

**Implementation (RESEARCH.md Pattern 2/3):** `github.com/bmatcuk/doublestar/v4` `Match` (NOT `path/filepath.Match` — no `**`). `Excluded(relPath string, isDir bool) bool` — single ordered pass, `!` negation re-includes (last match wins). `DefaultPathExcludes` Go-constant slice (Pattern 3 set: `**/vendor/**`, `**/node_modules/**`, `**/*.min.js`, lockfiles, etc.). Validate user patterns with `doublestar.ValidatePattern` (Security Domain V5; mirror `compile`'s RE2-reject error style at config.go:228).

**Pitfalls:** Pitfall 1 — match against `filepath.ToSlash(filepath.Rel(root, path))`, not the OS path (doublestar assumes `/`). Pitfall 2 — defaults FIRST then file order, last-match-wins, or `!` overrides silently break.

---

### `internal/suppress/baseline.go` (NEW — service, file-I/O + lookup CRUD)

**Analog (serialization):** `internal/output/json.go` (`ScanResult` envelope + `encoding/json` encoder). **Analog (key parsing):** `internal/finding/finding.go` `computeFingerprint`.

**Envelope + encoder pattern to mirror** (`internal/output/json.go:11-46`):
```go
type ScanResult struct {
	Findings []finding.Finding `json:"findings"`
	Summary  ScanSummary       `json:"summary"`
}
...
enc := json.NewEncoder(w)
enc.SetIndent("", "  ")
return enc.Encode(result)
```
Baseline envelope (RESEARCH.md Open Q4 / A2): `{"version":1,"generated_at":"<rfc3339>","findings":[...]}` reusing `[]finding.Finding` verbatim (D-09).

**Fingerprint format the content-key parser depends on** (`internal/finding/finding.go:64-71`):
```go
func computeFingerprint(repoRelPath, ruleID, rawSecret string) string {
	normalizedPath := toSlash(repoRelPath)
	h := sha256.Sum256([]byte(rawSecret))
	hashPrefix := hex.EncodeToString(h[:])[:16] // first 8 bytes = 16 hex chars
	return normalizedPath + ":" + ruleID + ":" + hashPrefix
}
```
So `Fingerprint = path:rule_id:hash16`. The content key = last two `:` segments (`rule_id:hash16`), parsed with `strings.LastIndex` twice (RESEARCH.md `contentKey`). NO schema change needed (D-10).

**Implementation (RESEARCH.md Pattern 4):** `LoadBaseline(path)` → two `map[string]struct{}` sets (`fullFP`, `contentFP`). `IsBaselined(f) bool` returns true if EITHER set matches (OR-match; content-key survives file move — Pitfall 4, the must-pass criterion-4 case). Writer reuses the deterministic File→Line→Column sort already in `scanner.Scan` (lines 137-145) for clean PR diffs. Decode into a typed envelope; reject on `json.Unmarshal` error (Security V5).

**Security invariant:** `Finding` never stores the raw value (finding.go:25-36, 92-104) so baseline is raw-secret-free by construction (D-09). Add a self-scan test asserting no fixture-secret string appears in `--baseline-out` output (mirrors Phase 1 OUT-03).

---

### `internal/scanner/scanner.go` (MOD — service, event-driven)

**Analog:** self. Three in-place extensions.

**(1) Path-prune in the WalkDir callback** — insert AFTER the `.git` skip block (scanner.go:76-87), BEFORE the size gate (scanner.go:89-101), so files are never opened (D-05). The callback already computes nothing rel-relative for dirs; add:
```go
rel, _ := filepath.Rel(root, path)
rel = filepath.ToSlash(rel)
if d.IsDir() {
	if matcher.Excluded(rel, true) { excludedPaths.Add(1); return filepath.SkipDir }
	return nil
}
if matcher.Excluded(rel, false) { excludedPaths.Add(1); return nil }
```
Note `scanFile` already does this exact normalization at scanner.go:181-187 — reuse the same `filepath.Rel`+`ToSlash`+`TrimPrefix "./"` recipe.

**(2) Inline-ignore in the per-line loop** (`scanner.go:194-206`) — after `ScanLine` returns:
```go
lineFindings := s.engine.ScanLine(line, relPath, lineNum)
// NEW: for each f, if suppress.InlineSuppresses(line, f.RuleID):
//   drop it (default) OR annotate f.Suppressed=true, f.SuppressionReason="inline-ignore" (--show-suppressed)
```
The line text is already in hand here (`line := scanner.Text()`) — this is why inline detection belongs here, not in the engine.

**(3) Extend `Stats`** (`scanner.go:24-28`, current):
```go
type Stats struct {
	FilesScanned int
	Duration     time.Duration
}
```
Add (RESEARCH.md Code Examples): `PathsExcluded int` (D-13 aggregate) and `Suppressed map[string]int` (reason→count, D-11). Use `atomic.Int64` for the excluded counter inside the concurrent walk (mirrors the existing `filesScanned atomic.Int64` at scanner.go:55, 115).

**Decoupling constraint (RESEARCH.md anti-pattern):** do NOT run the baseline match inside the per-file goroutine. The baseline filter is a single post-`g.Wait()` stage (after scanner.go:132) so Phase 4 verify slots into the same position.

---

### `internal/finding/finding.go` (MOD — model)

**Analog:** self. Add two `omitempty` fields to the `Finding` struct (finding.go:25-36):
```go
Suppressed        bool   `json:"suppressed,omitempty"`         // D-12
SuppressionReason string `json:"suppression_reason,omitempty"` // baseline|inline-ignore|allowlist
```
`omitempty` preserves the OUT-02 stable schema for consumers not passing `--show-suppressed`. These fields carry no secret — the reflect-inspection raw-secret guard in `finding_test.go` (referenced finding.go:6) must still pass after the change.

---

### `internal/config/config.go` (MOD — config)

**Analog:** self. `extendSection` already reserves `Path` "for Phase 2" (config.go:55-60):
```go
type extendSection struct {
	UseDefault    bool     `toml:"use_default"`
	DisabledRules []string `toml:"disabled_rules"`
	Path          string   `toml:"path"` // reserved for Phase 2; not implemented in Phase 1
}
```
Add the master defaults toggle here, e.g. `UseDefaultAllowlists bool `toml:"use_default_allowlists"`` (RESEARCH.md A4; exact key is planner discretion, default-on semantics). Decode is automatic via the existing `parseBytes`/`toml.Unmarshal` path (config.go:145-151) — no new loader. The `.mimirignore` FILE load itself is a scanner/cmd concern (RESEARCH.md structure), not config.

---

### `internal/output/human.go` + `internal/output/json.go` (MOD — writers)

**Analog:** self.

**Human summary** (`human.go:55-62`, current clean/warn branches):
```go
if len(findings) > 0 {
	fmt.Fprintf(w, "%s\n", warnStyle.Sprintf("⚠ %d finding(s) in %d file(s) · scanned %d files · %s", ...))
} else {
	fmt.Fprintf(w, "%s\n", okStyle.Sprintf("✓ no findings · scanned %d files · %s", ...))
}
```
Extend to the D-11 breakdown: `✓ no NEW secrets · 3 baselined · 2 ignored · 1 allowlisted · 11 paths excluded · 1,204 files · 0.8s`. Build from `Stats.Suppressed["baseline"|"inline-ignore"|"allowlist"]` and `Stats.PathsExcluded`; omit zero clauses but ALWAYS print the line unless `--quiet`. `--show-suppressed` adds per-finding rows tagged with reason (reuse the existing `Fprintf` finding-row format at human.go:46-47).

**JSON summary** (`json.go:18-23`):
```go
type ScanSummary struct {
	FilesScanned int   `json:"files_scanned"`
	FindingCount int   `json:"finding_count"`
	DurationMs   int64 `json:"duration_ms"`
}
```
Extend with suppressed-by-reason + paths-excluded fields (new fields are additive; existing three frozen per OUT-02). The new `Finding.Suppressed`/`SuppressionReason` omitempty fields flow through automatically since `ScanResult.Findings` is `[]finding.Finding`.

---

### `cmd/mimir/scan.go` (MOD — controller)

**Analog:** self.

**Flag registration** (`scan.go:22-33`, mirror existing `init()` style):
```go
scanCmd.Flags().StringP("format", "f", "human", "...")
scanCmd.Flags().Bool("exit-zero", false, "...")
scanCmd.Flags().BoolP("verbose", "v", false, "...")
```
Add: `--baseline-out <file>`, `--baseline <file>` (StringP, no shorthand), `--show-suppressed` (Bool), and `--explain`/extend `--verbose` for the D-04 paste-ready hint. Default baseline filename suggestion `.mimir-baseline.json` (planner discretion).

**Flag → behavior wiring** mirrors scan.go:51-59 (`cmd.Flags().GetX` → set on cfg / local var).

**Post-scan baseline stage** — insert between `s.Scan(...)` (scan.go:66) and output (scan.go:79). Load baseline via `suppress.LoadBaseline`, annotate/drop findings, accumulate `Stats.Suppressed` counts. This is the discrete decoupled stage (RESEARCH.md Open Q3 — lives in `internal/suppress`, called from `runScan`).

**Exit-code fix (CRITICAL — Pitfall 5 / IFACE-02)** — current (scan.go:91-93):
```go
exitZero, _ := cmd.Flags().GetBool("exit-zero")
if len(findings) > 0 && !exitZero {
	os.Exit(1)
}
```
Must change to count only NON-suppressed findings: `if len(newFindings) > 0 && !exitZero`. `--show-suppressed` adds output rows but must NOT flip the exit code (D-12 informational guarantee). An all-baselined scan exits 0.

---

### `cmd/mimir/scan_test.go` (MOD — CLI/exit-code test)

**Analog:** self. Exit codes MUST be tested via the compiled binary because `runScan` calls `os.Exit` (in-process testing unreliable). Reuse the existing harness verbatim:
- `TestMain` builds once to `/tmp/mimir-cmd-test` (scan_test.go:14-35)
- `runMimir(t, args...) (stdout, stderr, exitCode)` os/exec helper (scan_test.go:45-64)
- Pattern of `runMimir(t, "scan", "--no-color", "testdata/...")` + assert exit code (scan_test.go:67-88)

New cases (RESEARCH.md Test Map): `TestBaselineNewOnly`, `TestShowSuppressed`, `TestSuppressedExitCode` (all-baselined → 0; `--show-suppressed` still 0), `TestDefaultExcludes`, `TestVerboseHint`.

---

### `config/mimir.toml` (MOD — optional, Open Q2)

**Analog:** self. The existing `[[allowlists]] paths` block (mimir.toml:16-22) is content-regex scan-then-suppress:
```toml
[[allowlists]]
description = "noisy paths (suppression)"
paths = [
  'go\.(?:mod|sum)$',
  '(?:^|/)vendor/',
  '(?:^|/)\.git/',
]
```
RESEARCH.md Open Q2 / State-of-the-Art: these noisy PATHS are superseded by walk-prune globs (D-05). **Recommendation: keep them for now** (harmless, still function), add prune globs as the primary mechanism; only migrate if a `config_test.go`/`scanner_test.go` assertion conflicts. Do NOT route SUP-04 defaults through this regex mechanism (anti-pattern — file would still be opened).

## Shared Patterns

### Path normalization (forward-slash, repo-relative)
**Source:** `internal/scanner/scanner.go:181-187` and `internal/finding/finding.go:19-21` (`toSlash`)
**Apply to:** `pathmatch.go` matching, scanner walk-prune, any baseline path compare.
```go
relPath, err := filepath.Rel(scanRoot, filePath)
if err != nil { relPath = filePath }
relPath = filepath.ToSlash(relPath)
relPath = strings.TrimPrefix(relPath, "./")
```
Fingerprint stability across Windows↔Linux already depends on this (`finding.toSlash` uses `strings.ReplaceAll(path, \`\\`, "/")` + `filepath.ToSlash`). Reuse — do not hand-roll backslash handling.

### Subtree prune via filepath.SkipDir
**Source:** `internal/scanner/scanner.go:76-82` (`.git` skip)
**Apply to:** `.mimirignore`/default-glob directory prune (return `filepath.SkipDir` for matched dirs; `nil`/skip for matched files).

### Atomic counter inside the concurrent walk
**Source:** `internal/scanner/scanner.go:55,115` (`var filesScanned atomic.Int64` ... `filesScanned.Add(1)`)
**Apply to:** the `PathsExcluded` counter (incremented from the WalkDir callback, which runs single-threaded, but keep consistent with the existing atomic pattern).

### Compile-once pattern set into a struct
**Source:** `internal/config/config.go:198-220` (`compile` builds `[]Allowlist` with compiled regexes once at load)
**Apply to:** `PathMatcher` (build ordered pattern list once) and `Baseline` (build lookup maps once at `LoadBaseline`). Validate patterns at build time and reject with a descriptive error (mirror config.go:228 RE2-reject style; use `doublestar.ValidatePattern`).

### Pure boolean predicate (stateless, goroutine-safe)
**Source:** `internal/detect/engine.go:153-169` (`isAllowlisted`)
**Apply to:** `InlineSuppresses`, `PathMatcher.Excluded`, `Baseline.IsBaselined` — all pure predicates, individually unit-testable.

### Test conventions
**Unit (`internal/*`):** `t.TempDir()` + `github.com/stretchr/testify` `require`/`assert` — see `internal/config/config_test.go`, `internal/detect/engine_test.go`.
**CLI/exit-code (`cmd/mimir`):** compiled-binary os/exec harness — `TestMain` + `runMimir`, scan_test.go:14-64. Exit codes cannot be unit-tested in-process (os.Exit).
**Raw-secret guard:** the reflect-inspection test in `finding_test.go` must keep passing after the two new omitempty fields.

### Redact-at-boundary security invariant
**Source:** `internal/finding/finding.go` (package doc lines 3-6; `New` lines 87-104 — rawSecret never stored)
**Apply to:** baseline write (D-09 — reuse `Finding` verbatim, raw-secret-free by construction); never introduce a code path that serializes a raw value. Self-scan test on `--baseline-out` output.

## No Analog Found

None. Every Phase 2 file maps to an existing Phase 1 analog or extends an existing file in place. Phase 2 adds no novel algorithm (RESEARCH.md "Don't Hand-Roll" key insight) — the only genuinely new mechanism is `doublestar.Match` glob matching, which is the one mandated new dependency, not a hand-rolled component.

## Metadata

**Analog search scope:** `internal/{scanner,finding,config,detect,output}`, `cmd/mimir`, `config/`
**Files scanned (read in full):** scanner.go, finding.go, scan.go, config.go, engine.go, human.go, json.go, scan_test.go (head), mimir.toml (allowlist block)
**Source of truth:** Phase 1 working tree (read directly), 02-CONTEXT.md (D-01..D-13), 02-RESEARCH.md (Patterns 1-4, Pitfalls 1-5, Test Map)
**Pattern extraction date:** 2026-05-29
