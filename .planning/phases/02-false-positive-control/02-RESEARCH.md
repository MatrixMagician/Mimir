# Phase 2: False-Positive Control (Suppression + Baseline) - Research

**Researched:** 2026-05-29
**Domain:** Secret-scanner noise control — inline ignore directives, gitignore-style path pruning, snapshot baselining
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Inline Ignore (SUP-01)**
- **D-01:** Placement — same-line trailing only. A directive suppresses a finding only when it appears on the SAME line as the secret. No line-above, no block ranges in v1. Matches gitleaks' `gitleaks:allow`.
- **D-02:** Targeting — blanket + optional rule ID. `mimir:ignore` suppresses all findings on that line; `mimir:ignore:<rule-id>` scopes to a single rule on that line.
- **D-03:** Recognition — substring match anywhere on the line. Any line containing the directive token triggers suppression regardless of comment syntax (language-agnostic, zero comment parsing). Detect at scan time, per line.
- **D-04:** Hint surfacing — opt-in via `--verbose`. Default human output stays one-line-per-finding (Phase 1 D-01). The paste-ready suppression hint (exact `// mimir:ignore` text **plus the finding's fingerprint**) is shown only under `--verbose` (or a dedicated `--explain`).

**`.mimirignore` + Default Allowlists (SUP-02 / SUP-04)**
- **D-05:** Mechanism — skip the file entirely (walk prune). A path matching `.mimirignore` OR a shipped default-noisy pattern is never opened or scanned; pruned during `filepath.WalkDir`. SUP-04 defaults are implemented as default path-prune globs, **NOT** via the content-regex `Allowlist.Paths` "scan-then-suppress" mechanism.
- **D-06:** Discovery — repo/scan-root only (single file). One `.mimirignore` at each scan root, patterns relative to that root. No nested per-directory files in v1. Glob matching uses `doublestar/v4` for `**` support.
- **D-07:** Overrides — negation patterns + master toggle. Defaults apply automatically. Users can re-include a default-excluded path with a gitignore-style `!pattern`, and can disable ALL shipped defaults via a config toggle (planner picks exact key, e.g. `extend.use_default_allowlists = false`).

**Baseline (SUP-03)**
- **D-08:** Workflow — flags on `mimir scan`. `--baseline-out <file>` writes the snapshot; `--baseline <file>` filters a subsequent scan to NEW findings only. No dedicated subcommand in v1. Default file name is a planner detail (suggest `.mimir-baseline.json`).
- **D-09:** Entry shape — full redacted finding records. Each baseline entry is the complete redacted `Finding` JSON (reusing Phase 1 OUT-02 schema). Phase 2 criterion 3 (no raw secret) holds by construction.
- **D-10:** Match key — OR-match: fingerprint OR content-hash. A scanned finding is suppressed if EITHER (a) its full fingerprint (`path:rule:hash16`) matches a baseline entry, OR (b) its path-independent content key (`rule-id + hash16`) matches a baseline entry. The content key needs no schema change — `rule-id` and `hash16` are the last two colon-delimited segments of the stored `fingerprint`.

**Suppression Transparency (cross-cutting)**
- **D-11:** Always show suppressed counts. Extend the Phase 1 end-of-scan summary with a suppression breakdown (e.g. `✓ no NEW secrets · 3 baselined · 2 ignored · 1 allowlisted · 11 paths excluded · 1,204 files · 0.8s`).
- **D-12:** `--show-suppressed` flag for per-finding audit. Re-includes suppressed findings in human and JSON output, each tagged with its reason (`baseline` | `inline-ignore` | `allowlist`). JSON gains optional `suppressed` (bool) and `suppression_reason` (string) fields, both `omitempty` so the Phase 1 stable schema (OUT-02) is preserved.
- **D-13:** Path-excluded files are counted, not enumerated. Pruned paths are reported only as an aggregate `N paths excluded` count (path list under `--verbose`). `--show-suppressed` does NOT re-scan excluded paths.

### Claude's Discretion
- **Suppression-layer precedence (attribution order):** sensible default is **path-prune → inline-ignore → content allowlist → baseline**, earliest-matching layer wins the reported reason. Path-prune is necessarily first. Relative order of inline-ignore / allowlist / baseline only affects which reason is attributed in `--show-suppressed`, not the suppressed/not-suppressed outcome.
- **Exact config key names/flags** (`--baseline-out`, `--baseline`, `--show-suppressed`, `--explain`, the defaults toggle), default baseline filename, baseline file top-level schema (version field, metadata), and the exact default-noisy glob set — open to standard approaches, constrained by requirements + CLAUDE.md.
- **`--show-suppressed` interaction with exit codes:** suppressed-but-shown findings should NOT flip the exit code to 1 (informational); confirm against IFACE-02 exit-code contract.

### Deferred Ideas (OUT OF SCOPE)
- Honoring `.gitignore` automatically (not adopted in v1).
- Nested per-directory `.mimirignore` (single root file only, D-06).
- Inline block-range suppression (`mimir:ignore-start`/`-end`) and line-above placement (D-01).
- Fingerprint-targeted inline ignore (`mimir:ignore:<fingerprint>`) — overlaps v2 SUP2-01.
- Interactive baseline audit / review-and-approve (v2 SUP2-02).
- Baseline staleness / merge / partial-update tooling — regenerate the whole baseline in v1.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| SUP-01 | Suppress a finding with an inline ignore comment (`// mimir:ignore`) | Per-line substring detection in `scanFile`/`ScanLine` (Pattern 1); gitleaks `gitleaks:allow` validates the approach |
| SUP-02 | Exclude paths/globs via a `.mimirignore` file | `doublestar.Match` with `**` + `!` negation, applied as `filepath.SkipDir`/skip in the WalkDir callback (Pattern 2) |
| SUP-03 | Baseline file so Mimir alerts only on NEW findings vs a snapshot | Post-scan filter stage; OR-match (full fingerprint OR rule+hash16 content key) over `encoding/json` baseline (Pattern 4); validated against gitleaks `IsNew` |
| SUP-04 | Ship sensible default allowlists for noisy paths | Default-noisy glob set (Don't Hand-Roll + State of the Art tables) implemented as walk-prune globs, master toggle (Pattern 2/3) |
</phase_requirements>

## Summary

Phase 2 is almost entirely "plumb new suppression layers into an existing, well-factored scanner" — it adds **zero new detection logic** and **one new dependency** (`doublestar/v4`, already in the module cache as a transitive dep, exact version pinned by CLAUDE.md). The Phase 1 codebase is unusually friendly to this work: the `Finding` fingerprint is already content-hash-based and forward-slash normalized (so the baseline's stability properties hold "by construction"), the `filepath.WalkDir` loop already demonstrates the `SkipDir` prune pattern (used today for `.git`), and the `Finding` JSON schema is reusable verbatim as the baseline entry format.

The four deliverables map cleanly onto four distinct integration points: **(1) inline ignore** is a per-line `strings.Contains` check in the file scan loop; **(2) `.mimirignore` + default globs** are a walk-prune gate in the `WalkDir` callback using `doublestar.Match`; **(3) the baseline** is a post-scan filter stage reading a redacted-Finding JSON file and applying an OR-match; **(4) transparency** extends `Stats` and the output writers. The single most important architectural instruction for the planner: **the suppression layers must be ordered, decoupled stages**, because Phase 4 verification will later slot into the same post-scan pipeline position as the baseline filter.

**Primary recommendation:** Build a small `internal/suppress` package that owns the inline-directive matcher, the `.mimirignore`/default-glob path matcher, and the baseline OR-match filter as three independent, individually-testable units; wire path-prune into the walk, inline-ignore into the per-line loop, and the baseline filter as a discrete post-scan stage that returns annotated findings (suppressed bool + reason) so `--show-suppressed` and the summary counts fall out for free.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| `.mimirignore` + default-glob path exclusion (SUP-02/04) | Scanner walk (`scanner.Scan` WalkDir callback) | `internal/suppress` (matcher) / `internal/config` (load defaults + toggle) | Files must never be opened (D-05) → the decision belongs at the walk gate, before a file is enqueued |
| Inline `mimir:ignore` directive (SUP-01) | Per-line scan (`scanFile` loop / `engine.ScanLine`) | `internal/suppress` (directive parser) | The directive lives on the same physical line as the secret (D-01) → must be evaluated where the line text is in hand |
| Baseline OR-match filter (SUP-03) | Post-scan filter stage (new, in `scanner` or `cmd`) | `internal/suppress` (matcher) / `internal/finding` (fingerprint parse) | Operates on the complete finding set after the walk; decoupled so Phase 4 verify slots in here |
| Baseline file read/write (SUP-03) | `internal/finding` or `internal/suppress` (serialization) | `cmd` (flag wiring) | Reuses the redacted `Finding` JSON schema; `encoding/json` only |
| Suppression counts + `--show-suppressed` (D-11/12/13) | `internal/output` (human + json writers) + `scanner.Stats` | `cmd` (flag) | Reporting concern; reads the annotated findings + extended Stats |
| Exit-code interaction (IFACE-02) | `cmd/mimir/scan.go` (`runScan`) | — | Exit code is decided in `runScan`; must count only NON-suppressed findings |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `github.com/bmatcuk/doublestar/v4` | v4.10.0 | `**`/`?`/`[...]`/`{a,b}` glob matching for `.mimirignore` and default-noisy paths | Mandated by CLAUDE.md. `path/filepath.Match` does NOT support `**` recursive globs; doublestar does and is the common Go choice. `[VERIFIED: module cache @ v4.10.0, MIT]` |
| `encoding/json` (stdlib) | stdlib (Go 1.25/1.26) | Baseline file read + write (reuses `Finding` schema) | CLAUDE.md mandate — no third-party JSON lib. Already used by `internal/output/json.go`. `[CITED: CLAUDE.md]` |
| `strings` (stdlib) | stdlib | Inline-directive substring detection (`strings.Contains`) | Language-agnostic substring match (D-03) needs nothing more. Matches gitleaks' `gitleaks:allow` approach. `[CITED: gitleaks README]` |
| `path/filepath` (stdlib) | stdlib | `WalkDir` + `SkipDir` prune; `ToSlash` path normalization | Already the walk + prune mechanism in `scanner.Scan` (used for `.git`). `[VERIFIED: codebase scanner.go]` |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `github.com/pelletier/go-toml/v2` | v2.3.1 | Decode the new defaults-toggle key (e.g. `extend.use_default_allowlists`) | Only if the toggle lives in `.mimir.toml` (recommended — `extendSection` already exists). `[VERIFIED: go.mod]` |
| `github.com/stretchr/testify` | v1.11.1 | `require`/`assert` in new unit + fixture tests | All new tests, matching existing test files. `[VERIFIED: go.mod]` |
| `github.com/spf13/cobra` | v1.10.2 | New flags (`--baseline`, `--baseline-out`, `--show-suppressed`) | Flag wiring in `scan.go init()`. `[VERIFIED: go.mod]` |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `doublestar.Match` (string-based) | `doublestar.GlobWalk` (fs.FS-based walk) | `GlobWalk` would replace the existing `filepath.WalkDir`; rejected — the codebase already has a working WalkDir with `.git`/size/binary gates and per-file goroutine fan-out. Use `Match` against the repo-relative path inside the existing callback. |
| Defaults as embedded glob slice in Go | Defaults in the embedded `config/mimir.toml` | Both viable. The `[[allowlists]] paths` section in `mimir.toml` is content-regex (scan-then-suppress) and must NOT be reused for D-05 prune globs. Recommend a separate `[extend] default_path_excludes` TOML array OR a Go constant slice in `internal/suppress`. Planner decides; a Go constant keeps prune globs textually distinct from the regex allowlists and avoids confusion. |
| Baseline as JSON array of findings | Wrapped envelope `{version, generated_at, findings:[...]}` | Recommend the wrapped envelope (see Open Questions Q4) for forward-compat; gitleaks ships a bare array but Mimir benefits from a `version` field for the future SUP2 merge tooling. |

**Installation:**
```bash
# doublestar/v4 is the only new module dependency; pin the CLAUDE.md version
go get github.com/bmatcuk/doublestar/v4@v4.10.0
go mod tidy
```

**Version verification:** `doublestar/v4 v4.10.0` confirmed present in the local module cache (`~/go/pkg/mod/github.com/bmatcuk/doublestar/v4@v4.10.0`), MIT-licensed. This is the exact version pinned in CLAUDE.md (verified against proxy.golang.org 2026-05-22 in the CLAUDE.md Sources block). `go.sum` does not yet reference it as a direct dep — `go get`/`go mod tidy` will promote it.

## Package Legitimacy Audit

| Package | Registry | Age | Downloads | Source Repo | slopcheck | Disposition |
|---------|----------|-----|-----------|-------------|-----------|-------------|
| `github.com/bmatcuk/doublestar/v4` | Go module proxy | ~9 yrs (v1 2014; v4 2021) | Very high (transitive dep across Go ecosystem; gitleaks-adjacent tooling) | github.com/bmatcuk/doublestar | n/a (Go ecosystem; slopcheck is npm/PyPI-oriented) | Approved |

**Packages removed due to slopcheck [SLOP] verdict:** none
**Packages flagged as suspicious [SUS]:** none

*slopcheck targets npm/PyPI/cargo hallucination vectors and does not cover Go modules. doublestar legitimacy was verified by (1) presence in the local Go module cache at the exact CLAUDE.md-pinned version, (2) MIT license file present, (3) CLAUDE.md's HIGH-confidence proxy.golang.org verification on 2026-05-22, (4) it being a long-established, widely-depended-on package with a stable GitHub source. No `postinstall`-equivalent risk exists in the Go build model. `[VERIFIED: module cache + CLAUDE.md]`*

## Architecture Patterns

### System Architecture Diagram

```
                          mimir scan [paths] --baseline X --baseline-out Y --show-suppressed
                                          │
                                          ▼
                          ┌──────────────────────────────┐
                          │ cmd/mimir/scan.go: runScan    │
                          │  - load config (+ defaults    │
                          │    toggle)                    │
                          │  - load .mimirignore @ root   │
                          │  - load baseline file (json)  │
                          └──────────────┬────────────────┘
                                         │  builds path-matcher + baseline-matcher
                                         ▼
        ┌────────────────────── scanner.Scan (WalkDir) ───────────────────────┐
        │                                                                       │
        │   for each path:                                                      │
        │     ┌─ dir?  → .git / matched-prune-glob? ── yes ─▶ SkipDir           │
        │     │                                              (count excluded)   │
        │     └─ file? → matched-prune-glob? ── yes ─▶ skip (count excluded) ───┤  [LAYER 1: path prune — D-05]
        │                      │ no                                             │
        │                      ▼                                                │
        │            scanFile → per line:                                       │
        │              engine.ScanLine → []Finding                              │
        │              line contains mimir:ignore[:rule]? ─ yes ─▶ annotate     │  [LAYER 2: inline ignore — D-01..03]
        │                      │                            suppressed=inline   │
        │                      ▼ (content allowlist already applied in engine)  │  [LAYER 3: content allowlist — existing]
        │            collect findings (incl. annotated-suppressed)              │
        └───────────────────────────────┬───────────────────────────────────--┘
                                         │  []Finding (some annotated suppressed)
                                         ▼
                          ┌──────────────────────────────┐
                          │ POST-SCAN FILTER STAGE        │  [LAYER 4: baseline OR-match — D-10]
                          │  for each finding:            │
                          │   fullFP in baseline? OR      │  ◀── Phase 4 verify slots in HERE later
                          │   (rule+hash16) in baseline?  │      (keep decoupled)
                          │   → annotate suppressed=baseline
                          └──────────────┬────────────────┘
                                         │  annotated findings + Stats(counts by reason)
                                         ▼
                ┌────────────────────────────────────────────────┐
                │ output: human / json                            │
                │  - default: show only NON-suppressed            │
                │  - --show-suppressed: show all, tagged w/ reason│
                │  - summary: D-11 counts (baselined/ignored/…)   │
                │  - --baseline-out: write redacted Finding JSON  │
                └────────────────────────┬───────────────────────┘
                                         │
                                         ▼
                          exit code (IFACE-02): count NON-suppressed only
                          0 clean · 1 findings · 2 error · --exit-zero soft
```

### Recommended Project Structure
```
internal/
├── suppress/              # NEW — owns the three suppression mechanisms
│   ├── inline.go          # mimir:ignore[:rule-id] line directive parser (D-01..03)
│   ├── pathmatch.go       # .mimirignore + default-glob matcher (doublestar, !negation, D-05..07)
│   ├── baseline.go        # Load/Write baseline JSON + OR-match IsSuppressed (D-08..10)
│   └── *_test.go
├── finding/               # EXISTING — Finding + fingerprint (add Suppressed/Reason omitempty fields, D-12)
├── scanner/               # EXISTING — wire path-prune into Scan, inline check into scanFile, extend Stats (D-11)
├── detect/                # EXISTING — engine.ScanLine unchanged (inline check happens at the line loop)
├── config/                # EXISTING — add defaults-toggle key to extendSection; load .mimirignore is scanner/cmd concern
└── output/                # EXISTING — extend human + json for D-11/D-12
```

### Pattern 1: Inline `mimir:ignore` directive (SUP-01, D-01..D-03)
**What:** After `engine.ScanLine` returns findings for a line, check whether the SAME line text contains the directive token; if so, drop or annotate the matching findings.
**When to use:** In the per-line loop of `scanFile` (the line text is already in hand there; `engine.ScanLine` stays unchanged so the engine remains a pure detector).
**Example:**
```go
// internal/suppress/inline.go
// Source: pattern mirrors gitleaks gitleaks:allow (strings.Contains, same line).
package suppress

import "strings"

const directiveToken = "mimir:ignore"

// InlineDecision reports whether a line suppresses a finding for ruleID.
// D-02: bare "mimir:ignore" suppresses ALL rules on the line;
//       "mimir:ignore:<rule-id>" suppresses only that rule.
// D-03: substring match anywhere on the line, language-agnostic (no comment parsing).
func InlineSuppresses(line, ruleID string) bool {
    idx := strings.Index(line, directiveToken)
    if idx < 0 {
        return false
    }
    rest := line[idx+len(directiveToken):]
    // Scoped form: "mimir:ignore:rule-id"
    if strings.HasPrefix(rest, ":") {
        scoped := rest[1:]
        // take the rule-id token up to the next whitespace
        if sp := strings.IndexFunc(scoped, func(r rune) bool {
            return r == ' ' || r == '\t'
        }); sp >= 0 {
            scoped = scoped[:sp]
        }
        return scoped == ruleID
    }
    // Blanket form: "mimir:ignore" (not followed by ":") suppresses all rules.
    return true
}
```
*Caller (in `scanFile` loop): for each finding from `ScanLine`, if `InlineSuppresses(line, f.RuleID)` then mark `f.Suppressed=true; f.SuppressionReason="inline-ignore"` (when `--show-suppressed`) or drop it (default). Edge case: a directive line that contains BOTH a real secret AND `mimir:ignore` in a value — accepted per D-03 (substring, language-agnostic). The directive token itself must not trip a rule; verify in a fixture.*

### Pattern 2: `.mimirignore` + default-glob walk prune (SUP-02 / SUP-04, D-05..D-07)
**What:** Build a `PathMatcher` from (default globs unless toggled off) + (`.mimirignore` lines, including `!negations`). In the `WalkDir` callback, test the **repo-relative, forward-slash** path; on match prune (dirs → `filepath.SkipDir`, files → skip) and increment an excluded counter.
**When to use:** Inside the existing `scanner.Scan` WalkDir callback, BEFORE the size/binary gates (cheapest gate first; the file is never opened — D-05).
**Example:**
```go
// internal/suppress/pathmatch.go
// Source: doublestar v4.10.0 Match doc — "/**/" matches zero+ dirs; Match
// requires pattern to match ALL of name; uses '/' separator.
package suppress

import "github.com/bmatcuk/doublestar/v4"

type PathMatcher struct {
    includes []string // normal patterns → exclude on match
    excludes []string // !patterns → re-include (negation, gitignore-style)
}

// Excluded reports whether relPath (forward-slash, repo-relative) is pruned.
// Last-match-wins gitignore semantics: a later !pattern re-includes a path
// matched by an earlier exclude pattern.
func (m *PathMatcher) Excluded(relPath string, isDir bool) bool {
    excluded := false
    for _, p := range m.ordered { // ordered = patterns in file order, defaults first
        neg := strings.HasPrefix(p, "!")
        pat := strings.TrimPrefix(p, "!")
        if ok, _ := doublestar.Match(pat, relPath); ok {
            excluded = !neg
        }
        // also match a directory prefix so "vendor/" prunes the whole subtree
        if isDir {
            if ok, _ := doublestar.Match(pat, relPath+"/"); ok {
                excluded = !neg
            }
        }
    }
    return excluded
}
```
*Integration in `scanner.Scan` callback (after the `.git` skip, before size check):*
```go
rel, _ := filepath.Rel(root, path)
rel = filepath.ToSlash(rel)
if d.IsDir() {
    if matcher.Excluded(rel, true) {
        excludedPaths.Add(1)     // D-13: count, don't enumerate (verbose lists)
        return filepath.SkipDir  // prune whole subtree — never opened (D-05)
    }
    return nil
}
if matcher.Excluded(rel, false) {
    excludedPaths.Add(1)
    return nil                   // skip file — never opened
}
```
*Key doublestar facts: `Match` matches the FULL name (not substring), splits on `/`, and `**` must be surrounded by separators (`a/**/b`). For "prune everything under vendor/" the pattern `vendor/**` (or matching the dir name `vendor` directly when `isDir`) is what you want. Always `filepath.ToSlash` the rel-path first since patterns and the matcher assume `/`.*

### Pattern 3: Shipped default-noisy globs as prune globs (SUP-04, D-05)
**What:** A constant set of gitignore-style globs shipped in the binary, applied first (before `.mimirignore` lines so user `!negations` can override them), gated by a master toggle.
**When to use:** Construct the `PathMatcher` with defaults prepended unless `use_default_allowlists=false`.
**Example (recommended default set — mirrors gitleaks):**
```go
// internal/suppress/pathmatch.go
// Source: derived from gitleaks config/gitleaks.toml default allowlist paths.
var DefaultPathExcludes = []string{
    "**/vendor/**", "vendor/**",
    "**/node_modules/**", "node_modules/**",
    "**/.git/**",                      // belt-and-suspenders; .git already skipped
    "**/dist/**", "**/build/**",
    "**/*.min.js", "**/*.min.css",
    "**/*.map",                        // source maps
    "**/package-lock.json", "**/npm-shrinkwrap.json",
    "**/yarn.lock", "**/pnpm-lock.yaml",
    "**/go.sum",                       // go.mod can hold module paths; go.sum is pure hashes
    "**/Gemfile.lock", "**/poetry.lock", "**/Pipfile.lock",
    "**/composer.lock", "**/Cargo.lock",
    "**/*.snap",                       // jest snapshots
}
```
*Note: today `config/mimir.toml` has a `[[allowlists]] paths` block listing `go\.(?:mod|sum)$`, `vendor/`, `\.git/` as **content-regex** allowlists (scan-then-suppress). Per D-05 these noisy PATHS should move to prune globs; the planner should decide whether to leave the regex allowlist entries (they still work, just slower) or migrate them. Do NOT route SUP-04 defaults through the regex `Allowlist.Paths` mechanism.*

### Pattern 4: Baseline OR-match post-scan filter (SUP-03, D-08..D-10)
**What:** Load the baseline JSON into two lookup sets — full-fingerprint set and content-key set (`rule-id:hash16`, parsed from the last two colon segments of each fingerprint). A scanned finding is baselined if EITHER set contains its corresponding key.
**When to use:** A discrete stage AFTER the walk completes and AFTER inline/allowlist suppression, operating on the full finding slice. Keep it a standalone function so Phase 4 verify can be added as a sibling stage.
**Example:**
```go
// internal/suppress/baseline.go
// Source: design per CONTEXT.md D-10; gitleaks IsNew validates the snapshot-diff model.
package suppress

import (
    "encoding/json"
    "os"
    "strings"
    "github.com/MatrixMagician/mimir/internal/finding"
)

// Baseline holds the two membership sets derived from a snapshot file.
type Baseline struct {
    fullFP    map[string]struct{} // "path:rule:hash16"
    contentFP map[string]struct{} // "rule:hash16" (path-independent)
}

// contentKey extracts rule-id + hash16 (last two colon-delimited segments).
// fingerprint = path:rule_id:hash16  →  rule_id:hash16
func contentKey(fp string) string {
    i := strings.LastIndex(fp, ":")
    if i < 0 { return fp }
    j := strings.LastIndex(fp[:i], ":")
    if j < 0 { return fp }
    return fp[j+1:] // "rule_id:hash16"
}

func LoadBaseline(path string) (*Baseline, error) {
    data, err := os.ReadFile(path)
    if err != nil { return nil, err }
    var env baselineEnvelope            // {version, generated_at, findings:[]Finding}
    if err := json.Unmarshal(data, &env); err != nil { return nil, err }
    b := &Baseline{
        fullFP:    make(map[string]struct{}),
        contentFP: make(map[string]struct{}),
    }
    for _, f := range env.Findings {
        b.fullFP[f.Fingerprint] = struct{}{}
        b.contentFP[contentKey(f.Fingerprint)] = struct{}{}
    }
    return b, nil
}

// IsBaselined returns true if the finding matches the baseline by EITHER
// full fingerprint (a) OR path-independent content key (b) — D-10.
func (b *Baseline) IsBaselined(f finding.Finding) bool {
    if _, ok := b.fullFP[f.Fingerprint]; ok { return true }            // (a)
    if _, ok := b.contentFP[contentKey(f.Fingerprint)]; ok { return true } // (b) survives file-move
    return false
}
```
*Writing (`--baseline-out`): serialize the SAME redacted `[]Finding` (post-suppression or full set — see Open Questions Q5) through `encoding/json` with the envelope. The raw-secret-free invariant holds because `Finding` never stores the raw value (D-09). Keep the deterministic File→Line→Column sort so the committed baseline diffs cleanly in PRs.*

### Anti-Patterns to Avoid
- **Routing SUP-04 default noisy paths through the content-regex `Allowlist.Paths`:** violates D-05 (file would still be opened and scanned). Use walk-prune globs.
- **Modifying `engine.ScanLine` to know about inline ignore:** keeps the engine a pure detector; do inline suppression in the scanner's line loop or a `suppress` helper.
- **Putting the baseline match inside the per-file goroutine:** the baseline is a whole-finding-set concern; doing it per-file couples it to the walk and blocks the clean "Phase 4 verify slots in here" decoupling. Run it as a single post-`g.Wait()` stage.
- **Counting suppressed findings toward the exit code:** breaks IFACE-02 and D-12's "informational" guarantee. The exit code must count only NON-suppressed findings.
- **`strings.Contains(line, "mimir:ignore")` without distinguishing scoped vs blanket:** would make `mimir:ignore:other-rule` suppress everything. Parse the optional `:rule-id` suffix (Pattern 1).
- **Using `path/filepath.Match` for `.mimirignore`:** no `**` support — explicitly forbidden by CLAUDE.md. Use `doublestar.Match`.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Recursive `**` glob matching | A custom glob/regex translator for `.mimirignore` patterns | `doublestar.Match` (v4.10.0) | `**`, `{a,b}`, `[...]`, `?` and edge cases (trailing slash, mid-pattern `**`) are subtle; doublestar is the tested standard and a CLAUDE.md mandate |
| Baseline (de)serialization | A bespoke line/CSV baseline format | `encoding/json` over the existing `Finding` struct | Reuses the OUT-02 stable schema, stays raw-secret-free by construction, human-reviewable in PR diffs (D-09) |
| Content-key extraction | A new field on `Finding` or a re-hash | Parse the last two `:` segments of the existing `Fingerprint` | D-10 explicitly notes no schema change is needed — `rule-id` and `hash16` are already in the fingerprint string |
| Cross-platform path normalization | Custom backslash handling | `filepath.ToSlash` (already used in `finding.toSlash` + `scanner.scanFile`) | Fingerprint stability across Windows↔Linux already relies on this; reuse it for path matching too |
| Directory subtree prune | Manual recursion / readdir | `filepath.SkipDir` return from the `WalkDir` callback | Already the established `.git`-skip pattern in `scanner.Scan` |

**Key insight:** Phase 2 adds no novel algorithms — every hard part (glob semantics, JSON schema, fingerprint stability, subtree prune) is either an existing stdlib facility, an existing Phase 1 asset, or the one mandated dependency. The risk is in *wiring order and decoupling*, not in any single mechanism.

## Runtime State Inventory

> This phase is additive (new suppression layers), not a rename/refactor. The closest "state" concern is the baseline FILE format Mimir writes and later reads. Inventory included for completeness.

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | The baseline file (`.mimir-baseline.json`) that Mimir writes via `--baseline-out` and reads via `--baseline`. It stores redacted `Finding` JSON + (recommended) a `version` field. | Define the schema carefully NOW (Open Q4) — a v1 baseline must remain readable by future versions, or carry a `version` field to allow migration. No external migration needed (first introduction). |
| Live service config | None — Mimir touches no external service in this phase (verification is Phase 4). | None — verified by ROADMAP Phase 4 scope. |
| OS-registered state | None — no daemons, scheduled tasks, or hooks installed in this phase (pre-commit hook is Phase 3). | None — verified by ROADMAP Phase 3 scope. |
| Secrets/env vars | None — no new secret keys or env vars. `NO_COLOR` (existing) still honored. | None. |
| Build artifacts | `doublestar/v4` becomes a direct dependency (currently transitive/cache-only). `go.mod`/`go.sum` change. | `go get github.com/bmatcuk/doublestar/v4@v4.10.0 && go mod tidy`. The existing `config/mimir.toml` embedded ruleset may have its `[[allowlists]] paths` entries (vendor/.git/go.sum) reconsidered (Pattern 3 note) — embedded, rebuilds on `go build`. |

## Common Pitfalls

### Pitfall 1: Path-matcher tested against the wrong path form
**What goes wrong:** Patterns match against the absolute or OS-separator path instead of the repo-relative forward-slash path, so `vendor/**` never matches on Windows (backslashes) or matches inconsistently depending on the scan-root argument.
**Why it happens:** The WalkDir callback receives the OS-native `path` joined from `root`; `doublestar.Match` assumes `/`.
**How to avoid:** Compute `rel = filepath.ToSlash(filepath.Rel(root, path))` first (same normalization `scanner.scanFile` already does for findings), then match. Add a fixture asserting `vendor/sub/file.go` is pruned with a synthetic backslash input.
**Warning signs:** Defaults work in one repo but not another; Windows CI differs from Linux.

### Pitfall 2: Negation (`!pattern`) order dependence
**What goes wrong:** `!important/secrets.env` fails to re-include a path because the negation is evaluated before the broad exclude, or defaults are applied AFTER user patterns so a `!` can't override a default.
**Why it happens:** gitignore semantics are last-match-wins and order-sensitive; getting the ordering wrong silently breaks overrides (D-07).
**How to avoid:** Apply patterns in a single ordered pass (defaults FIRST, then `.mimirignore` lines in file order), last match wins (Pattern 2). Fixture: a default that excludes `*.min.js` plus a `!keep.min.js` line re-includes that one file.
**Warning signs:** `!` patterns appear to do nothing.

### Pitfall 3: Inline directive token self-matches or over-scopes
**What goes wrong:** (a) The literal token `mimir:ignore` in documentation/test code gets flagged or interferes; (b) `mimir:ignore:aws-access-token` accidentally suppresses a *different* rule on the same line because the code only did `strings.Contains(line, "mimir:ignore")`.
**Why it happens:** Naive substring check doesn't parse the optional `:rule-id` scope (D-02).
**How to avoid:** Parse the suffix as in Pattern 1: bare token → blanket; `:rule-id` → scoped to that exact rule ID only. Fixture: a line with two findings (two rules) and `mimir:ignore:rule-a` suppresses only rule-a.
**Warning signs:** Scoped ignores behave like blanket ignores, or vice-versa.

### Pitfall 4: Baseline file-move case fails (criterion 4)
**What goes wrong:** A baselined finding re-appears after the file is moved, failing Phase 2 success criterion 4.
**Why it happens:** Matching ONLY on the full fingerprint (`path:rule:hash16`) — the path changed, so the full FP differs. (This is gitleaks' documented limitation, ref Issue #1284.)
**How to avoid:** Implement the OR-match (D-10): the path-independent content key (`rule-id:hash16`) still matches after a move. This is the *entire reason* D-10 chose OR-match. Fixture: baseline a finding, move the file, re-scan → still suppressed.
**Warning signs:** Moving any file resurfaces baselined findings.

### Pitfall 5: Suppressed findings flip the exit code
**What goes wrong:** `--show-suppressed` (or a fully-baselined scan) exits 1, breaking CI green-on-clean.
**Why it happens:** `runScan` currently does `if len(findings) > 0 { os.Exit(1) }` — counting ALL findings.
**How to avoid:** After suppression, compute `newFindings` (non-suppressed) and base the exit code only on `len(newFindings)`. `--show-suppressed` adds rows to output but must not change `newFindings`. Confirm against IFACE-02. Fixture: a scan where every finding is baselined exits 0; same scan with `--show-suppressed` still exits 0 but prints the suppressed rows.
**Warning signs:** A clean-after-baseline repo fails CI.

## Code Examples

### Extending `Finding` for `--show-suppressed` (D-12)
```go
// internal/finding/finding.go — add two omitempty fields (OUT-02 schema preserved)
type Finding struct {
    // ... existing fields ...
    Suppressed        bool   `json:"suppressed,omitempty"`         // D-12
    SuppressionReason string `json:"suppression_reason,omitempty"` // baseline|inline-ignore|allowlist
}
```
*`omitempty` ensures consumers that don't pass `--show-suppressed` see the exact Phase 1 JSON schema (the reflect-inspection test in `finding_test.go` checks no raw secret; these new fields carry no secret).*

### Extending `Stats` for the D-11 summary
```go
// internal/scanner/scanner.go
type Stats struct {
    FilesScanned   int
    Duration       time.Duration
    PathsExcluded  int            // D-13 aggregate count
    Suppressed     map[string]int // reason → count: "baseline"|"inline-ignore"|"allowlist" (D-11)
}
```

### D-11 summary line (extends `output.WriteHuman`)
```
✓ no NEW secrets · 3 baselined · 2 ignored · 1 allowlisted · 11 paths excluded · 1,204 files · 0.8s
```
*Build from `Stats.Suppressed["baseline"]`, `["inline-ignore"]`, `["allowlist"]`, `Stats.PathsExcluded`. Omit zero-count clauses for readability, but ALWAYS show the line (trust-by-default, D-11) unless `--quiet`.*

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| gitleaks line-number fingerprint (`commit:file:rule:startline`) for baseline | Mimir content-hash fingerprint (`path:rule:hash16`) + OR-match content key | Mimir Phase 1 design (SUP-05) | Baseline survives line shifts AND file moves — strictly better than gitleaks' baseline (which breaks on both per Issue #1284) |
| `path/filepath.Match` for ignore globs | `doublestar.Match` (`**` support) | doublestar v4 (2021) | Recursive `**` and `{a,b}` alternation work; gitignore-style UX |
| Content-regex path allowlists ("scan then suppress") | Walk-prune globs ("never open") | gitleaks/common practice; Mimir D-05 | Faster + lower memory; cannot enumerate findings in excluded paths (accepted, D-13) |

**Deprecated/outdated:**
- The `[[allowlists]] paths` regex entries in `config/mimir.toml` for `vendor/`, `.git/`, `go.sum` are superseded by walk-prune globs for the SUP-04 noisy-path use case (they still function but scan-then-suppress; planner decides whether to migrate them — see Pattern 3).

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Default-noisy glob set (vendor, node_modules, lockfiles, *.min.js, dist/build, snapshots, source maps) is the "sensible" SUP-04 default | Pattern 3 / State of the Art | Low — derived from gitleaks defaults; planner/user can trim. Over-excluding could hide a real secret in e.g. a lockfile, but `!negation` + master toggle (D-07) provide escape hatches |
| A2 | Baseline envelope should carry `version` + `generated_at` rather than a bare array | Standard Stack / Open Q4 | Low — additive; a bare array also works. Recommended for forward-compat with v2 merge tooling |
| A3 | Inline directive `:rule-id` scope token terminates at whitespace | Pattern 1 | Low — matches the natural `// mimir:ignore:rule-id` form; a fixture confirms |
| A4 | Default config key for the master toggle is `extend.use_default_allowlists` | User Constraints / Config | None — CONTEXT.md explicitly leaves the exact key to the planner; this is a suggestion |
| A5 | `--baseline-out` writes the FULL finding set (not the post-suppression set) so the baseline is a complete snapshot | Open Q5 | Medium — affects baseline semantics; see Open Q5. Resolve before implementing |

## Open Questions

1. **Should the master toggle live in `.mimir.toml` (`extend`) or as a CLI flag (or both)?**
   - What we know: `extendSection` already exists in config; CONTEXT.md suggests `extend.use_default_allowlists = false`.
   - What's unclear: whether a `--no-default-excludes` flag is also wanted.
   - Recommendation: TOML key (persistent, project-level) as primary; a flag is cheap to add if desired. Planner decides.

2. **Migrate or keep the existing `[[allowlists]] paths` regex entries in `config/mimir.toml`?**
   - What we know: They currently suppress `vendor/`, `.git/`, `go.sum` via scan-then-suppress (slower, against D-05's spirit for noisy paths).
   - What's unclear: whether removing them changes any Phase 1 test expectation.
   - Recommendation: Keep them for now (harmless), add the prune globs as the primary mechanism; revisit migration if a test conflicts. Check `config_test.go`/`scanner_test.go` for assertions on those paths before removing.

3. **Where does the post-scan baseline filter live — `scanner` or `cmd`?**
   - What we know: It must be decoupled (Phase 4 verify slots in the same position).
   - Recommendation: A standalone function in `internal/suppress` called from `runScan` (or a thin `scanner` post-stage) operating on `[]Finding`. Keeping it out of the per-file goroutine is the load-bearing requirement.

4. **Baseline top-level schema: bare `[]Finding` array vs. wrapped envelope?**
   - Recommendation (A2): `{"version": 1, "generated_at": "<rfc3339>", "findings": [...]}`. Lets future versions detect/migrate format and aids human review. Low cost.

5. **Does `--baseline-out` snapshot ALL findings or only post-suppression findings?**
   - What we know: D-09 says "the complete redacted Finding JSON"; the intent is "the set of findings you're accepting as known."
   - What's unclear: whether inline-ignored / allowlisted / path-excluded findings should appear in the baseline.
   - Recommendation: Write the findings that WOULD be reported (i.e. after inline/allowlist suppression but those are already dropped; path-excluded never produce findings). I.e. snapshot the reportable finding set, NOT the suppressed ones. Confirm with user during planning (affects A5). Excluded paths can't be in the baseline anyway (never scanned, D-13).

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Go toolchain | build/test | ✓ (per CLAUDE.md: `go1.26.2` local; `go 1.25` floor in go.mod) | 1.25/1.26 | — |
| `github.com/bmatcuk/doublestar/v4` | SUP-02/04 glob matching | ✓ (module cache) | v4.10.0 | None needed (mandated dep) |
| git | NOT required this phase (history is Phase 3) | ✓ | 2.54.0 | — (unused in Phase 2) |

**Missing dependencies with no fallback:** None.
**Missing dependencies with fallback:** None.

*Note: the orchestrator's shell sometimes reports `go: command not found` (PATH not loaded in non-interactive shell), but Go is installed (module cache populated, CLAUDE.md confirms `go1.26.2`). Execution tasks should source the user profile or use the absolute `go` path.*

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Go stdlib `testing` + `github.com/stretchr/testify` v1.11.1 (`require`/`assert`) |
| Config file | none — `go test` convention |
| Quick run command | `go test ./internal/suppress/... -run <Name> -race` |
| Full suite command | `go test ./... -race` |

*Existing test patterns to reuse: black-box CLI tests in `cmd/mimir/scan_test.go` use `TestMain` + `os/exec` (because `runScan` calls `os.Exit`, in-process testing is unreliable — exit codes MUST be tested via the compiled binary). Unit tests in `internal/*` use `t.TempDir()` + `testify/require`. The `finding_test.go` reflect-inspection raw-secret guard must continue to pass after adding the two `omitempty` fields.*

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| SUP-01 | `mimir:ignore` on the secret's line drops that finding; `mimir:ignore:rule-a` scopes to one rule | unit | `go test ./internal/suppress/ -run TestInline -race` | ❌ Wave 0 |
| SUP-01 | Finding message under `--verbose` shows paste-ready `mimir:ignore` + fingerprint (criterion 1) | integration (CLI) | `go test ./cmd/mimir/ -run TestVerboseHint -race` | ❌ Wave 0 |
| SUP-02 | `.mimirignore` glob (`**`) prunes matching paths; `!negation` re-includes | unit | `go test ./internal/suppress/ -run TestPathMatch -race` | ❌ Wave 0 |
| SUP-02 | Pruned files are never opened (walk-prune), counted not enumerated (D-13) | unit (scanner) | `go test ./internal/scanner/ -run TestWalkPrune -race` | ❌ Wave 0 |
| SUP-04 | Out-of-box defaults keep `vendor/`, `node_modules/`, `*.min.js`, lockfiles quiet on first run; master toggle disables them (criterion 2) | integration | `go test ./cmd/mimir/ -run TestDefaultExcludes -race` | ❌ Wave 0 |
| SUP-03 | `--baseline-out` writes redacted Finding JSON containing NO raw secret (criterion 3) | unit + self-scan | `go test ./internal/suppress/ -run TestBaselineNoRawSecret -race` | ❌ Wave 0 |
| SUP-03 | `--baseline` re-scan reports only NEW findings | integration | `go test ./cmd/mimir/ -run TestBaselineNewOnly -race` | ❌ Wave 0 |
| SUP-03/crit-4 | Baselined finding stays suppressed after (a) blank-line insert above, (b) file move, (c) Windows↔Linux path diff | unit (OR-match) | `go test ./internal/suppress/ -run TestBaselineStability -race` | ❌ Wave 0 |
| D-11 | Summary shows suppressed-by-reason counts + paths-excluded count | unit (output) | `go test ./internal/output/ -run TestSuppressionSummary -race` | ❌ Wave 0 |
| D-12 | `--show-suppressed` re-includes findings tagged with reason in human + JSON; JSON keeps OUT-02 schema otherwise | integration | `go test ./cmd/mimir/ -run TestShowSuppressed -race` | ❌ Wave 0 |
| IFACE-02 | All-baselined scan exits 0; `--show-suppressed` does not flip exit to 1 | integration (CLI exit code) | `go test ./cmd/mimir/ -run TestSuppressedExitCode -race` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `go test ./internal/suppress/... -race` (+ the touched package's tests)
- **Per wave merge:** `go test ./... -race`
- **Phase gate:** `go test ./... -race` green AND `go vet ./...` / golangci-lint (gosec enabled) clean before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `internal/suppress/inline_test.go` — covers SUP-01 (blanket + scoped + token-self-match edge)
- [ ] `internal/suppress/pathmatch_test.go` — covers SUP-02/SUP-04 (`**`, `!negation`, defaults, toggle, ToSlash)
- [ ] `internal/suppress/baseline_test.go` — covers SUP-03 + criterion-4 stability (the 3 transformations), no-raw-secret
- [ ] `internal/scanner/scanner_test.go` additions — walk-prune never-opens + excluded count (D-13)
- [ ] `internal/output/output_test.go` additions — D-11 summary, D-12 JSON `omitempty` fields
- [ ] `cmd/mimir/scan_test.go` additions — `--baseline`/`--baseline-out`/`--show-suppressed`/`--verbose` hint + exit-code (via `os/exec` binary)
- [ ] **Fixture: a "dirty" test repo** under `testdata/` containing: a real fixture secret, a noisy `vendor/`/`node_modules/` dir, a `*.min.js`, a lockfile, a file with an inline `mimir:ignore`, and a baseline JSON — PLUS a moved-file and blank-line-inserted variant to exercise criterion 4. Reuse the existing fixture-secret values from Phase 1 tests; ensure `.semgrepignore` rules from MEMORY are respected (no fabricated commit-block hooks).

### Criterion-4 stability validation (the load-bearing test)
Build the fixture once, derive three transformed copies, assert the baselined finding is suppressed in all three:
```go
// internal/suppress/baseline_test.go (sketch)
// Source: design per CONTEXT.md D-10; gitleaks IsNew comparison.
func TestBaselineStability(t *testing.T) {
    // base finding fingerprint: "src/app.go:aws-access-token:<hash16>"
    bl := baselineWith("src/app.go:aws-access-token:abc123def4567890")

    // (a) blank-line insert above → line changes, fingerprint has no line → same FP
    require.True(t, bl.IsBaselined(findingFP("src/app.go:aws-access-token:abc123def4567890")))
    // (b) file move → path changes → full FP differs but content key (rule:hash16) matches
    require.True(t, bl.IsBaselined(findingFP("lib/app.go:aws-access-token:abc123def4567890")))
    // (c) Windows path → normalized to forward-slash before fingerprinting → same FP
    require.True(t, bl.IsBaselined(findingFP("src/app.go:aws-access-token:abc123def4567890")))
    // genuinely new secret (different hash) → NOT baselined
    require.False(t, bl.IsBaselined(findingFP("src/app.go:aws-access-token:0000000000000000")))
}
```
*(a) and (c) are inherent to the Phase 1 fingerprint (line-independent, ToSlash-normalized) and need only a regression assertion; (b) is the OR-match's reason to exist and is the must-pass case.*

## Security Domain

> `security_enforcement` is not set to `false` in config.json → treated as enabled.

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | No auth in this phase (verification is Phase 4) |
| V3 Session Management | no | N/A (CLI tool) |
| V4 Access Control | no | Reads local files only; no privilege boundary added |
| V5 Input Validation | yes | `.mimirignore` patterns and baseline JSON are untrusted input: validate globs with `doublestar.ValidatePattern` and reject malformed patterns with a clear error (mirrors DET-05's RE2-reject pattern); `json.Unmarshal` into a typed envelope, reject on decode error |
| V6 Cryptography | no (reuse) | Fingerprint hashing (sha256) already done in Phase 1; this phase only PARSES the existing hash16 substring — introduces no new crypto |
| V14 Config | yes | The defaults master-toggle and baseline path are config inputs; document precedence; do not let a malformed `.mimirignore` silently disable all exclusion (fail loud, like CFG broken-config → exit 2) |

### Known Threat Patterns for a Go secret-scanner suppression layer

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Raw secret leaks into the committed baseline file | Information Disclosure | Reuse the redact-at-`Finding`-boundary invariant (D-09); add a self-scan test asserting no fixture-secret string appears in `--baseline-out` output (mirrors Phase 1 OUT-03 self-scan) |
| Malformed `.mimirignore` ReDoS / pathological glob | Denial of Service | doublestar is linear-ish and not regex-backtracking; still cap pattern count sanity and validate with `ValidatePattern`. (CLAUDE.md already forbids `regexp2`; no backtracking engine is introduced.) |
| Over-broad default excludes hide a real secret | Tampering (trust erosion) | Master toggle + `!negation` (D-07); ALWAYS show `N paths excluded` count (D-11) so suppression is never silent — directly serves the PROJECT.md trust value |
| Suppressed finding silently flips CI to green when it shouldn't | Repudiation / trust | Exit code counts only NON-suppressed findings; D-11 count makes hidden findings auditable; `--show-suppressed` provides the full audit trail |
| Path traversal via baseline/ignore path argument | Tampering | `os.ReadFile` on the user-supplied `--baseline` path is acceptable (user already controls their FS); no traversal amplification since Mimir only reads |

## Sources

### Primary (HIGH confidence)
- **Mimir codebase** (read directly): `internal/finding/finding.go` (fingerprint format + redact invariant), `internal/scanner/scanner.go` (WalkDir + SkipDir prune, scanFile line loop, ToSlash), `internal/detect/engine.go` (ScanLine + isAllowlisted), `internal/config/config.go` (Allowlist, extendSection.Path reserved, merge model), `internal/output/{human,json}.go` (Stats summary, OUT-02 schema), `cmd/mimir/scan.go` (flag wiring + exit-code logic), `config/mimir.toml` (existing allowlist paths).
- **doublestar/v4 v4.10.0 source** (`~/go/pkg/mod/.../match.go`) — `Match` uses `/` separator, matches full name, `**` must be separator-surrounded; `ValidatePattern` available. MIT license confirmed.
- **CONTEXT.md / REQUIREMENTS.md / ROADMAP.md / CLAUDE.md** — locked decisions D-01..D-13, SUP-01..04, success criteria, mandated stack.
- **.planning/config.json** — `nyquist_validation: true` (Validation Architecture required).

### Secondary (MEDIUM confidence)
- gitleaks DeepWiki "Allowlists & Baselines" + WebSearch — `LoadBaseline`/`IsNew` in `detect/baseline.go`, line-number fingerprint, redaction handling. Validates Mimir's snapshot-diff model AND confirms Mimir's content-hash OR-match is strictly better for file-move (gitleaks Issue #1284 documents the limitation).
- gitleaks README + WebSearch — `gitleaks:allow` same-line `strings.Contains` directive (validates SUP-01/D-01..03).
- gitleaks `config/gitleaks.toml` (WebSearch summary) — default allowlist paths (vendor, node_modules, lockfiles, min.js) informing the SUP-04 default glob set.

### Tertiary (LOW confidence)
- None — all material claims cross-verified against codebase or gitleaks primary behavior.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — single new dep, version verified in module cache + CLAUDE.md, all others already in go.mod.
- Architecture: HIGH — integration points read directly from Phase 1 source; the four layers map onto existing, identified hooks.
- Pitfalls: HIGH — derived from concrete code (exit-code logic, ToSlash usage) and gitleaks' documented baseline limitation.
- Default glob set / baseline schema: MEDIUM — sensible defaults (A1/A2/A5 in Assumptions Log) that the planner/user should confirm.

**Research date:** 2026-05-29
**Valid until:** 2026-06-28 (stable domain; doublestar + gitleaks behavior change slowly)
