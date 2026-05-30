# Phase 2: False-Positive Control (Suppression + Baseline) - Context

**Gathered:** 2026-05-28
**Status:** Ready for planning

<domain>
## Phase Boundary

Make Mimir trustworthy on a real, dirty repo without drowning the user in noise.
A developer can: suppress an individual false positive inline, exclude noisy
paths via a `.mimirignore` file (with sensible shipped defaults), and baseline
existing findings so only NEW secrets alert. All suppression is transparent —
the user always knows what was hidden and can audit it.

Delivers (requirements SUP-01, SUP-02, SUP-03, SUP-04):
- Inline `mimir:ignore` directive (SUP-01)
- `.mimirignore` path exclusion (SUP-02)
- Shipped default allowlists for noisy paths (SUP-04)
- Stable-fingerprint baseline so only NEW findings report (SUP-03)

**Explicitly NOT in this phase** (later phases own these):
- Git-history scan, staged-changes scan, pre-commit hook installer → Phase 3
- Live verification (AWS/GitHub network calls) → Phase 4
- Ignore-by-fingerprint as a standalone suppression mode (SUP2-01), interactive
  baseline audit (SUP2-02) → v2

</domain>

<decisions>
## Implementation Decisions

### Inline Ignore (SUP-01)
- **D-01:** **Placement — same-line trailing only.** A directive suppresses a
  finding only when it appears on the SAME line as the secret (e.g.
  `key = "..."  // mimir:ignore`). No line-above and no block ranges in v1
  (avoids "which line owns it" ambiguity and a scanner lookback). Matches
  gitleaks' `gitleaks:allow` model.
- **D-02:** **Targeting — blanket + optional rule ID.** `mimir:ignore`
  suppresses all findings on that line; `mimir:ignore:<rule-id>` scopes the
  suppression to a single rule on that line (so a different rule still alerts).
- **D-03:** **Recognition — substring match anywhere on the line.** Any line
  containing the directive token triggers suppression regardless of comment
  syntax — language-agnostic, zero comment-parsing, works in `.env`/yaml/toml.
  Matches gitleaks. (Implementation note: detect at scan time, per line.)
- **D-04:** **Hint surfacing — opt-in via `--verbose`.** The default human
  output stays a clean one-line-per-finding (Phase 1 D-01). The paste-ready
  suppression hint — the exact `// mimir:ignore` text **plus the finding's
  fingerprint** (Phase 2 criterion 1) — is shown only under `--verbose` (or a
  dedicated `--explain`). Keeps grep-friendly density by default.

### `.mimirignore` + Default Allowlists (SUP-02 / SUP-04)
- **D-05:** **Mechanism — skip the file entirely (walk prune).** A path matching
  `.mimirignore` OR a shipped default-noisy pattern is never opened or scanned;
  it is pruned during `filepath.WalkDir` (faster, lower memory). This is
  gitignore-style semantics. Default noisy paths (e.g. `vendor/`,
  `node_modules/`, `*.min.js`, lockfiles) are pruned the same way — i.e. SUP-04
  defaults are implemented as default path-prune globs, NOT via the existing
  content-regex `Allowlist.Paths` "scan-then-suppress" mechanism.
- **D-06:** **Discovery — repo/scan-root only (single file).** One
  `.mimirignore` at each scan root, patterns relative to that root. No nested
  per-directory `.mimirignore` in v1 (simpler matching + testing). Glob matching
  uses `doublestar/v4` for `**` support (per CLAUDE.md).
- **D-07:** **Overrides — negation patterns + master toggle.** Defaults apply
  automatically. Users can re-include a default-excluded path with a
  gitignore-style `!pattern` in `.mimirignore`, and can disable ALL shipped
  defaults via a config toggle (planner picks the exact key, e.g.
  `extend.use_default_allowlists = false`). Gives both ergonomic per-pattern
  recovery and a full escape hatch.

### Baseline (SUP-03)
- **D-08:** **Workflow — flags on `mimir scan`.** `--baseline-out <file>` writes
  the snapshot; `--baseline <file>` filters a subsequent scan to NEW findings
  only. No dedicated `baseline` subcommand in v1 (mirrors gitleaks
  `--baseline-path`). Default file name is a planner detail (suggest
  `.mimir-baseline.json`).
- **D-09:** **Entry shape — full redacted finding records.** Each baseline entry
  is the complete redacted `Finding` JSON (fingerprint + file/line/rule +
  redacted snippet), reusing the Phase 1 OUT-02 JSON schema. Human-reviewable in
  PR diffs and still raw-secret-free (the Finding model never stores the raw
  value — security invariant in `internal/finding/finding.go`). **Phase 2
  criterion 3 (committed baseline contains no raw secret) holds by construction.**
- **D-10:** **Match key — OR-match: fingerprint OR content-hash.** A scanned
  finding is suppressed if EITHER (a) its full fingerprint
  (`path:rule:hash16`) matches a baseline entry, OR (b) its path-independent
  content key (`rule-id + hash16`) matches a baseline entry. Rationale:
  - Blank-line insert above → fingerprint has no line number → stable (crit. 4)
  - Windows↔Linux path → path is forward-slash normalized → stable (crit. 4)
  - **File move → path changes → (a) fails but (b) still matches → stays
    suppressed (satisfies criterion 4's "file move" clause).** Strict
    path-inclusive membership alone would FAIL this (same limitation gitleaks
    has); the content-hash fallback is what makes criterion 4 pass.
  - A genuinely new secret in a new file → different hash → still alerts.
  - Accepted blind spot: the identical secret VALUE copied into a brand-new file
    stays suppressed — but it is the same compromised credential, already
    baselined, so this is acceptable.
  - **Implementation note:** the content key needs no schema change — `rule-id`
    and `hash16` are already the last two colon-delimited segments of the stored
    `fingerprint` string and can be parsed back out of each baseline entry.

### Suppression Transparency (cross-cutting trust)
- **D-11:** **Always show suppressed counts.** Extend the Phase 1 D-02
  end-of-scan summary with a suppression breakdown, e.g.
  `✓ no NEW secrets · 3 baselined · 2 ignored · 1 allowlisted · 11 paths excluded · 1,204 files · 0.8s`.
  Trust-by-default: a clean run still proves nothing was silently hidden.
- **D-12:** **`--show-suppressed` flag for per-finding audit.** A flag
  re-includes suppressed findings in both human and JSON output, each tagged
  with its suppression reason (`baseline` | `inline-ignore` | `allowlist`).
  JSON gains optional `suppressed` (bool) and `suppression_reason` (string)
  fields, both `omitempty` so the Phase 1 stable schema (OUT-02) is preserved
  for consumers that don't pass the flag.
- **D-13:** **Path-excluded files are counted, not enumerated.** Because
  `.mimirignore`/default-excluded paths are pruned from the walk (D-05) and
  never scanned, individual findings inside them cannot be listed. They are
  reported only as an aggregate `N paths excluded` count (with a path list
  under `--verbose`). `--show-suppressed` does NOT re-scan excluded paths
  (preserves the prune performance win and stays consistent with D-05).

### Claude's Discretion
- **Suppression-layer precedence (attribution order):** sensible default is
  **path-prune (`.mimirignore`/defaults) → inline-ignore → content allowlist →
  baseline**, earliest-matching layer wins the reported reason. Path-prune is
  necessarily first (file never scanned). The relative order of inline-ignore /
  allowlist / baseline only affects which reason is attributed in
  `--show-suppressed`, not the final suppressed/not-suppressed outcome.
- **Exact config key names/flags** (`--baseline-out`, `--baseline`,
  `--show-suppressed`, `--explain`, the defaults toggle), default baseline
  filename, baseline file top-level schema (version field, metadata), and the
  exact default-noisy glob set — open to standard approaches, constrained by
  requirements + CLAUDE.md. Planner/researcher decide.
- **`--show-suppressed` interaction with exit codes:** suppressed-but-shown
  findings should NOT flip the exit code to 1 (they are informational); planner
  to confirm against the IFACE-02 exit-code contract.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Locked technical stack & architecture (READ FIRST)
- `CLAUDE.md` — Locked stack/architecture. For Phase 2 specifically:
  `github.com/bmatcuk/doublestar/v4` for `**` glob matching of `.mimirignore`
  paths (NOT `path/filepath.Match`), go-toml/v2 for any new config keys,
  `encoding/json` for the baseline file, the redact-at-boundary security rule
  (baseline must never contain raw secrets), and the "lean binary" constraint.
  Not to be re-litigated.

### Project scope & requirements
- `.planning/PROJECT.md` — Core value (low false positives = adoption),
  "suppression must be ergonomic" usability constraint, Key Decisions table.
- `.planning/REQUIREMENTS.md` — SUP-01, SUP-02, SUP-03, SUP-04 definitions and
  the Traceability table. Note SUP-05 (stable fingerprint) is already complete
  in Phase 1 and is the foundation the baseline builds on.
- `.planning/ROADMAP.md` §"Phase 2" — Goal + 4 success criteria this phase must
  satisfy (note criterion 4's file-move clause drove decision D-10).

### Phase 1 foundations this phase builds on (READ — implementation depends on these)
- `internal/finding/finding.go` — The `Finding` struct and `computeFingerprint`
  (`path:rule_id:sha256[:16](rawSecret)`). The fingerprint is content-hash based
  and forward-slash normalized; the OR-match baseline key (D-10) parses
  `rule-id`/`hash16` back out of the fingerprint string. Security invariant:
  raw secret never stored — baseline reuse (D-09) inherits this.
- `internal/config/config.go` — Existing `Allowlist` (`Regexes` + `Paths`,
  compiled), `GlobalAllowlists`, `Config`, and `extendSection.Path` (already
  reserved "for Phase 2"). New `.mimirignore`/defaults logic and the
  defaults-toggle config key extend these structures.
- `internal/detect/engine.go` — `ScanLine` and `isAllowlisted`. Inline-ignore
  detection (D-01..D-03) and content-allowlist suppression attribution (D-12)
  interact here / at the scanner line loop.
- `internal/scanner/scanner.go` — `Scan` (the `filepath.WalkDir` loop that
  currently skips `.git`/binary/oversized) and `scanFile` (line loop, computes
  the repo-relative path). The walk-prune for `.mimirignore`/defaults (D-05)
  and the per-line inline-ignore check (D-03) attach here. `Stats` extends for
  the suppressed/excluded counts (D-11).

No external ADRs/specs beyond the above — requirements and decisions are fully
captured in this repo's `.planning/` docs, `CLAUDE.md`, and the Phase 1 source.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **Fingerprint scheme** (`finding.computeFingerprint`) — already
  line-number-independent and cross-platform normalized; the baseline (D-08..D-10)
  is built directly on it with no changes to the fingerprint format.
- **`Finding` JSON schema** (OUT-02) — reused verbatim as the baseline entry
  format (D-09); add only `omitempty` `suppressed`/`suppression_reason` fields
  for `--show-suppressed` (D-12).
- **`config.Allowlist` (Regexes + Paths, compiled) + `engine.isAllowlisted`** —
  the existing content-allowlist suppression path; reused for the "allowlisted"
  suppression reason (D-12). Note SUP-04 default noisy PATHS are NOT routed
  through this (they are walk-prune globs, D-05).
- **`scanner.Stats`** — extend with suppressed-by-reason counts and
  paths-excluded count (D-11).

### Established Patterns
- Redact-at-`Finding`-boundary security invariant (regression-guarded by the
  reflect test in `finding_test.go`) — the baseline inherits this; do not
  introduce any code path that stores/serializes a raw secret.
- `filepath.WalkDir` with `filepath.SkipDir` is already the prune mechanism for
  `.git` — the `.mimirignore`/defaults prune (D-05) follows the same pattern.
- Deterministic finding sort (File → Line → Column) — keep baseline output and
  suppressed-finding output deterministic for stable diffs/CI.

### Integration Points
- **Scanner walk** (`Scanner.Scan`): add `.mimirignore` + default-glob prune
  before enqueueing a file (and count excluded paths).
- **Per-line scan** (`scanFile`/`engine.ScanLine`): detect the inline
  `mimir:ignore[:rule-id]` directive on the line and drop/attribute matching
  findings.
- **Post-scan filter**: apply the baseline OR-match (D-10) to surviving findings
  and tag suppression reasons; this is also where Phase 4 verification will
  later slot in (keep it a discrete, decoupled stage).
- **Output/summary**: extend human summary (D-11) and JSON (D-12); honor
  `--show-suppressed`.

</code_context>

<specifics>
## Specific Ideas

- Trust is the throughline: the user chose "always show suppressed counts"
  (D-11) and an auditable `--show-suppressed` (D-12) precisely so suppression is
  never silent — directly serving the PROJECT.md core value.
- Criterion 4's "file move" clause was explicitly reconciled (D-10): the
  user accepted a small blind spot (same secret value re-pasted into a new file
  stays suppressed) in exchange for move-stability, rather than relaxing the
  roadmap criterion.
- `.mimirignore` should feel like `.gitignore` to users (gitignore-style
  semantics, `!` negation) — familiarity over novelty.

</specifics>

<deferred>
## Deferred Ideas

- **Honoring `.gitignore` automatically** — considered as a possible noise
  reducer; not adopted in v1 (gitleaks doesn't either by default, and it can
  hide intentionally-gitignored secret files). Revisit if users ask.
- **Nested per-directory `.mimirignore`** — rejected for v1 in favor of a single
  root file (D-06); revisit for monorepo ergonomics if needed.
- **Inline block-range suppression** (`mimir:ignore-start`/`-end`) and
  line-above placement — rejected for v1 (D-01); revisit if same-line proves
  too restrictive.
- **Fingerprint-targeted inline ignore** (`mimir:ignore:<fingerprint>`) — not in
  v1's directive forms (D-02); overlaps with the standalone ignore-by-fingerprint
  v2 item (SUP2-01).
- **Interactive baseline audit / review-and-approve** — v2 (SUP2-02); v1 baseline
  is generate + consume only.
- **Baseline staleness / merge / partial-update tooling** — not in v1;
  regenerate the whole baseline. Revisit if baseline churn is painful.

</deferred>

---

*Phase: 2-False-Positive Control (Suppression + Baseline)*
*Context gathered: 2026-05-28*
