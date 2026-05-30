# Phase 3: Full Source Coverage (Git History + Staged + Pre-commit) - Context

**Gathered:** 2026-05-29
**Status:** Ready for planning

<domain>
## Phase Boundary

Mimir scans *where secrets actually leak* — past commits (including secrets later
deleted), the staged diff, and as a fast offline pre-commit hook that blocks
commits containing secrets. This extends the Phase 1 source coverage (working
tree + config files) with git-aware sources, reusing the existing detection
engine, suppression layers, fingerprint, and exit-code contract unchanged.

Delivers (requirements SCAN-03, SCAN-04, IFACE-03):
- Git-history scan over past commits, catching added-then-deleted secrets (SCAN-03)
- Staged-changes scan (`git diff --cached`) for the pre-commit use case (SCAN-04)
- A `mimir`-installed pre-commit hook: staged-only, offline, fast, honest bypass (IFACE-03)

**Explicitly NOT in this phase** (later phases / v2 own these):
- Live verification (AWS/GitHub network calls) → Phase 4 (and the hook must NEVER verify, VERIFY-01)
- Commit-range / incremental history scanning (`--since`, ranges) → v2 (SUP2-03)
- Scanning non-git directory history → out of scope (REQUIREMENTS "Out of Scope")
- `go-git` in-process history walk → out of scope as default; `git log -p` shell-out is locked

</domain>

<decisions>
## Implementation Decisions

### CLI Surface (SCAN-03 / SCAN-04 / IFACE-03)
- **D-01:** **Mode flags on `mimir scan`, not new scan subcommands.** Git-history
  and staged scanning attach as `mimir scan --git` (history) and
  `mimir scan --staged`. One command reuses the entire existing flag surface
  (`--baseline`, `--baseline-out`, `--format`, `--show-suppressed`,
  `--no-default-excludes`, `--config` precedence, `--exit-zero`, `--verbose`) for
  free. The mode flag selects the *Source*; default with no mode flag stays
  working-tree (Phase 1 behavior, unchanged). Matches the CLAUDE.md sketch
  (`mimir scan --staged`, `mimir scan --git`).
- **D-02:** **Pre-commit hook installer is a `mimir hook` subcommand group.**
  `mimir hook install` / `mimir hook uninstall` / `mimir hook status`. Noun-verb
  grouping leaves room to grow (status/doctor/re-install) without polluting the
  top-level command list. New cobra command under the existing
  `rootCmd.AddCommand` pattern in `cmd/mimir/`.

### Git-History Scan Scope (SCAN-03)
- **D-03:** **Default `--git` scope = current-branch full history** (all commits
  reachable from HEAD). Deterministic, fast, matches gitleaks' default; catches
  the added-then-deleted secret (criterion 1) without scanning unrelated refs.
  NOT `--all` refs by default (avoids noise from stale/abandoned branches and
  the extra wall time).
- **D-04:** **v1 is full-history only — no range/`--since`/`--log-opts` knobs.**
  Commit-range and incremental history scanning are explicitly deferred to v2
  (SUP2-03). Keeping v1 to whole-history keeps the scope tight and makes the
  criterion-2 benchmark gate (bounded memory + acceptable wall time) clean to
  define and test. (Reconsider a `--log-opts` passthrough only if a planner finds
  it genuinely free and low-risk — see Claude's Discretion.)

### Pre-commit Hook Installer (IFACE-03)  — *delegated to Claude; recommended defaults below*
- **D-05 (recommended):** **Managed standalone hook; never silently clobber.**
  `mimir hook install` writes a managed `pre-commit` script only when none
  exists. If a `pre-commit` hook already exists, error with guidance and require
  `--force` to overwrite. Resolve the hook directory via `git rev-parse --git-dir`
  so it works under worktrees and submodules (not a hardcoded `.git/hooks`).
- **D-06 (recommended):** **Honest bypass = `git commit --no-verify` + a git-config
  off-switch.** Document the git-native `--no-verify`, AND honor a persistent
  `git config hooks.mimir false` toggle (re-enable with `true`/`unset`). Matches
  gitleaks; honest and discoverable (criterion 4's "honest documented bypass").
- **D-07 (recommended):** **Ship a `.pre-commit-hooks.yaml` manifest alongside the
  native installer.** Lets `pre-commit`-framework / husky users reference Mimir;
  the manifest is a few cheap YAML lines and broadens adoption. Native
  `mimir hook install` remains the primary path.
- **Locked hook behavior (from requirements, not open):** the hook runs
  `mimir scan --staged`, is **staged-only**, **fully offline** (NEVER `--verify` —
  Phase 4 is opt-in and explicitly never in pre-commit, VERIFY-01), **sub-second
  on a typical staged diff** (criterion 4), and **respects inline `// mimir:ignore`**
  (criterion 3, reuses Phase 2 SUP-01).

### Commit Provenance in Output (OUT-02 extension)  — *delegated to Claude; recommended defaults below*
- **D-08 (recommended):** **History findings carry commit SHA + author + date as
  `omitempty` `Finding` fields.** Full provenance (jump to the leaking commit and
  author) matching gitleaks. Working-tree and staged findings leave these empty,
  so the OUT-02 JSON schema stays byte-identical for non-history scans — the same
  `omitempty` extension discipline Phase 2 used for `suppressed`/`suppression_reason`.
- **D-09 (recommended):** **Fingerprint stays content-based and commit-independent**
  (`path:rule_id:sha256[:16]`, NO commit SHA). The same leaked secret across many
  history commits and the working tree shares one fingerprint, so the Phase 2
  baseline (OR-match) and cross-mode dedup work correctly. The commit SHA travels
  as separate metadata (D-08) only — it MUST NOT enter the fingerprint, or baseline
  matching breaks and history re-floods on every commit.
- **D-10 (recommended):** **Human output keeps the clean one-line default;**
  append the short commit SHA to the `file:line` line for history findings (e.g.
  `path/to/file:42 @ abc1234 — rule`), with full author/date shown only under
  `--verbose`. Preserves the Phase 1 grep-friendly density (D-01/D-04 lineage).

### Claude's Discretion
- **D-05/D-06/D-07/D-08/D-09/D-10 specifics** — the user delegated the hook-installer
  details (install/overwrite policy, bypass mechanism, framework manifest) and the
  provenance level + rendering. The recommended defaults above are the starting
  point; planner/researcher may refine within the locked constraints (offline,
  staged-only, sub-second, OUT-02 stability, content-based fingerprint).
- **Exact flag/command spellings** — `--git` vs `--history` (and any alias),
  `mimir hook` subcommand verbs, the `git config hooks.mimir` key name, and the
  short-SHA length in human output — open to standard conventions.
- **History streaming/dedup internals** — `git log -p` invocation, go-gitdiff
  parsing of added (`+`) lines, blob de-duplication, and the memory-bounding
  approach for criterion 2 are research/planner territory (CLAUDE.md locks the
  backend choice; the *how* of streaming is open). Define the criterion-2
  benchmark gate's concrete pass thresholds during planning.
- **`--git` + `--staged` combination / precedence** — whether the two mode flags
  are mutually exclusive or composable; planner to define against the IFACE-02
  exit-code contract.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Locked technical stack & architecture (READ FIRST)
- `CLAUDE.md` — Locked stack/architecture. For Phase 3 specifically: history
  backend is **shell out to system `git` (`git log -p`, `git diff --cached`) +
  parse with `github.com/gitleaks/go-gitdiff` v0.9.1** — NOT `go-git` (the
  "What NOT to Use" / "Out of Scope" rationale: ~8x memory). `git` ≥ 2.x is a
  documented runtime prerequisite for history mode. cobra for the new
  subcommand/flags; `golang.org/x/sync` (errgroup/semaphore) for bounded
  concurrency; redact-at-boundary and lean-binary constraints still apply. Not
  to be re-litigated.

### Project scope & requirements
- `.planning/PROJECT.md` — Core value (low false positives = adoption),
  performance constraint (fast enough for CI and pre-commit), security constraint
  (redact by default; verification opt-in and never leaks creds).
- `.planning/REQUIREMENTS.md` — SCAN-03, SCAN-04, IFACE-03 definitions; note
  SUP2-03 (commit-range/incremental history) is **v2** (drove D-04), and the
  "Out of Scope" table locks out go-git-as-default and non-git history.
- `.planning/ROADMAP.md` §"Phase 3" — Goal + 4 success criteria this phase must
  satisfy (criterion 1 deleted-secret, criterion 2 benchmark gate, criterion 3
  staged + hook respecting inline-ignore, criterion 4 offline/sub-second/bypass).

### Phase 1 + 2 foundations this phase builds on (READ — implementation depends on these)
- `internal/finding/finding.go` — The `Finding` struct + JSON tags and
  `computeFingerprint` (`path:rule_id:sha256[:16]`). D-08 adds `omitempty` commit
  metadata fields here; D-09 keeps the fingerprint content-based (no commit). The
  redact-at-boundary security invariant (reflect test in `finding_test.go`) and
  the existing `suppressed`/`suppression_reason` omitempty fields are the pattern
  to follow.
- `internal/scanner/scanner.go` — `Scanner`, `New`, `Scan(ctx, paths)` (the
  `filepath.WalkDir` working-tree source), `scanFile` (per-line loop +
  inline-ignore via Phase 2), and `Stats`. The new git-history and staged sources
  produce `[]finding.Finding` the same way so the engine/suppression/output
  stages downstream are unchanged. Per-line scanning of diff-added lines reuses
  `scanFile`'s line logic / `engine.ScanLine`.
- `cmd/mimir/scan.go` — `scanCmd`, its `init()` flag surface (D-14 flags), and
  `runScan` (config precedence, engine/scanner build, baseline post-stage). D-01
  adds `--git`/`--staged` here and branches the Source; D-02's `mimir hook` group
  is a sibling command. The baseline post-`Scan` stage (lines ~99+) is the
  decoupled filter slot where suppression/baseline already apply across modes.
- `internal/suppress/` — Phase 2 inline-ignore (SUP-01), `.mimirignore`/default
  path-prune (SUP-02/SUP-04), and baseline OR-match (SUP-03). The staged scan +
  hook must respect inline-ignore (criterion 3); baseline/dedup correctness across
  modes depends on D-09's content-based fingerprint.
- `.planning/phases/02-false-positive-control/02-CONTEXT.md` — D-09..D-13
  (baseline entry shape, OR-match key, suppression transparency) and the omitempty
  schema-extension discipline that D-08 mirrors.

No external ADRs/specs beyond the above — requirements and decisions are fully
captured in this repo's `.planning/` docs, `CLAUDE.md`, and the Phase 1/2 source.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **Detection engine** (`internal/detect`, `engine.ScanLine`) — runs unchanged on
  diff-added lines; no engine changes needed (mirrors the Phase 4 "zero engine
  changes" design ethos).
- **`Finding` model + JSON schema (OUT-02)** — reused verbatim; D-08 adds only
  `omitempty` commit metadata, preserving byte-identical output for non-history
  scans (the Phase 2 `suppressed`/`suppression_reason` precedent).
- **`computeFingerprint`** — already line-number-independent and forward-slash
  normalized; stays the cross-mode dedup/baseline key (D-09), no change.
- **Suppression layers** (`internal/suppress`) — inline-ignore, allowlists, and
  baseline apply to git-sourced findings in the same post-scan filter stage.
- **`scanFile` per-line loop / inline-ignore** — the staged-scan + hook path needs
  inline-ignore (criterion 3); reuse the existing per-line directive detection.

### Established Patterns
- Redact-at-`Finding`-boundary (reflect-test guarded) — git-history findings build
  through `finding.New`, inheriting it; never store/serialize a raw secret or a raw
  diff line containing one.
- `omitempty` schema extension — add new optional fields, never reshape existing
  ones, to keep OUT-02 stable for downstream consumers (D-08).
- Deterministic finding sort (File → Line → Column) — extend ordering sensibly for
  history (e.g. commit order / time) so output and baselines stay diff-stable.
- cobra `rootCmd.AddCommand` + per-command `init()` flag registration — the
  `mimir hook` group (D-02) follows the existing `scanCmd` shape.
- Fail-loud on bad input (`os.Exit(2)` on malformed config/baseline/ignore) — the
  git source should fail-loud when `git` is absent or the repo is not a git repo.

### Integration Points
- **Source selection in `runScan`** (`cmd/mimir/scan.go`): `--git`/`--staged`
  branch picks the git Source instead of the working-tree walk; everything after
  (suppression, baseline, output, exit codes) is shared and unchanged.
- **New git source(s)** (likely `internal/scanner` or a new `internal/gitscan`):
  shell out to `git log -p` / `git diff --cached`, stream through go-gitdiff,
  emit `[]finding.Finding` with commit metadata (D-08) attached.
- **New `mimir hook` command** (`cmd/mimir/hook.go` or similar): install/uninstall/
  status; resolves hook dir via `git rev-parse --git-dir`; the installed hook
  shells `mimir scan --staged`.
- **Output reporters** (`internal/output`): human reporter appends short SHA on
  history findings (D-10); JSON gains the omitempty commit fields (D-08).
- **Benchmark gate** (criterion 2): a test/bench that asserts bounded peak memory +
  acceptable wall time on a large real repo (diff-streamed, blob-deduped).

</code_context>

<specifics>
## Specific Ideas

- **Reuse over rebuild is the throughline:** the user chose mode-flags-on-`scan`
  (D-01) and a content-based fingerprint (D-09) specifically so the new git
  sources slot into the existing engine/suppression/baseline/output pipeline with
  near-zero changes to those stages — the same decoupling that lets Phase 4
  verification slot in later.
- **Tight v1 scope:** range/incremental history was consciously kept out (D-04)
  per the SUP2-03 v2 deferral, so the criterion-2 benchmark gate has a single
  well-defined workload (whole current-branch history).
- **The hook must stay honest and offline:** documented bypass + git-config
  toggle (D-06), never any network call (no `--verify`) — directly serving the
  "developers trust it and keep it" adoption value.

</specifics>

<deferred>
## Deferred Ideas

- **Commit-range / incremental / `--since` history scanning** — v2 (SUP2-03);
  consciously out of v1 (D-04). A `--log-opts` passthrough is the only possible
  v1 escape hatch and only if proven free/low-risk.
- **Scanning all refs/branches by default** — rejected for v1 (D-03, noise + time);
  a `--all` opt-in flag could be added later if users ask.
- **`go-git` in-process history backend** — out of scope as default (CLAUDE.md);
  only a possible later fallback for no-`git`-binary environments.
- **Including commit SHA in the fingerprint** — rejected (D-09); would break
  cross-mode baseline/dedup.
- **Live verification of history findings** — Phase 4 (VERIFY-*); never in the
  pre-commit hook.

None of the above were surfaced as scope creep during discussion — they are the
explicit v1/v2 and phase boundaries from REQUIREMENTS.md/ROADMAP.md.

</deferred>

---

*Phase: 3-Full Source Coverage (Git History + Staged + Pre-commit)*
*Context gathered: 2026-05-29*
