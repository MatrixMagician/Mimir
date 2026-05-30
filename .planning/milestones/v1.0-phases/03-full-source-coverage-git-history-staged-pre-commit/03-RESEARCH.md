# Phase 3: Full Source Coverage (Git History + Staged + Pre-commit) - Research

**Researched:** 2026-05-30
**Domain:** Git-aware secret scanning (history via `git log -p`, staged via `git diff --staged`, pre-commit hook installer) in Go
**Confidence:** HIGH

## Summary

This phase adds three git-aware *sources* to Mimir without touching the detection engine, suppression layers, `Finding` model, or exit-code contract. All three sources reduce to one mechanic: **shell out to the system `git` binary, stream its unified-diff (`-U0`) output through `github.com/gitleaks/go-gitdiff` v0.9.1, iterate each added (`OpAdd`) line, and feed it to the existing `engine.ScanLine(line, path, lineNum)`**. This is empirically verified (see Code Examples) against a real git repo, including the criterion-1 "added-then-deleted secret" case and the criterion-3 staged-diff case.

The load-bearing discovery: go-gitdiff v0.9.1's `Parse(r io.Reader)` returns a **`<-chan *File` channel**, not a buffered slice. Consuming it lazily while `git log -p` streams to a pipe gives bounded peak memory for free — you never hold full history in memory. Each `*File` carries `PatchHeader` (commit `SHA`, `Author`, `AuthorDate`, `Title`) for D-08 provenance, and `TextFragments[].Lines` where each `Line` has `Op` (`OpAdd`/`OpDelete`/`OpContext`) and `Line` string. With `-U0`, an added line's absolute line number is `TextFragment.NewPosition + (count of OpAdd/OpContext lines seen so far in that fragment)`.

The cleanest integration seam is a **`Source` abstraction in a new `internal/gitscan` package** that emits `[]finding.Finding` exactly as the working-tree walk does; `runScan` branches on `--git`/`--staged` to pick the source, and every downstream stage (suppression, baseline, output, exit code) is unchanged. The pre-commit hook is a thin `mimir hook` cobra command group that writes a managed script invoking `mimir scan --staged`, resolving the hook dir via `git rev-parse --git-path hooks`.

**Primary recommendation:** Build an `internal/gitscan` package with two source functions (`ScanHistory`, `ScanStaged`) that both stream `git ... -U0 --no-color | gitdiff.Parse`, iterate `OpAdd` lines, call `engine.ScanLine` per line, attach commit metadata from `PatchHeader`, and return `[]finding.Finding`. Wire `--git`/`--staged` into `runScan` as source selectors. Add a `mimir hook install/uninstall/status` command. Add `omitempty` commit fields to `Finding` and a streaming-memory benchmark gate.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Git history enumeration | External `git` process | `internal/gitscan` (orchestration) | CLAUDE.md locks shell-out to `git log -p`; Mimir orchestrates and parses, git does the object walk |
| Patch parsing (diff → per-line) | `internal/gitscan` (via go-gitdiff) | — | go-gitdiff streams `git`'s stdout into typed `*File`/`TextFragment`/`Line` |
| Secret detection on a line | `internal/detect` (`engine.ScanLine`) | — | Unchanged; reused verbatim on diff-added lines (zero engine changes) |
| Suppression (inline/path/baseline) | `cmd/mimir` runScan + `internal/suppress` | — | Post-scan filter stage already source-agnostic |
| Commit provenance metadata | `internal/finding` (omitempty fields) + `internal/gitscan` (populates) | `internal/output` (renders) | D-08: metadata travels on `Finding`, never in fingerprint |
| Pre-commit hook install | `cmd/mimir` (`hook` command) | External `git rev-parse` (dir resolution) | IFACE-03; OS-level state written to `.git/hooks` |
| Exit-code contract | `cmd/mimir` runScan | — | IFACE-02, unchanged — staged findings flip exit 1 to block commit |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `github.com/gitleaks/go-gitdiff` | v0.9.1 | Parse `git log -p` / `git diff --staged` patch streams into typed per-file, per-line fragments | [VERIFIED: Go module proxy — latest is v0.9.1, present in local module cache] The gitleaks-maintained fork; gitleaks itself uses this exact version+API for history scanning. `Parse` returns a streaming channel ideal for bounded memory. [CITED: gitleaks/sources/git.go] |
| system `git` binary | ≥ 2.x (2.54.0 local) | History walk + diff generation (shelled out) | [CITED: CLAUDE.md — locked; ~8x less memory than go-git in-process walk]. [VERIFIED: `git version 2.54.0` available locally] |
| `github.com/spf13/cobra` | v1.10.2 | `mimir hook` subcommand group + `--git`/`--staged` flags on `scan` | [CITED: CLAUDE.md] Already the project's CLI framework; `rootCmd.AddCommand` pattern in place |
| stdlib `os/exec` | stdlib (Go 1.25/1.26) | Spawn `git` with a streamed stdout pipe | [VERIFIED: probe ran `exec.Command(...).StdoutPipe()` → `gitdiff.Parse` successfully] |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `golang.org/x/sync/errgroup` | v0.20.0 | Bounded concurrency if per-commit/per-file scanning is parallelized | [CITED: CLAUDE.md] Already used in `internal/scanner`. NOTE: history streaming is inherently serial at the `git log` pipe; parallelize *within* a commit (across files/lines) or keep serial for v1 simplicity. Measure before adding. |
| stdlib `testing` (`testing.B`, `runtime.ReadMemStats`, `b.ReportMetric`) | stdlib | Criterion-2 benchmark gate (peak memory + wall time) | For the memory/wall-time regression gate. `testing.AllocsPerOp` / `b.ReportAllocs()` + a `runtime.MemStats` HeapAlloc delta assertion. |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `git log -p` shell-out + go-gitdiff | `go-git/go-git` v5 in-process walk | [CITED: CLAUDE.md/REQUIREMENTS "Out of Scope"] ~8x memory; explicitly rejected as default. Only a possible later no-git-binary fallback. **Do not use in this phase.** |
| Per-line `OpAdd` iteration → `engine.ScanLine` | gitleaks' "join Raw(OpAdd) blob + newlineIndices offset math" | gitleaks joins added lines into one blob and back-computes line numbers via newline indices [CITED: gitleaks/detect/detect.go]. Mimir already has a clean **per-line** `engine.ScanLine(line, path, lineNum)` API, so per-line iteration is simpler, reuses existing tested code, and needs no offset arithmetic. **Prefer per-line iteration.** |
| `git rev-parse --git-path hooks` | hardcoded `.git/hooks` | [VERIFIED: `git rev-parse --git-path hooks` → `.git/hooks`] Hardcoding breaks under worktrees, submodules, and `core.hooksPath`. [CITED: D-05] Use `rev-parse`. |

**Installation:**
```bash
# go-gitdiff is the only new module dependency (already in CLAUDE.md locked stack + local module cache):
/usr/local/go/bin/go get github.com/gitleaks/go-gitdiff@v0.9.1
# git binary is a documented RUNTIME prerequisite for --git/--staged modes (not a Go dependency).
```

**Version verification (performed this session):**
```
go list -m -versions github.com/gitleaks/go-gitdiff  → ... v0.9.0 v0.9.1   (v0.9.1 is latest) [VERIFIED]
local module cache: github.com/gitleaks/go-gitdiff@v0.9.1 PRESENT [VERIFIED]
git version 2.54.0 [VERIFIED]
go version go1.26.2 (go.mod floor: go 1.25.0) [VERIFIED]
```

## Package Legitimacy Audit

> go-gitdiff is the only external package this phase introduces, and it is already in the CLAUDE.md locked stack and the local Go module cache. slopcheck targets npm/PyPI (not Go modules); Go verification is via the module proxy + provenance.

| Package | Registry | Age | Downloads | Source Repo | slopcheck | Disposition |
|---------|----------|-----|-----------|-------------|-----------|-------------|
| `github.com/gitleaks/go-gitdiff` | Go module proxy (proxy.golang.org) | fork of bluekeyes/go-gitdiff, multi-year | used transitively by gitleaks (widely deployed) | github.com/gitleaks/go-gitdiff | N/A (Go module, not npm/PyPI) | Approved |

**Packages removed due to slopcheck [SLOP] verdict:** none
**Packages flagged as suspicious [SUS]:** none

**Provenance note:** `github.com/gitleaks/go-gitdiff` is the gitleaks organization's own maintained fork of `bluekeyes/go-gitdiff`. It is the dependency gitleaks itself pulls for history scanning [CITED: gitleaks go.mod / sources/git.go]. Verified present at v0.9.1 in the local module cache and as the latest tag on the Go proxy [VERIFIED]. Go-native legitimacy check: `go mod verify` should be run after `go get` to confirm checksum integrity against `go.sum`.

## Architecture Patterns

### System Architecture Diagram

```
                          mimir scan [--git | --staged | (default)]
                                          │
                                  runScan (cmd/mimir/scan.go)
                                          │  selects Source by mode flag
            ┌─────────────────────────────┼─────────────────────────────┐
            │                             │                              │
   (default: working tree)        --git (history)                --staged
   internal/scanner.Scan          internal/gitscan.ScanHistory   internal/gitscan.ScanStaged
   filepath.WalkDir                       │                              │
            │              exec: git log -p -U0 --no-color    exec: git diff -U0 --no-ext-diff
            │                     [current branch HEAD]            --no-color --staged
            │                             │  stdout pipe (streamed)      │  stdout pipe
            │                    gitdiff.Parse(pipe) ──► <-chan *File ◄───┘
            │                             │
            │              for each *File:  PatchHeader{SHA,Author,AuthorDate,Title}  (empty for staged)
            │                for each TextFragment:
            │                  lineNum = NewPosition
            │                  for each Line where Op==OpAdd:
            │                     ├─ trim trailing "\n"
            │                     └─ engine.ScanLine(line, NewName, lineNum) ──┐
            │                        inline-ignore check (suppress.InlineSuppresses on the diff line)
            │                        attach commit metadata (D-08) to finding   │
            └─────────────────┬───────────────────────────────────────────────┘
                              ▼
                   []finding.Finding  (redacted at boundary via finding.New — unchanged)
                              │
        ┌─────────────────────┴─── SHARED, UNCHANGED PIPELINE ───────────────────────┐
        │  baseline filter (suppress) → newFindings → output (human/json) → exit code  │
        └──────────────────────────────────────────────────────────────────────────────┘

  mimir hook install/uninstall/status (cmd/mimir/hook.go)
        └─ git rev-parse --git-path hooks → write managed pre-commit script → `mimir scan --staged`
```

### Recommended Project Structure
```
internal/
└── gitscan/                 # NEW: git-aware sources
    ├── gitscan.go           # Source funcs: ScanHistory(ctx, engine, repoRoot, opts) / ScanStaged(...)
    ├── command.go           # builds + spawns the git exec.Cmd with a streamed stdout pipe
    ├── parse.go             # gitdiff.Parse loop: OpAdd line iteration + lineNum tracking + metadata attach
    └── gitscan_test.go      # fixture-repo tests (history deleted-secret, staged, inline-ignore)
cmd/mimir/
├── scan.go                  # MODIFIED: --git/--staged flags, branch to gitscan source
└── hook.go                  # NEW: `mimir hook` cobra group (install/uninstall/status)
internal/finding/
└── finding.go               # MODIFIED: omitempty CommitSHA/CommitAuthor/CommitDate fields (D-08)
.pre-commit-hooks.yaml       # NEW (D-07): framework manifest (repo root)
```

### Pattern 1: Stream git stdout through go-gitdiff (bounded memory)
**What:** Spawn `git` with a `StdoutPipe()`, call `gitdiff.Parse(pipe)`, and range over the returned channel lazily. Never buffer the full `git log` output into memory.
**When to use:** Both history and staged sources.
**Example:**
```go
// Source: empirically verified this session against /tmp/gdtest2 + go-gitdiff v0.9.1
cmd := exec.CommandContext(ctx, "git", "-C", repoRoot,
    "log", "-p", "-U0", "--full-history", "--no-color") // current-branch history (D-03: NOT --all)
stdout, err := cmd.StdoutPipe()
if err != nil { return nil, err }
if err := cmd.Start(); err != nil { return nil, err }

files, err := gitdiff.Parse(stdout) // returns <-chan *gitdiff.File — STREAMING
if err != nil { return nil, err }
for f := range files {
    // f.PatchHeader carries commit SHA/author/date (D-08); empty for staged diffs
    // ... iterate fragments (Pattern 2)
}
if err := cmd.Wait(); err != nil { /* fail-loud: not a git repo / git missing */ }
```

### Pattern 2: Per-line OpAdd iteration with absolute line numbers
**What:** For each `TextFragment`, start a counter at `NewPosition`; for each `Line`, if `Op==OpAdd` scan it at the current counter then increment; if `Op==OpContext` just increment; `OpDelete` does not advance the new-file counter.
**When to use:** Converting diff fragments to per-line `engine.ScanLine` calls.
**Example:**
```go
// Source: empirically verified — output matched git's hunk headers exactly
for _, tf := range f.TextFragments {
    lineNum := int(tf.NewPosition)
    for _, l := range tf.Lines {
        switch l.Op {
        case gitdiff.OpAdd:
            line := strings.TrimSuffix(l.Line, "\n") // Line includes trailing newline
            // inline-ignore (criterion 3): the diff-added line IS the source line
            lineFindings := engine.ScanLine(line, f.NewName, lineNum)
            for i := range lineFindings {
                if suppress.InlineSuppresses(line, lineFindings[i].RuleID) {
                    // count + drop (or annotate under --show-suppressed) — same as scanFile
                    continue
                }
                attachCommitMeta(&lineFindings[i], f.PatchHeader) // D-08
                out = append(out, lineFindings[i])
            }
            lineNum++
        case gitdiff.OpContext:
            lineNum++
        case gitdiff.OpDelete:
            // no advance: deleted lines aren't in the new file
        }
    }
}
```

### Pattern 3: Managed pre-commit hook installer
**What:** Resolve hook dir via `git rev-parse --git-path hooks`; refuse to overwrite an existing `pre-commit` without `--force`; write a short managed script that honors a `git config --bool hooks.mimir` off-switch and invokes `mimir scan --staged`.
**When to use:** `mimir hook install`.
**Example hook script (written by installer):**
```sh
#!/bin/sh
# mimir managed pre-commit hook — staged-only, offline. Bypass: git commit --no-verify
if [ "$(git config --type=bool --get hooks.mimir)" = "false" ]; then exit 0; fi
exec mimir scan --staged
```

### Anti-Patterns to Avoid
- **Buffering full `git log -p` output** (`io.ReadAll` then parse): defeats criterion-2 bounded memory. Stream the channel instead.
- **Putting commit SHA in the fingerprint:** [CITED: D-09] breaks cross-mode baseline/dedup; the same secret across commits must share one fingerprint. Commit SHA is metadata only.
- **Reimplementing detection for diff lines:** call the existing `engine.ScanLine` — zero engine changes (mirrors the working-tree path).
- **Hardcoding `.git/hooks`:** breaks worktrees/submodules/`core.hooksPath` — use `git rev-parse --git-path hooks`.
- **`--all` by default for history:** [CITED: D-03] noise + wall time; default to current-branch HEAD reachability.
- **Any network call in the hook:** [CITED: VERIFY-01] hook is offline-only; never `--verify`.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Parse unified-diff / `git log -p` | A custom `@@`-hunk parser | `gitdiff.Parse` (go-gitdiff v0.9.1) | Handles renames, binary patches, mode changes, commit-header preamble, quoted-printable email headers, multi-fragment hunks — all edge cases gitleaks hit. [CITED: go-gitdiff source] |
| Compute added-line line numbers | Manual `@@ -a,b +c,d @@` arithmetic | `TextFragment.NewPosition` + per-`OpAdd` counter | go-gitdiff already parsed positions; [VERIFIED] counter matches git's reported line numbers |
| Commit SHA/author/date extraction | Parsing `commit <sha>` / `Author:` lines yourself | `File.PatchHeader.{SHA,Author,AuthorDate,Title}` | go-gitdiff parses the pretty-format preamble [VERIFIED: SHA + author populated in probe] |
| History object walk | go-git in-process walk | shell out to `git log -p` | [CITED: CLAUDE.md] ~8x less memory; git's walk is C-optimized |
| Hook directory resolution | String-building `.git/hooks` | `git rev-parse --git-path hooks` | [VERIFIED] handles worktrees/submodules/hooksPath |
| pre-commit framework integration | Custom framework adapter | `.pre-commit-hooks.yaml` manifest | [CITED: gitleaks .pre-commit-hooks.yaml] a few YAML lines (`id`/`name`/`entry`/`language: golang`/`pass_filenames: false`) |

**Key insight:** Every git-specific concern in this phase has a battle-tested solution in either the system `git` binary or go-gitdiff. The only Mimir-original code is the thin glue: spawn git, range the channel, iterate `OpAdd` lines into the *already-built* `engine.ScanLine`, attach metadata, and the source-selection branch in `runScan`.

## Runtime State Inventory

> This phase is **additive (greenfield sources), not a rename/refactor**. No existing stored data, secrets, or OS-registered state is being renamed. One forward-looking item (the installed hook) is OS-registered state this phase *creates*.

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | None — no datastore stores a renamed key; fingerprint scheme unchanged (D-09). Verified by reading `internal/finding/finding.go` (computeFingerprint untouched). | none |
| Live service config | None — no external service config. | none |
| OS-registered state | **This phase CREATES** `.git/hooks/pre-commit` (or `core.hooksPath`) — a managed script. `mimir hook uninstall` must remove only Mimir's managed hook (verify a marker line before deleting). `git config hooks.mimir` toggle is set/read by the hook. | installer writes; uninstaller removes managed hook only |
| Secrets/env vars | None — no secret/env var renamed. The hook reads no secrets (offline). | none |
| Build artifacts | None — new `internal/gitscan` package; `go build` produces the same single binary. New runtime prerequisite: `git` on PATH for `--git`/`--staged` modes (document in README). | document git prerequisite |

## Common Pitfalls

### Pitfall 1: go-gitdiff `Line.Line` includes the trailing newline
**What goes wrong:** Passing `l.Line` directly to `engine.ScanLine` includes a trailing `\n`, which can shift column math, pollute redacted match context, or break regex anchors.
**Why it happens:** go-gitdiff preserves the raw line content including `\n` (see `Line.NoEOL()` which checks the last byte). [VERIFIED: probe printed `"SECRET_AKIA\n"`]
**How to avoid:** `strings.TrimSuffix(l.Line, "\n")` before scanning (and handle the no-EOL last line gracefully).
**Warning signs:** Off-by-one columns; redacted snippets with a stray newline.

### Pitfall 2: Streaming abandoned mid-range leaks the git process / goroutine
**What goes wrong:** `gitdiff.Parse` spawns an internal goroutine writing to the channel. If you `break` out of the `for f := range files` loop early (e.g. context cancel) without draining, the goroutine blocks and `cmd.Wait()` may hang on the unread pipe.
**Why it happens:** Channel send blocks until received; the git process's stdout buffer fills. [CITED: go-gitdiff parser.go — `out <- file` in a goroutine]
**How to avoid:** Use `exec.CommandContext` so context cancel kills git; drain the channel on early exit, or close the stdout pipe to unblock. Always `cmd.Wait()` in a deferred cleanup.
**Warning signs:** Hanging tests; zombie git processes; context-cancel tests that never return.

### Pitfall 3: `git log -p` shows the secret even when later deleted — but ALSO re-shows it on every later modification's diff
**What goes wrong:** A secret added in commit A and modified (not removed) in commit B may appear as an added line in BOTH commits' diffs, producing duplicate findings.
**Why it happens:** Each commit's `-p` patch shows that commit's additions; a line touched twice is "added" twice across history.
**How to avoid:** D-09's content-based fingerprint (`path:rule:hash16`) makes these duplicates share one fingerprint — dedup by fingerprint after collecting history findings (and the Phase 2 baseline OR-match already keys on it). Decide v1 dedup policy: collapse to first-introducing commit (earliest by AuthorDate) for the human one-liner. [CITED: D-09/D-10]
**Warning signs:** Same secret reported N times with N different SHAs in `--git` output.

### Pitfall 4: `git` absent or directory is not a git repo
**What goes wrong:** `--git`/`--staged` in a non-repo (or with no `git` on PATH) silently produces "clean" (exit 0) — the opposite of trustworthy, mirroring the working-tree root-path concern already handled in `scanner.go`.
**Why it happens:** `exec.Command` returns an error on missing binary; `git` returns non-zero in a non-repo.
**How to avoid:** Check `exec.LookPath("git")` and `cmd.Wait()` error; fail-loud with `os.Exit(2)` and a clear message (matches the existing "fail-loud on bad input" pattern in `scanner.go`/`runScan`). [CITED: code_context Established Patterns]
**Warning signs:** Exit 0 on a path that isn't a git repo.

### Pitfall 5: Staged `PatchHeader` is empty — don't emit garbage commit metadata
**What goes wrong:** Treating staged findings as if they had a commit SHA produces empty/zero metadata in JSON or a `@ 0000000` in human output.
**Why it happens:** `git diff --staged` output has no commit preamble. [VERIFIED: probe — `PatchHeader nil/empty == true` for staged]
**How to avoid:** Only attach commit metadata when `PatchHeader != nil && PatchHeader.SHA != ""`. D-08's `omitempty` fields then stay absent for staged/working-tree findings, preserving OUT-02 byte-identical schema. [CITED: D-08]
**Warning signs:** `"commit_sha":""` appearing in staged JSON output.

### Pitfall 6: `--git` + `--staged` precedence undefined
**What goes wrong:** Both flags set produces ambiguous behavior.
**Why it happens:** Two source selectors, one source slot. [CITED: D-decision deferred to planner]
**How to avoid:** Planner decides: simplest is mutually-exclusive (error if both set), consistent with IFACE-02 exit-2-on-misuse. Document it.

## Code Examples

### Build the history git command (current-branch HEAD, D-03)
```go
// Source: gitleaks/sources/git.go uses "log -p -U0 --full-history --all --diff-filter=tuxdb"
// Mimir DIVERGES on --all (D-03: current branch only, no --all). Keep --full-history for rename following.
args := []string{"-C", repoRoot, "log", "-p", "-U0", "--full-history", "--no-color"}
// (no --all → reachable-from-HEAD only; no --log-opts in v1, D-04)
cmd := exec.CommandContext(ctx, "git", args...)
```

### Build the staged git command (criterion 3)
```go
// Source: gitleaks staged path = "diff -U0 --no-ext-diff --staged ." [VERIFIED behavior in probe]
args := []string{"-C", repoRoot, "diff", "-U0", "--no-ext-diff", "--no-color", "--staged"}
cmd := exec.CommandContext(ctx, "git", args...)
```

### Resolve hook directory (worktree/submodule/hooksPath safe)
```go
// Source: VERIFIED `git rev-parse --git-path hooks` → ".git/hooks" (relative to repo)
out, err := exec.Command("git", "-C", repoRoot, "rev-parse", "--git-path", "hooks").Output()
hookDir := strings.TrimSpace(string(out)) // create dir if missing, then write managed "pre-commit"
```

### D-08 Finding fields (additive, omitempty — preserves OUT-02)
```go
// internal/finding/finding.go — add to the Finding struct (mirrors the suppressed/suppression_reason precedent):
CommitSHA    string `json:"commit_sha,omitempty"`
CommitAuthor string `json:"commit_author,omitempty"`
CommitDate   string `json:"commit_date,omitempty"` // RFC3339 from AuthorDate
// Populated ONLY by gitscan when PatchHeader has a SHA; empty for working-tree/staged → schema byte-identical.
// MUST NOT enter computeFingerprint (D-09).
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| go-gitdiff `Parse` returns `([]*File, string, error)` (older bluekeyes API) | gitleaks fork v0.9.x `Parse(r) (<-chan *File, error)` — streaming channel | gitleaks fork | Enables bounded-memory streaming for criterion 2 without extra work [VERIFIED: parser.go signature] |
| gitleaks blob-join + newlineIndices line math | (Mimir choice) per-`OpAdd`-line iteration into existing `ScanLine` | this phase | Reuses tested per-line engine; no offset arithmetic |

**Deprecated/outdated:**
- `bluekeyes/go-gitdiff` upstream (non-streaming older tags): use the gitleaks fork v0.9.1 per CLAUDE.md. The two share the type layout but the fork is the locked dependency.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Current-branch full history is best produced by `git log -p -U0 --full-history --no-color` (omitting `--all`, keeping `--full-history` for rename following) | Code Examples | LOW — if `--full-history` over-broadens, drop it; core `log -p -U0` is verified. Planner should confirm `--full-history` vs plain `log -p` for D-03's "current-branch" intent (full-history can surface merged-in side branches). |
| A2 | Mutually-exclusive `--git`/`--staged` is the right precedence | Pitfall 6 | LOW — explicitly delegated to planner; either choice is defensible. |
| A3 | Collapsing duplicate history findings to earliest-introducing commit is the desired human-output behavior | Pitfall 3 | MEDIUM — affects how many rows a user sees for one leaked secret; confirm during planning (dedup-by-fingerprint is certain; *which* commit to show is the open bit, ties to D-10). |
| A4 | Benchmark "bounded memory + acceptable wall time" thresholds | Validation Architecture | MEDIUM — concrete pass thresholds are explicitly planner territory (D-04/Discretion). Must be set against a real fixture repo, not guessed. |

## Open Questions

1. **Concrete criterion-2 benchmark thresholds**
   - What we know: streaming the channel keeps peak heap bounded (independent of history length); the gate should assert heap delta stays roughly flat as history grows, plus a wall-time ceiling.
   - What's unclear: exact MB / seconds numbers and the fixture-repo size.
   - Recommendation: build a generated fixture repo (e.g. N commits × M files) in a benchmark helper; assert `HeapAlloc` delta < a fixed ceiling and `ns/op` under budget. Set thresholds from a first measured baseline + headroom, not a priori (A4).

2. **`--full-history` vs plain `git log -p` for D-03 "current branch"**
   - What we know: gitleaks uses `--full-history --all`; Mimir drops `--all` (D-03).
   - What's unclear: whether `--full-history` (without `--all`) still matches "current-branch full history" intent or pulls extra merged-side-branch diffs.
   - Recommendation: planner test both against a multi-branch fixture; default to whichever yields exactly HEAD-reachable additions including the deleted-secret case.

3. **History dedup commit attribution (ties to D-10 human output)**
   - What we know: content-fingerprint dedups occurrences; D-10 appends short SHA to `file:line`.
   - What's unclear: which commit's SHA to show when a secret spans many commits.
   - Recommendation: show earliest-introducing (oldest AuthorDate) commit; document it (A3).

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| `git` binary | `--git`, `--staged`, `mimir hook` | ✓ | 2.54.0 | none (fail-loud; document as prerequisite) |
| `github.com/gitleaks/go-gitdiff` | history/staged patch parsing | ✓ | v0.9.1 (in module cache + proxy) | none |
| Go toolchain | build/test/bench | ✓ | go1.26.2 (go.mod floor 1.25.0) | none |

**Missing dependencies with no fallback:** none at research time. **Note:** `git` is the one *runtime* (not build-time) prerequisite for the new modes — Pitfall 4 handles its absence with fail-loud exit 2. Document `git ≥ 2.x` in README for `--git`/`--staged`.

**Missing dependencies with fallback:** none.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Go stdlib `testing` + `stretchr/testify` v1.11.1 (`require`/`assert`) |
| Config file | none (Go convention; no config file) |
| Quick run command | `/usr/local/go/bin/go test ./internal/gitscan/ -run TestX -count=1` |
| Full suite command | `/usr/local/go/bin/go test -race ./...` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| SCAN-03 | History scan finds an added-then-deleted secret with correct file:line + commit SHA | integration (fixture repo) | `go test ./internal/gitscan -run TestHistoryDeletedSecret -count=1` | ❌ Wave 0 |
| SCAN-03 | History findings carry commit SHA/author/date; working-tree/staged do not (OUT-02 stable) | unit | `go test ./internal/finding -run TestCommitMetaOmitempty -count=1` | ❌ Wave 0 |
| SCAN-03 | Duplicate secret across commits collapses to one fingerprint | unit/integration | `go test ./internal/gitscan -run TestHistoryDedup -count=1` | ❌ Wave 0 |
| SCAN-04 | Staged scan finds a secret in `git diff --staged` at correct file:line | integration (fixture repo) | `go test ./internal/gitscan -run TestStagedSecret -count=1` | ❌ Wave 0 |
| SCAN-04 | Staged scan respects inline `// mimir:ignore` (criterion 3) | integration | `go test ./internal/gitscan -run TestStagedInlineIgnore -count=1` | ❌ Wave 0 |
| IFACE-03 | `mimir hook install` writes managed hook; refuses overwrite without `--force` | e2e (built binary) | `go test ./cmd/mimir -run TestHookInstall -count=1` | ❌ Wave 0 |
| IFACE-03 | Installed hook blocks a commit containing a staged secret; `--no-verify` / `hooks.mimir false` bypasses | e2e | `go test ./cmd/mimir -run TestHookBlocksCommit -count=1` | ❌ Wave 0 |
| IFACE-03 | Hook is offline (no network) and sub-second on a typical staged diff | e2e + bench | `go test ./cmd/mimir -run TestHookOffline -count=1` ; `go test -bench BenchmarkStaged ./internal/gitscan` | ❌ Wave 0 |
| Criterion 2 | History scan peak memory bounded + wall time acceptable (regression gate) | benchmark | `go test -bench BenchmarkHistoryMem -benchmem ./internal/gitscan` | ❌ Wave 0 |
| Cross-mode | Suppression/baseline/exit-code identical across modes | integration | `go test ./cmd/mimir -run TestGitModeExitCodes -count=1` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `go test ./internal/gitscan/ -run <relevant> -count=1` (fast, < 30s)
- **Per wave merge:** `go test -race ./...`
- **Phase gate:** full suite green + benchmark gate passing before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `internal/gitscan/gitscan_test.go` — covers SCAN-03, SCAN-04 (fixture-repo helper that `git init`s a temp repo, commits/stages secrets)
- [ ] `internal/gitscan/bench_test.go` — `BenchmarkHistoryMem` (criterion 2 gate) + `BenchmarkStaged`
- [ ] `internal/finding/` test — commit-metadata omitempty + fingerprint-unchanged assertion (extends existing reflect-guard test)
- [ ] `cmd/mimir/hook_test.go` — install/uninstall/status + block-commit e2e (reuses existing `TestMain` built-binary + `runMimir` harness in `cmd/mimir/scan_test.go`)
- [ ] Shared fixture helper: temp-repo builder (`t.TempDir()` + `git init` + scripted commits/stages) — used by gitscan and hook tests
- [ ] No framework install needed — `testing` + testify already present

**Benchmark gate construction (criterion 2):** Use `testing.B` with `b.ReportAllocs()` and a `runtime.MemStats` HeapAlloc delta check across a generated multi-commit fixture; assert the delta is independent of history length (proving streaming) and `ns/op` under a planner-set budget. Concrete thresholds = Open Question 1 / A4.

## Security Domain

> `security_enforcement` not explicitly false in config — included.

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | No auth in this phase (hook is offline, no network) |
| V3 Session Management | no | — |
| V4 Access Control | no | Local CLI only |
| V5 Input Validation | yes | Untrusted repo content (diff lines, file paths, commit messages) flows through RE2 (linear-time, ReDoS-safe — already enforced). go-gitdiff parses untrusted patch text; treat parse errors as non-fatal-per-file but fail-loud on git process error. |
| V6 Cryptography | no | Fingerprint uses SHA-256 (already implemented, unchanged) |
| V7 Error/Logging | yes | **Redact-at-boundary invariant extends to diff lines:** a raw diff line containing a secret must never be logged/serialized. All findings go through `finding.New` (redacts). Never log `l.Line` verbatim in verbose mode. Commit message/author are non-secret metadata (safe). |
| V12 Files/Resources | yes | Hook installer writes to `.git/hooks`: refuse to clobber (D-05), set exec bit, validate resolved hook path is under the repo. `exec.Command` arg lists (never shell strings) — no command injection from repo paths. |

### Known Threat Patterns for {Go CLI + git shell-out}

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Command injection via repo path / branch name | Tampering | Use `exec.Command(name, args...)` arg slice (never `sh -c`); pass paths as `-C <repo>` args, not interpolated strings |
| ReDoS via adversarial diff content | Denial of Service | RE2 (stdlib `regexp`) linear-time — already locked (CLAUDE.md "What NOT to Use" forbids regexp2) |
| Secret leakage in logs/verbose output | Info Disclosure | Redact at `finding.New`; never `fmt.Fprintf(stderr, ...l.Line...)` with a raw added line |
| Hook clobbering a user's existing pre-commit | Tampering | Refuse without `--force`; managed-marker check on uninstall (D-05) |
| Hook making a network call (verification in pre-commit) | (policy violation) | Hook only runs `mimir scan --staged`; VERIFY-01 forbids `--verify` in hook — offline guarantee |
| Zombie git process / resource exhaustion on early cancel | Denial of Service | `exec.CommandContext` + drain/close pipe + deferred `cmd.Wait()` (Pitfall 2) |

## Sources

### Primary (HIGH confidence)
- `github.com/gitleaks/go-gitdiff@v0.9.1` local module cache — `gitdiff.go` (File/TextFragment/Line/LineOp types), `parser.go` (`Parse` returns `<-chan *File`), `patch_header.go` (PatchHeader SHA/Author/AuthorDate/Title) — read directly.
- Empirical probe (this session) — ran `gitdiff.Parse` against real `git log -p -U0` and `git diff --staged -U0` output on temp repos; verified deleted-secret detection, line-number attribution, staged empty-PatchHeader, OpAdd line content.
- `git version 2.54.0`, `go version go1.26.2`, `go list -m -versions github.com/gitleaks/go-gitdiff` — local tool verification.
- `CLAUDE.md` — locked stack (go-gitdiff, shell-out, RE2, no go-git default).
- Existing source: `internal/scanner/scanner.go`, `internal/detect/engine.go`, `internal/finding/finding.go`, `internal/suppress/inline.go`, `internal/output/{human,json}.go`, `cmd/mimir/scan.go`, `cmd/mimir/scan_test.go` — read directly for integration seams.
- `.planning/phases/03-.../03-CONTEXT.md` — locked decisions D-01..D-10.

### Secondary (MEDIUM confidence)
- gitleaks `sources/git.go` (via WebFetch of raw GitHub) — confirmed `log -p -U0 --full-history --all --diff-filter=tuxdb` and staged `diff -U0 --no-ext-diff --staged .` flag patterns; line-number computation via NewPosition.
- gitleaks `detect/detect.go` (WebFetch) — blob-join + newlineIndices approach (the alternative Mimir rejects in favor of per-line).
- gitleaks `.pre-commit-hooks.yaml` (WebFetch) — manifest field shape (id/name/entry/language/pass_filenames).

### Tertiary (LOW confidence)
- WebSearch (pkg.go.dev go-gitdiff, gitleaks issues) — corroborating TextFragment field semantics; superseded by direct source read + probe.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — go-gitdiff v0.9.1 verified present, latest, gitleaks-maintained; API read from source and exercised empirically.
- Architecture: HIGH — integration seams read directly from existing code; per-line `engine.ScanLine` reuse confirmed; streaming channel verified.
- Pitfalls: HIGH — Pitfalls 1, 3, 5 empirically reproduced; 2 read from go-gitdiff goroutine source; 4 mirrors existing fail-loud pattern.
- Benchmark thresholds: LOW — explicitly planner territory (A4 / Open Q1); construction approach is HIGH, concrete numbers must be measured.

**Research date:** 2026-05-30
**Valid until:** 2026-06-29 (stable Go ecosystem; go-gitdiff v0.9.1 is current — re-verify only if gitleaks fork bumps majors)
