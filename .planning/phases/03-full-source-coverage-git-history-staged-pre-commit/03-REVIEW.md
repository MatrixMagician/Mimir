---
phase: 03-full-source-coverage-git-history-staged-pre-commit
reviewed: 2026-05-30T00:00:00Z
depth: standard
files_reviewed: 14
files_reviewed_list:
  - cmd/mimir/hook.go
  - cmd/mimir/hook_test.go
  - cmd/mimir/hook_nofollow_unix.go
  - cmd/mimir/hook_nofollow_windows.go
  - cmd/mimir/scan.go
  - cmd/mimir/scan_test.go
  - internal/finding/finding.go
  - internal/finding/finding_test.go
  - internal/gitscan/bench_test.go
  - internal/gitscan/command.go
  - internal/gitscan/gitscan.go
  - internal/gitscan/gitscan_test.go
  - internal/gitscan/parse.go
  - internal/output/human.go
findings:
  critical: 0
  warning: 4
  info: 4
  total: 8
status: issues_found
---

# Phase 3: Code Review Report

**Reviewed:** 2026-05-30
**Depth:** standard
**Files Reviewed:** 14
**Status:** issues_found

## Summary

Phase 3 adds git-history scanning (`--git`), staged scanning (`--staged`), and a
managed pre-commit hook (`mimir hook`). The security-sensitive surfaces hold up well
under adversarial review:

- **Command injection (V12):** `historyArgs`/`stagedArgs`/`startGit`/`resolveHookPath`
  all use explicit `exec.Command` arg slices with `repoRoot` as a distinct argument.
  No `sh -c`, no interpolation. Sound.
- **Redact-at-boundary:** `finding.New` redacts at construction; the new commit metadata
  fields carry only SHA/author/date and never the raw secret; `parsePatch` passes raw
  lines only into `engine.ScanLine` → `finding.New`. The reflect-based regression test
  guards it. Sound.
- **Symlink/TOCTOU hardening (hook.go):** The `Lstat` + `O_NOFOLLOW` + post-`Lstat`
  remove-then-create flow is correct. `os.Remove` unlinks the symlink, not the target;
  `O_NOFOLLOW` fails closed on a raced-in link; `f.Chmod` on the fd (not the path) avoids
  a re-substitution window. The Windows no-op is acceptable and documented. Sound.
- **Terminal-escape sanitization (human.go `sanitizeForTTY`):** Correctly strips ESC/DEL/C0
  (except tab) and length-caps. Applied to every untrusted-origin field (file, SHA, author,
  date, secret, fingerprint). Sound. (Minor robustness note in WR-04.)

No BLOCKER-class defects found. Four WARNINGs (one a real cross-commit attribution
correctness bug, three robustness/consistency gaps) and four INFO items follow.

## Warnings

### WR-01: Cross-commit dedup attributes the wrong line number to the kept commit SHA

**File:** `internal/gitscan/gitscan.go:138-157`, surfaced at `internal/output/human.go:64-66`

**Issue:** `dedupByFingerprint` keeps the **first-seen** finding's positional data
(`File`, `Line`, `Column`) but, on a duplicate with an earlier `CommitDate`, overwrites
only `CommitSHA`/`CommitAuthor`/`CommitDate` (lines 146-150). `git log -p` emits commits
newest-first, so the first-seen occurrence is from the **newest** commit while the copied
SHA points to the **oldest** commit. The result is a finding whose displayed `Line`
(and file, if the secret moved) belongs to a *different* commit than the displayed short
SHA. The human one-liner prints `%s:%d:%d @ %s` (`file:line @ SHA`) — so a user who
`git show`s that SHA at that line may find an unrelated line, undermining the D-10 "jump
to the leaking commit" promise. The doc comment claims "the earliest-introducing commit is
kept," but only its *metadata* is kept, not its *location*.

**Fix:** When adopting the earlier commit's metadata, adopt its location too, so SHA and
position stay consistent:

```go
if f.CommitDate != "" && (out[pos].CommitDate == "" || f.CommitDate < out[pos].CommitDate) {
    out[pos].CommitSHA = f.CommitSHA
    out[pos].CommitAuthor = f.CommitAuthor
    out[pos].CommitDate = f.CommitDate
    out[pos].File = f.File     // keep location consistent with the attributed commit
    out[pos].Line = f.Line
    out[pos].Column = f.Column
}
```

Note: changing `File` would also change the fingerprint key in principle, but since dedup
keys on the existing `Fingerprint` (already computed, path-based) this only affects display,
which is the intent. If keeping the newest line is actually desired, fix the doc comment
instead — but then the SHA should also be the newest commit's, not the oldest.

### WR-02: `--git` / `--staged` silently ignore positional path arguments

**File:** `cmd/mimir/scan.go:44-49, 110-117`

**Issue:** `runScan` resolves `paths` (defaulting to `["."]`) and `scanRoot` from args,
then for `--git`/`--staged` passes only `scanRoot` to `gitscan.ScanHistory`/`ScanStaged`.
Any *additional* positional paths a user supplies (e.g. `mimir scan --git ./a ./b`) are
silently dropped — only the first path's resolved root is used. A user reasonably expecting
`mimir scan --git pkg/secrets/` to scope history to a subtree gets a full-repo history scan
with no warning. Silent scope mismatch in a security tool risks a false sense of coverage.

**Fix:** Either document that `--git`/`--staged` take at most one repo-root arg and reject
extras, or scope the diff to the given pathspecs. Minimal fix — reject misuse loudly,
consistent with the other `os.Exit(2)` guards:

```go
if (gitMode || stagedMode) && len(args) > 1 {
    fmt.Fprintln(os.Stderr, "error: --git/--staged accept at most one repository path")
    os.Exit(2)
}
```

### WR-03: `resolveScanRoot` mishandles a bare filename and trailing-slash paths

**File:** `cmd/mimir/scan.go:204-223`

**Issue:** When `paths[0]` is an existing **file** with no separator (e.g. `mimir scan
config.go` run in the file's own directory), the manual separator scan at lines 217-221
finds no `/` or `\` and returns `"."` — correct by luck. But when `paths[0]` is a directory
given with a trailing slash that does not exist as given, or a relative file like
`./config.go`, the hand-rolled loop returns `.` / `.` inconsistently with what
`filepath.Dir` would yield, and the `info.IsDir()` branch returns `paths[0]` *including a
trailing slash*, which then flows into config discovery and `gitscan` as a repo root. This
hand-rolled path splitting duplicates and diverges from stdlib `filepath.Dir`/`filepath.Clean`,
which already handle every separator/trailing-slash edge case cross-platform.

**Fix:** Replace the manual loop with stdlib:

```go
func resolveScanRoot(paths []string) string {
    if len(paths) == 0 {
        return "."
    }
    info, err := os.Stat(paths[0])
    if err != nil {
        return "."
    }
    if info.IsDir() {
        return filepath.Clean(paths[0])
    }
    return filepath.Dir(paths[0])
}
```

### WR-04: `sanitizeForTTY` does not neutralize lone CR / U+2028 / U+2029 line-spoofing

**File:** `internal/output/human.go:141-169`

**Issue:** The sanitizer strips ESC (0x1b), DEL (0x7f), and C0 controls except tab. That
correctly covers `\r` (0x0d, a C0 control) and `\n` (0x0a) — good. But it does **not** strip
the Unicode line separators **U+2028 (LINE SEPARATOR)** and **U+2029 (PARAGRAPH SEPARATOR)**,
which many terminals and downstream log viewers render as line breaks. A crafted commit
author name or file path containing U+2028 can therefore still inject a visual newline and
forge a second output line (a weaker variant of the T-03-03 log-injection the function exists
to stop). Because the function is the designated chokepoint for *all* untrusted repo metadata,
this gap applies uniformly to author, path, and snippet.

**Fix:** Treat U+2028/U+2029 (and optionally U+0085 NEL) as control runes in both the
detection scan and the rewrite loop:

```go
func isControl(r rune) bool {
    return r == 0x1b || r == 0x7f || (r < 0x20 && r != '\t') ||
        r == 0x85 || r == 0x2028 || r == 0x2029
}
```

and use `isControl(r)` in both loops in place of the inlined condition.

## Info

### IN-01: Dead code — `uniqueFileCount` and `suppressInlineReason` are unused

**File:** `internal/output/human.go:171-182`

**Issue:** `uniqueFileCount` (func) and `suppressInlineReason` (const) are defined but
referenced nowhere in the package (`activeFiles` map is used for the count instead, and the
inline reason comes from `stats.Suppressed` keys). Dead code; `golangci-lint`'s `unused`
linter (enabled per CLAUDE.md) will flag these and can fail CI.

**Fix:** Delete both declarations.

### IN-02: `historyArgs` doc comment cites command-injection threat IDs not relevant to a fixed arg slice; `--full-history` comment is inaccurate

**File:** `internal/gitscan/command.go:14-25`

**Issue:** Two doc inaccuracies. (1) The comment says `--full-history` "follows renames so a
moved-then-leaked file is covered" — `--full-history` does not follow renames; it changes
history simplification for pathspec-limited logs and is a no-op here since no pathspec is
passed. Rename-following would require `--follow` (single file only) or `-M` on the diff.
(2) Minor: the injection-mitigation prose is correct but the threat-ID soup (T-03-01,
V12) belongs in design docs, not the arg-builder. Misleading comments cause future
maintainers to rely on coverage that does not exist (a renamed-then-leaked file is found
only because its *add* appears as `OpAdd` in some commit, not because of `--full-history`).

**Fix:** Correct the comment to describe what `--full-history` actually does, or drop the
flag if its effect was never intended. Verify the renamed-file coverage claim with a test.

### IN-03: `parsePatch` defensive `OpContext` branch is unreachable under `-U0` and untested

**File:** `internal/gitscan/parse.go:44, 69-70`

**Issue:** Both `historyArgs` and `stagedArgs` pass `-U0`, so the patch stream never contains
context lines; the `case gitdiff.OpContext` branch (line 69) is dead under the actual call
sites. It is harmless and arguably good defensive hygiene, but it is untested and silently
relies on an invariant (`-U0` always present) enforced only in a separate file. If a future
change drops `-U0`, the `lineNum` accounting becomes load-bearing with zero coverage.

**Fix:** Either add a unit test that feeds a `>0`-context patch directly to `parsePatch` to
exercise the `OpContext` line-counter, or document that `-U0` is a required precondition of
`parsePatch` (not just the command builders).

### IN-04: `ScanHistory`/`ScanStaged` set `stats.FilesScanned = len(deduped)` — a misleading metric

**File:** `internal/gitscan/gitscan.go:67-70, 122-125`

**Issue:** `FilesScanned` is set to the number of *deduped findings*, not the number of files
(or commits) scanned. The human summary prints `scanned %d files` (human.go:106-110), so a
history scan with 3 findings reports "scanned 3 files" regardless of how many files/commits
git actually emitted — and a clean history reports "scanned 0 files," implying nothing was
examined. This is a cosmetic correctness issue (the field name promises file count) but it
can mislead a user into thinking the scan covered far less than it did.

**Fix:** Track a real count (distinct `f.NewName` seen during `parsePatch`, or commit count)
and assign that to `FilesScanned`; or rename/repurpose the field for git modes and adjust the
summary wording. At minimum, do not derive a "files scanned" number from the post-dedup
finding count.

---

_Reviewed: 2026-05-30_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
