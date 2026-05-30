---
phase: 03-full-source-coverage-git-history-staged-pre-commit
verified: 2026-05-30T00:00:00Z
status: passed
score: 4/4 success criteria verified (13/13 plan must-have truths verified)
overrides_applied: 0
re_verification:
  previous_status: none
  previous_score: n/a
human_verification:
  - test: "Live pre-commit block in a real repo (03-VALIDATION Manual-Only sign-off)"
    expected: "mimir hook install in a real repo, stage a real-looking secret, git commit is BLOCKED; git commit --no-verify SUCCEEDS"
    why_human: "Automated TestHookBlocksCommit/TestHookBypass cover this against a real git commit subprocess in CI; the manual sign-off row remains for a one-time human confirmation in a genuine working repo. Non-blocking — automated e2e already proves the behavior."
---

# Phase 3: Full Source Coverage (Git History + Staged + Pre-commit) Verification Report

**Phase Goal:** Mimir scans where secrets actually leak — past commits (including deleted secrets) and the staged diff — and installs as a fast, offline pre-commit hook that blocks commits containing secrets.
**Verified:** 2026-05-30
**Status:** passed
**Mode:** mvp (verified against the 4 ROADMAP Success Criteria — the roadmap contract)
**Re-verification:** No — initial verification

## Goal Achievement

This phase is MVP-mode. The ROADMAP goal is a capability statement backed by 4 Success Criteria (the contract). Each per-plan `<phase_goal>` is a proper User Story; the ROADMAP-level goal is not a strict "As a…/I want…/so that…" sentence, so verification is performed against the 4 Success Criteria plus the 13 plan-frontmatter must-have truths (which refine, never reduce, the SCs).

### Observable Truths — ROADMAP Success Criteria (the contract)

| # | Success Criterion | Status | Evidence |
| --- | --- | --- | --- |
| SC-1 | User can scan git history and Mimir finds a secret added in a past commit and later deleted | ✓ VERIFIED | `gitscan.ScanHistory` streams `git log -p -U0 --full-history --no-color` (command.go:23) → `parsePatch` OpAdd → `engine.ScanLine` (parse.go:52). Test `TestHistoryDeletedSecret` (PASS) commits a non-EXAMPLE AWS key then deletes the file; finding returned with non-empty CommitSHA. End-to-end `TestGitModeFindsHistorySecret` (PASS): `mimir scan --git` exits 1 with ` @ ` short-SHA marker. |
| SC-2 | History scan keeps peak memory bounded + wall time acceptable, verified by a benchmark gate | ✓ VERIFIED | `BenchmarkHistoryMem` (bench_test.go) measured live: 50-commit 0.79 MB/3.2 ms vs 500-commit 2.06 MB/7.8 ms — 10x history → ~2.6x heap (sub-linear ⇒ streamed, not buffered). Gate `b.Fatalf` on >16 MB or >wall ceiling (bench_test.go:158,163) — PASSED. `gitdiff.Parse` consumed via channel `range` (parse.go:35); no `io.ReadAll`. |
| SC-3 | User can scan staged changes and an installed pre-commit hook blocks a secret commit while respecting inline `// mimir:ignore` | ✓ VERIFIED | `gitscan.ScanStaged` streams `git diff -U0 --no-ext-diff --no-color --staged` (command.go:43); `TestStagedModeFindsSecret` (PASS) exits 1. Hook e2e `TestHookBlocksCommit` (PASS): real `git commit` with staged secret blocked, no raw secret in output. Inline-ignore: `TestStagedInlineIgnore` + `TestHookRespectsInlineIgnore` (PASS) — `// mimir:ignore` line commits cleanly. |
| SC-4 | Hook is staged-only, fully offline, sub-second on a typical staged diff, with an honest documented bypass | ✓ VERIFIED | Hook body `exec mimir scan --staged`, NO `--verify` (hook.go:28); `TestHookOffline` (PASS) asserts no `--verify`. `BenchmarkStaged` 0.82 ms/op (sub-second). Bypass: `git commit --no-verify` + `git config hooks.mimir false` off-switch (hook.go:25); `TestHookBypass` (PASS). README + `.pre-commit-hooks.yaml` document it. |

**Score: 4/4 Success Criteria verified.**

### Plan-Frontmatter Must-Have Truths (refining detail)

| # | Truth (plan) | Status | Evidence |
| --- | --- | --- | --- |
| 1 | `--git` reports an added-then-deleted secret with commit SHA (SC-1, crit 1) | ✓ VERIFIED | TestHistoryDeletedSecret / TestGitModeFindsHistorySecret PASS |
| 2 | History findings carry SHA/author/date; WT+staged do not (OUT-02 byte-identical) | ✓ VERIFIED | D-08 omitempty fields finding.go:56-58; `attachCommitMeta` SHA-guard parse.go:87; TestCommitMetaOmitempty + TestStagedModeNoCommitJSON PASS |
| 3 | Same secret across commits collapses to one fingerprint (D-09) | ✓ VERIFIED | `dedupByFingerprint` gitscan.go:138; TestHistoryDedup PASS (1 fingerprint) |
| 4 | `--git` on non-repo / no git → exit 2 (fail-loud) | ✓ VERIFIED | `startGit` LookPath + non-zero `cmd.Wait()` error (command.go:58, gitscan.go:49); TestHistoryNonRepoFailsLoud + TestGitModeNonRepoFailsLoud PASS |
| 5 | History scan streams (no io.ReadAll); memory bounded | ✓ VERIFIED | parse.go:35 channel range; BenchmarkHistoryMem gate PASS |
| 6 | `--staged` reports staged secret at correct file:line (SC-3, crit 3) | ✓ VERIFIED | TestStagedSecret asserts Line==1; TestStagedModeFindsSecret PASS |
| 7 | Staged scan respects inline `// mimir:ignore` | ✓ VERIFIED | Shared parsePatch inline-ignore block parse.go:56-64; TestStagedInlineIgnore(Cmd) PASS |
| 8 | `--git` + `--staged` mutually exclusive → exit 2 | ✓ VERIFIED | scan.go:104-107; TestGitStagedMutuallyExclusive PASS |
| 9 | Staged findings have no commit metadata (OUT-02 stable) | ✓ VERIFIED | empty PatchHeader → attachCommitMeta no-op; TestStagedSecret CommitSHA empty + TestStagedModeNoCommitJSON PASS |
| 10 | History peak memory bounded — benchmark gate (SC-2) | ✓ VERIFIED | BenchmarkHistoryMem FATAL-gate, measured sub-linear, PASS |
| 11 | `hook install` writes managed hook; refuses overwrite without `--force` (D-05) | ✓ VERIFIED | hook.go:122-135; TestHookInstall + TestHookInstallRefusesOverwrite + TestHookInstallRefusesSymlink PASS |
| 12 | Installed hook blocks staged-secret commit + respects inline-ignore | ✓ VERIFIED | TestHookBlocksCommit + TestHookRespectsInlineIgnore PASS (real git commit) |
| 13 | Hook staged-only/offline + honest bypass; uninstall removes only managed hook; rev-parse hook-dir | ✓ VERIFIED | hook.go: `git rev-parse --git-path hooks` (line 86), marker-gated uninstall (line 179), TestHookOffline/Bypass/UninstallManagedOnly/Status PASS |

**Plan truths: 13/13 verified.**

### Required Artifacts

| Artifact | Expected | Status | Details |
| --- | --- | --- | --- |
| `internal/gitscan/command.go` | git arg-slice builders + startGit | ✓ VERIFIED | historyArgs/stagedArgs/startGit; exec.CommandContext arg slice, no sh -c |
| `internal/gitscan/parse.go` | streaming OpAdd → ScanLine + inline-ignore + commit-meta | ✓ VERIFIED | gitdiff.Parse channel range; InlineSuppresses; attachCommitMeta SHA-guard |
| `internal/gitscan/gitscan.go` | ScanHistory + ScanStaged + dedup | ✓ VERIFIED | both exported; WR-01 line/SHA coherence fix at lines 146-156 |
| `internal/gitscan/bench_test.go` | BenchmarkHistoryMem (gate) + BenchmarkStaged | ✓ VERIFIED | measured-baseline comment; b.Fatalf gate; ran PASS |
| `internal/finding/finding.go` | D-08 omitempty commit fields; fingerprint untouched | ✓ VERIFIED | commit_sha/author/date omitempty (56-58); computeFingerprint+New unchanged |
| `internal/output/human.go` | short-SHA line (D-10) + sanitizeForTTY | ✓ VERIFIED | short-SHA branch (64-70); sanitizeForTTY incl. U+2028/29 (WR-04 fix, 149); IN-01 dead code removed |
| `cmd/mimir/scan.go` | --git/--staged flags + source switch + mutual-exclusion | ✓ VERIFIED | flags 35-36; switch 110-117; exclusion 104-107; exit-code block unchanged |
| `cmd/mimir/hook.go` | hook install/uninstall/status group | ✓ VERIFIED | hookCmd group; rev-parse dir; Lstat+O_NOFOLLOW TOCTOU hardening |
| `cmd/mimir/hook_nofollow_{unix,windows}.go` | build-tagged O_NOFOLLOW | ✓ VERIFIED | unix=syscall.O_NOFOLLOW, windows=0 no-op; both build OK |
| `.pre-commit-hooks.yaml` | D-07 framework manifest | ✓ VERIFIED | id:mimir, entry:scan --staged, language:golang, pass_filenames:false |
| `README.md` | git/staged modes + prerequisite + hook + bypass docs | ✓ VERIFIED | --git/--staged, rev-parse, --no-verify, hooks.mimir all present |

### Key Link Verification

| From | To | Via | Status |
| --- | --- | --- | --- |
| cmd/mimir/scan.go | gitscan.ScanHistory | --git branch | ✓ WIRED (scan.go:112) |
| cmd/mimir/scan.go | gitscan.ScanStaged | --staged branch | ✓ WIRED (scan.go:114) |
| parse.go | engine.ScanLine | per-OpAdd call | ✓ WIRED (parse.go:52) |
| parse.go | suppress.InlineSuppresses | inline-ignore on diff lines | ✓ WIRED (parse.go:57) |
| command.go | git log -p / git diff --staged | exec.CommandContext arg slice | ✓ WIRED (command.go:24,43,62) |
| hook.go | git rev-parse --git-path hooks | hook-dir resolution | ✓ WIRED (hook.go:86) |
| installed hook script | mimir scan --staged | exec line | ✓ WIRED (hook.go:28) |
| installed hook script | git config hooks.mimir | off-switch bypass | ✓ WIRED (hook.go:25) |
| bench_test.go | runtime ReadMemStats HeapAlloc | criterion-2 gate | ✓ WIRED (heapDelta + Fatalf gate) |

### Security Follow-Up Fixes (task note — verified real AND tested, not just claimed)

| Fix | Location | Real? | Tested? |
| --- | --- | --- | --- |
| Terminal-escape sanitization incl. U+2028/U+2029 (WR-04) | internal/output/human.go:146-177 (`isUnsafe` includes ` `/` ` at line 149) | ✓ Present | ✓ human_test.go:128-129 asserts NotContains U+2028/U+2029 |
| Symlink-follow / TOCTOU hardening (Lstat + O_NOFOLLOW, build-tagged) | cmd/mimir/hook.go:122-154 + hook_nofollow_{unix,windows}.go | ✓ Present (Lstat refuse, os.Remove symlink, OpenFile O_NOFOLLOW, f.Chmod on fd) | ✓ TestHookInstallRefusesSymlink PASS; builds on both tags |
| Dedup line/SHA-coherence fix (WR-01) | internal/gitscan/gitscan.go:146-156 (adopts earlier commit's Line/Column with its SHA) | ✓ Present | △ TestHistoryDedup covers collapse; explicit line/SHA-pairing assertion not isolated (minor coverage note, not a gap) |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| --- | --- | --- | --- |
| Build | `go build ./...` | clean | ✓ PASS |
| Vet | `go vet ./...` | clean | ✓ PASS |
| Full suite -race | `go test -race ./...` | all packages ok | ✓ PASS |
| Phase-3 behavioral tests (uncached) | `go test -count=1 -run 'TestHistory\|TestStaged\|TestGit\|TestHook\|TestCommitMeta\|TestFingerprint\|TestNoRawSecret'` | 30+ subtests PASS, 0 FAIL | ✓ PASS |
| Criterion-2 bench gate | `go test -bench 'BenchmarkHistoryMem\|BenchmarkStaged' -benchmem` | sub-linear heap, gate PASS | ✓ PASS |
| Supply-chain | `go mod verify` | all modules verified | ✓ PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
| --- | --- | --- | --- | --- |
| SCAN-03 | 03-01 | Scan git history incl. later-deleted secrets | ✓ SATISFIED | ScanHistory + TestHistoryDeletedSecret + TestGitModeFindsHistorySecret |
| SCAN-04 | 03-02 | Scan staged changes for pre-commit use | ✓ SATISFIED | ScanStaged + TestStagedModeFindsSecret + inline-ignore tests |
| IFACE-03 | 03-03 | Install pre-commit hook blocking secret commits (staged-only/offline/fast/honest bypass) | ✓ SATISFIED | hook install/uninstall/status + TestHookBlocksCommit/Bypass/Offline |

No orphaned requirements: REQUIREMENTS.md maps exactly SCAN-03, SCAN-04, IFACE-03 to Phase 3, each claimed by one plan. (Note: the `[ ]` checkboxes in REQUIREMENTS.md lines 22/23/30 are an un-ticked docs-tracking artifact; implementation and tests fully satisfy all three — recommend ticking them.)

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| --- | --- | --- | --- | --- |
| (none) | — | No TBD/FIXME/XXX/HACK/PLACEHOLDER in phase-modified non-test files | ℹ️ Info | Clean |
| internal/output/human.go | — | IN-01 dead code (`uniqueFileCount`/`suppressInlineReason`) | ℹ️ Info | RESOLVED — both removed |

### Outstanding Code-Review Warnings (non-blocking, pre-existing)

Two of the four 03-REVIEW WARNINGs were intentionally NOT among the three applied follow-up fixes. Neither blocks any Success Criterion — both are robustness/UX edge cases. Surfaced for human decision:

- **WR-02** (scan.go): `--git`/`--staged` silently drop extra positional path args (`mimir scan --git ./a ./b` scans full repo, ignoring scope). UX foot-gun in a security tool. Not goal-blocking — single-root usage (the documented path and what the hook uses) works correctly.
- **WR-03** (scan.go:204-223 `resolveScanRoot`): hand-rolled separator splitting diverges from `filepath.Dir`/`Clean` on trailing-slash / bare-filename edge cases. Pre-existing from Phase 1; not introduced by this phase and not goal-blocking.

(IN-02/IN-03/IN-04 INFO items from the review remain as documented; cosmetic/comment-accuracy only.)

### Human Verification Required

1. **Live pre-commit block sign-off (03-VALIDATION Manual-Only)** — Non-blocking confirmation.
   - **Test:** `mimir hook install` in a real working repo, stage a real-looking secret, run `git commit`.
   - **Expected:** commit BLOCKED (non-zero); `git commit --no-verify` SUCCEEDS; `git config hooks.mimir false` then `git commit` SUCCEEDS.
   - **Why human:** The automated `TestHookBlocksCommit`/`TestHookBypass` already drive a real `git commit` subprocess and pass; this is a one-time human sign-off in a genuine repo per the phase's validation plan, not a gap.

### Gaps Summary

No gaps. All 4 ROADMAP Success Criteria and all 13 plan-frontmatter must-have truths are verified against the actual codebase: source exists, is substantive, is wired into `runScan`/the hook, and data flows end-to-end (real `git log -p`/`git diff --staged` streams through go-gitdiff into the engine; the installed hook blocks a real commit). The build is clean, `go test -race ./...` is green, the criterion-2 benchmark gate passes with sub-linear (streamed) memory, and `go mod verify` confirms the go-gitdiff supply-chain. All three claimed security follow-up fixes (U+2028/29 sanitization, symlink/TOCTOU O_NOFOLLOW hardening, dedup line/SHA coherence) are present in source and the first two are directly tested.

Status is `passed` with one non-blocking human sign-off item (the live-commit manual confirmation already covered by automated e2e).

---

_Verified: 2026-05-30_
_Verifier: Claude (gsd-verifier)_
