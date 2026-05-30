---
phase: 03-full-source-coverage-git-history-staged-pre-commit
plan: 03
subsystem: cli-hook
tags: [pre-commit, hook, git, installer, offline, cobra, e2e]

# Dependency graph
requires:
  - phase: 03-02
    provides: "mimir scan --staged (gitscan.ScanStaged) — the offline staged scan the hook invokes; exits 1 on a staged secret (IFACE-02), 0 when clean"
  - phase: 02-false-positive-control
    provides: "inline-ignore suppression (// mimir:ignore) honored on staged lines (criterion 3)"
  - phase: 01-foundation
    provides: "cobra rootCmd + SilenceErrors/SilenceUsage, version.go command shape, exit-code contract (IFACE-02), redact-at-boundary (finding.New)"
provides:
  - "mimir hook install/uninstall/status cobra group (cmd/mimir/hook.go): writes a managed, offline, staged-only pre-commit hook"
  - "hook-dir resolution via 'git rev-parse --git-path hooks' (worktree/submodule/core.hooksPath safe, never hardcoded .git/hooks)"
  - "managed-marker discipline: install refuses to clobber a foreign hook without --force (D-05); uninstall removes only the marker-bearing managed hook"
  - ".pre-commit-hooks.yaml manifest (D-07) for pre-commit-framework / husky users"
  - "README documentation of --git/--staged modes, git>=2.x runtime prerequisite, hook install/overwrite policy, and the honest bypass (D-06)"
affects: [phase-04-verification]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Managed-hook marker line ('# mimir-managed-hook') is the single source of truth for install-refuse / uninstall-protect / status — a foreign hook is identified purely by the marker's absence"
    - "e2e hook tests copy the TestMain-built binary as a file named exactly 'mimir' into a temp dir prepended to the git-commit subprocess PATH, so the hook's 'exec mimir scan --staged' resolves to the just-built binary (never a global mimir, never this project's repo)"

key-files:
  created:
    - cmd/mimir/hook.go
    - cmd/mimir/hook_test.go
    - .pre-commit-hooks.yaml
  modified:
    - README.md

key-decisions:
  - "Hook commands accept an optional [path] arg (default '.') so e2e tests can target an isolated t.TempDir() git repo; the path crosses into git only via an explicit exec.Command arg slice (-C <repo>), never sh -c (T-03-10)"
  - "Marker line '# mimir-managed-hook' drives all three subcommands; install/uninstall key off Contains(marker), so a user's foreign pre-commit hook is never overwritten or deleted (D-05, T-03-11)"
  - "os.Chmod(0755) after os.WriteFile so the exec bit survives overwriting a pre-existing file (WriteFile only applies perms on create)"

patterns-established:
  - "Managed-state-file pattern: write marker → detect via marker → mutate only marker-bearing files (reusable for any future mimir-managed OS state)"
  - "e2e-via-real-git pattern: drive an actual 'git commit' with a PATH-injected test binary to exercise the installed hook end-to-end inside an isolated temp repo"

requirements-completed: [IFACE-03]

# Metrics
duration: 9min
completed: 2026-05-30
---

# Phase 3 Plan 03: Pre-commit Hook Installer Summary

**`mimir hook install/uninstall/status` writes a managed, offline, staged-only pre-commit hook that blocks any commit containing a staged secret (IFACE-03) — resolving the hook dir via `git rev-parse --git-path hooks`, refusing to clobber a foreign hook without `--force` (D-05), honoring an honest bypass (`--no-verify` + `git config hooks.mimir false`, D-06), and shipping a `.pre-commit-hooks.yaml` manifest (D-07) plus README docs.**

## Performance

- **Duration:** ~9 min
- **Tasks:** 3 (Tasks 1–2 TDD)
- **Files:** 4 (3 created, 1 modified)

## Accomplishments
- `cmd/mimir/hook.go`: a parent `hookCmd` with `install`/`uninstall`/`status` subcommands, registered via `hookCmd.AddCommand(...)` + `rootCmd.AddCommand(hookCmd)` (mirrors version.go). `install` carries a `--force` bool flag (mirrors scan.go). Subcommands return errors from `RunE` (rootCmd's `SilenceErrors`/`SilenceUsage` give print-once behavior).
- **Hook-dir resolution via `git rev-parse --git-path hooks`** (never a hardcoded `.git/hooks`) — worktree/submodule/`core.hooksPath` safe. `exec.Command("git", "-C", repoRoot, "rev-parse", "--git-path", "hooks")` is an explicit arg slice (never `sh -c`), so an untrusted repo path cannot inject a command (T-03-10). Guards `exec.LookPath("git")` and fails loud `os.Exit(2)` if git is absent or the dir is not a repo (Pitfall 4).
- **Managed hook script** (`#!/bin/sh`): a unique `# mimir-managed-hook` marker, the off-switch `if [ "$(git config --type=bool --get hooks.mimir)" = "false" ]; then exit 0; fi`, then `exec mimir scan --staged`. It contains **no `--verify`** — the offline guarantee (VERIFY-01, T-03-14). chmod 0755.
- **D-05 never-clobber:** install refuses to overwrite an existing non-marker `pre-commit` without `--force`, naming the path and the `--force` remedy. `uninstall` removes the hook only if it carries the marker — a foreign hook is never deleted (T-03-11). `status` reports installed (managed) / non-mimir-present / not-installed by the same marker check.
- **End-to-end block-commit proof:** `TestHookBlocksCommit` installs the hook, stages a real secret, drives a real `git commit`, and asserts it is blocked (non-zero) with the finding named and **no raw secret** in the hook output (redact-at-boundary, T-03-13/Security V7). `TestHookRespectsInlineIgnore` proves a `// mimir:ignore` staged secret commits cleanly (criterion 3). `TestHookBypass` proves both `--no-verify` and `git config hooks.mimir false` allow the commit, and `--unset` restores blocking (D-06). `TestHookOffline` statically asserts no `--verify` + `--staged`-only.
- **`.pre-commit-hooks.yaml`** (D-07): `id: mimir`, `entry: mimir scan --staged`, `language: golang`, `pass_filenames: false`, with a description — pre-commit-framework / husky users can reference Mimir directly.
- **README**: documents `mimir scan --git`/`--staged`, the `git ≥ 2.x` runtime prerequisite, `mimir hook install/uninstall/status` + the `--force` overwrite policy, the honest bypass (`--no-verify` + `git config hooks.mimir false`/`true`/`--unset`), and the pre-commit-framework manifest usage.

## Task Commits

1. **Task 1 (TDD): hook install/uninstall/status group** — `4ebdf9a` (test, RED) + `602bc94` (feat, GREEN)
2. **Task 2 (TDD e2e): block-commit + honest-bypass** — `a56340f` (test; passes against the Task 1 installer)
3. **Task 3: .pre-commit-hooks.yaml manifest + README** — `6ab197b` (docs)

## Files Created/Modified
- `cmd/mimir/hook.go` (new) — `hookCmd` group; `resolveHookPath` (rev-parse + fail-loud + dir create); `isManaged` (marker check); install/uninstall/status `RunE`s; `managedHookScript` constant.
- `cmd/mimir/hook_test.go` (new) — 9 tests: install/refuse-overwrite/uninstall-managed-only/status/non-repo-fail-loud + block-commit/inline-ignore/bypass/offline e2e; `hookRepo`, `hookPath`, `mimirBinDir`, `commitInRepo`, `stageSecret` helpers.
- `.pre-commit-hooks.yaml` (new) — D-07 framework manifest.
- `README.md` (modified) — scanning-sources + pre-commit-hook + honest-bypass + framework sections.

## Decisions Made
- **Optional `[path]` arg on every hook subcommand (default "."):** lets each e2e test target an isolated `t.TempDir()` git repo so a hook can never fire against this project's own repo. The path reaches git only as a `-C <repo>` arg in an explicit slice (T-03-10).
- **Marker-line as the single managed-state signal:** all of install-refuse, uninstall-protect, and status derive from `strings.Contains(body, "# mimir-managed-hook")`. One mechanism, three behaviors — and a foreign hook is structurally safe.
- **`os.Chmod(0755)` after `os.WriteFile`:** `WriteFile` only applies its perm argument when creating a new file, so overwriting (e.g. `--force` over a foreign hook) needs an explicit chmod to guarantee the exec bit.

## Deviations from Plan
None — plan executed exactly as written.

Threat register satisfied: T-03-10 (rev-parse/config via explicit `exec.Command` arg slice, never `sh -c`), T-03-11 (install refuses non-marker clobber without `--force`; uninstall deletes only the marker-bearing hook — both asserted), T-03-12 (hook path is built by joining the rev-parse-resolved hooks dir + "pre-commit"; dir created with 0755 only there), T-03-13 (`TestHookBlocksCommit` asserts no raw secret in hook output), T-03-14 (`TestHookOffline` asserts no `--verify`; hook scans `--staged` only).

## Known Stubs
None.

## Issues Encountered
None. (A transient grep self-match on the literal `--verify` flag during source verification was resolved by inspecting the file directly: the hook body and code contain no `--verify`; the only `.git/hooks` occurrence is a comment warning against hardcoding it.)

## User Setup Required
None for the build. **Runtime note:** `git ≥ 2.x` must be on `PATH` for `mimir hook` and the `--git`/`--staged` scan modes (documented in README; absence fails loud with exit 2).

## Manual Verification (03-VALIDATION Manual-Only)
A human should confirm the live block once: `mimir hook install` in a real repo, stage a real-looking secret, and verify `git commit` is blocked and `git commit --no-verify` succeeds. The automated `TestHookBlocksCommit`/`TestHookBypass` cover this against a real `git commit`, but the manual sign-off row remains for human confirmation.

## Verification
- `go build ./...` — succeeds; `go vet ./...` — clean.
- `go test -race ./...` — all packages green (incl. the 9 hook tests).
- `go test ./cmd/mimir/ -run 'TestHookInstall|TestHookInstallRefusesOverwrite|TestHookUninstallManagedOnly|TestHookStatus|TestHookNonRepoFailsLoud' -count=1` — pass.
- `go test ./cmd/mimir/ -run 'TestHookBlocksCommit|TestHookRespectsInlineIgnore|TestHookBypass|TestHookOffline' -count=1` — pass.
- Task 3 verify: `.pre-commit-hooks.yaml` has `pass_filenames: false` + `scan --staged`; README has `--no-verify` + `hooks.mimir` — all present.
- Offline guarantee: hook body contains no `--verify`; hook dir is resolved via `git rev-parse --git-path hooks` (no hardcoded `.git/hooks` in code).

## Self-Check: PASSED

All created/modified files present (cmd/mimir/hook.go, cmd/mimir/hook_test.go, .pre-commit-hooks.yaml, README.md, 03-03-SUMMARY.md) and all task commits exist (4ebdf9a, 602bc94, a56340f, 6ab197b).

---
*Phase: 03-full-source-coverage-git-history-staged-pre-commit*
*Completed: 2026-05-30*
