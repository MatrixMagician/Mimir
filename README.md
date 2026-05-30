# Mimir

A Go-based scanner that scans repos and env files for leaked secrets such as API keys, passwords, tokens, private keys and connection strings.

## Scanning sources

Mimir scans the working tree by default. Two additional git-aware modes cover full
source history and what is about to be committed:

```sh
mimir scan                 # working tree (default)
mimir scan --git           # current-branch git history (catches added-then-deleted secrets)
mimir scan --staged        # the staged diff (git diff --staged) — what the pre-commit hook runs
```

`--git` and `--staged` are mutually exclusive (passing both exits with code 2).

**Runtime prerequisite:** `--git` and `--staged` (and the pre-commit hook) shell out to
the system `git` binary, so **`git` ≥ 2.x must be on your `PATH`**. In a non-git
directory, or with `git` absent, these modes fail loud (exit 2) rather than reporting a
misleading "clean".

## Pre-commit hook

Install Mimir as a managed pre-commit hook so any commit containing a staged secret is
blocked automatically — offline and fast:

```sh
mimir hook install         # install into the current repo (or: mimir hook install <path>)
mimir hook status          # report whether the managed hook is installed
mimir hook uninstall       # remove ONLY Mimir's managed hook
```

The installer resolves the hook directory via `git rev-parse --git-path hooks`, so it
works under worktrees, submodules, and `core.hooksPath` (it does not hardcode
`.git/hooks`). The installed hook is **staged-only** and **fully offline** — it runs
`mimir scan --staged` and never performs live verification.

**Overwrite policy:** `mimir hook install` refuses to overwrite an existing non-Mimir
`pre-commit` hook. Pass `--force` to replace it. `mimir hook uninstall` only removes a
hook that carries Mimir's managed marker, so a hook you wrote yourself is never deleted.

### Honest bypass

When you genuinely need to commit without scanning, there are two documented bypasses:

```sh
git commit --no-verify                 # skip all hooks for this one commit
git config hooks.mimir false           # persistently disable the mimir hook
git config hooks.mimir true            # re-enable it
git config --unset hooks.mimir         # remove the toggle (also re-enables)
```

### pre-commit-framework users

Mimir also ships a `.pre-commit-hooks.yaml` manifest, so [pre-commit](https://pre-commit.com)
or husky users can reference it directly:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/MatrixMagician/mimir
    rev: <tag>
    hooks:
      - id: mimir
```
