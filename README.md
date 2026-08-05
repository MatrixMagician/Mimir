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

## Exit codes

Mimir's exit code is the contract CI depends on:

| Code | Meaning |
| ---- | ------- |
| `0`  | No reportable findings, and every selected file was read (or `--exit-zero` was passed) |
| `1`  | One or more reportable findings — the pre-commit hook blocks the commit |
| `2`  | Error: bad flags, unreadable config, malformed baseline, not a git repo, missing `git` |

Suppressed findings never flip the exit code, even under `--show-suppressed`.

An **incomplete** scan also exits `1`. If a file was selected but could not be
read (permissions, I/O error), mimir warns on stderr, reports the count in the
summary and as `files_unreadable` in JSON, and fails — because "no findings"
across a file nobody could open is not evidence of no secrets. Pass
`--exit-zero` if you want CI to proceed anyway.

## Suppressing false positives

Three layers, applied in this order:

**1. Inline directives** — put a comment on the offending line:

```go
apiKey := "not-really-a-secret"  // mimir:ignore
token := "another"               // mimir:ignore:generic-api-key,github-pat
```

Bare `mimir:ignore` suppresses every rule on that line; the scoped form suppresses
only the listed rule IDs.

**2. `.mimirignore`** — gitignore-style path globs at the scan root. One glob per
line, `#` for comments, and a leading `!` re-includes a path (last match wins):

```
**/*.generated.go
**/*.env
!**/*.env.example
```

As in `.gitignore`, a negation cannot resurrect a path inside an already-excluded
**directory**: once `docs/**` prunes the directory, mimir never descends into it,
so `!docs/security/**` would have nothing to re-include. Exclude at the file level
(`docs/**/*.md`) if you need to carve an exception back out.

Vendored and generated paths (`vendor/`, `node_modules/`, `*.min.js`, lockfiles)
are excluded by default already; pass `--no-default-excludes` to scan them anyway.
This repo's own [`.mimirignore`](.mimirignore) is a worked example.

**3. Baselines** — accept the current findings, then alert only on new ones:

```sh
mimir scan --baseline-out .mimir-baseline.json .   # snapshot today's findings
mimir scan --baseline .mimir-baseline.json .       # exit 1 only on NEW findings
```

A baselined finding survives a file move, because the entry is matched on secret
content rather than on file path alone.

Use `--show-suppressed` to see what each layer withheld, annotated with the
reason and informational only.

## Custom rules

Drop a `.mimir.toml` at the scan root, or point at one with `--config`:

```toml
[extend]
use_default = true              # start from the shipped ruleset
disabled_rules = ["jwt"]        # ...minus these

[[rules]]
id = "acme-internal-token"
description = "ACME internal service token"
regex = '''\b(acme_[A-Za-z0-9]{32})\b'''
entropy = 3.0
keywords = ["acme_"]            # required: the Aho-Corasick pre-filter gate
```

Redeclaring a shipped rule's `id` **replaces** it, which is how you tighten or
loosen a default rule. Set `use_default = false` to run only your own rules.

Regexes are RE2 (no lookahead or backreferences) and are validated at load time —
a bad pattern fails loud with the offending rule ID rather than being skipped
silently. Use `entropy` and `[[rules.allowlists]]` instead of lookarounds.

## Live verification

`--verify` checks detected AWS and GitHub credentials against their providers and
labels each one `[ACTIVE]`, `[INACTIVE]`, or `[UNKNOWN]`:

```sh
mimir scan --verify .
```

It is **off by default**, and the pre-commit hook never enables it. It only ever
makes read-only calls (AWS STS `GetCallerIdentity`, GitHub `GET /user`), only on
findings that survived suppression, and it never changes the exit code — a live
credential and a dead one both still just count as a finding.

A network failure, timeout, or rate-limit always yields `unknown`, never
`inactive`, so an unreachable provider can never be read as "this key is safe".
