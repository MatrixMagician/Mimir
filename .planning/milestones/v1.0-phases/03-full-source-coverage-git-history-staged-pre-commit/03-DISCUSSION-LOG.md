# Phase 3: Full Source Coverage (Git History + Staged + Pre-commit) - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-29
**Phase:** 3-Full Source Coverage (Git History + Staged + Pre-commit)
**Areas discussed:** CLI surface for the 3 modes, Git-history scan scope, Pre-commit hook installer, Commit provenance in output

---

## CLI Surface for the 3 Modes

### How git-history and staged scanning attach to the CLI

| Option | Description | Selected |
|--------|-------------|----------|
| Flags on `mimir scan` | `mimir scan --git` / `--staged`; reuses ALL existing scan flags; mode flag picks the Source, default stays working-tree | ✓ |
| Separate subcommands | `mimir git` / `mimir staged`; matches modern gitleaks but duplicates flag wiring | |
| You decide | — | |

**User's choice:** Flags on `mimir scan`
**Notes:** Reuses --baseline/--format/--show-suppressed/config precedence for free; consistent with the single-scanCmd design.

### Pre-commit hook installer command shape (IFACE-03)

| Option | Description | Selected |
|--------|-------------|----------|
| `mimir hook` group | install / uninstall / status; room to grow | ✓ |
| `mimir install-hook` | single dedicated verb; simplest | |
| You decide | — | |

**User's choice:** `mimir hook` group

---

## Git-History Scan Scope

### Default scope for `mimir scan --git`

| Option | Description | Selected |
|--------|-------------|----------|
| Current branch full history | All commits reachable from HEAD; deterministic, fast, catches deleted secret | ✓ |
| All refs/branches | git log --all; broader but slower/noisier | |
| You decide | — | |

**User's choice:** Current branch full history

### Range control in v1 (SUP2-03 is v2)

| Option | Description | Selected |
|--------|-------------|----------|
| None — full history only | No --since/range flags; honors SUP2-03 v2 deferral; clean benchmark workload | ✓ |
| Minimal --log-opts passthrough | Forward raw args to git log as an escape hatch | |
| You decide | — | |

**User's choice:** None — full history only

---

## Pre-commit Hook Installer

### Handling an existing .git/hooks/pre-commit

| Option | Description | Selected |
|--------|-------------|----------|
| Refuse, require --force | Managed standalone hook; never silently clobber; resolve dir via git rev-parse --git-dir | (Claude's pick) |
| Append guarded block | Insert delimited mimir block into existing hook | |
| You decide | — | ✓ |

### Honest bypass (criterion 4)

| Option | Description | Selected |
|--------|-------------|----------|
| --no-verify + git config toggle | Document `git commit --no-verify` + `git config hooks.mimir false` | (Claude's pick) |
| --no-verify only | Rely solely on git-native bypass | |
| You decide | — | ✓ |

### pre-commit framework support in v1

| Option | Description | Selected |
|--------|-------------|----------|
| Ship manifest + native installer | Add .pre-commit-hooks.yaml + `mimir hook install` | (Claude's pick) |
| Native installer only | Just `mimir hook install`; framework support additive later | |
| You decide | — | ✓ |

**User's choice:** Delegated all three to Claude (see Claude's Discretion).

---

## Commit Provenance in Output

### How much provenance a history finding carries

| Option | Description | Selected |
|--------|-------------|----------|
| SHA + author + date | omitempty Finding fields; full provenance; non-history output byte-identical | (Claude's pick) |
| Commit SHA only | Smallest schema delta | |
| You decide | — | ✓ |

### Keep the fingerprint commit-independent?

| Option | Description | Selected |
|--------|-------------|----------|
| Yes — keep it content-based | path:rule:hash16, no commit; baseline/dedup work across modes | (Claude's pick) |
| Include commit in fingerprint | Makes occurrences distinct but breaks cross-mode baseline (not recommended) | |
| You decide | — | ✓ |

**User's choice:** Delegated both to Claude (see Claude's Discretion).

---

## Claude's Discretion

- **Hook installer details (D-05/D-06/D-07):** recommended defaults captured —
  managed standalone hook refusing to overwrite without `--force` (dir via
  `git rev-parse --git-dir`); bypass via `git commit --no-verify` + a
  `git config hooks.mimir false` toggle; ship `.pre-commit-hooks.yaml` + native
  installer. Within locked constraints (offline, staged-only, sub-second, respects
  inline-ignore).
- **Commit provenance (D-08/D-09/D-10):** recommended — SHA + author + date as
  omitempty Finding fields; content-based commit-independent fingerprint; human
  output appends short SHA with author/date under --verbose.
- **Flag/command spellings, history streaming & blob-dedup internals,
  `--git`+`--staged` precedence, and criterion-2 benchmark thresholds** — left to
  research/planner within CLAUDE.md's locked backend choice.

## Deferred Ideas

- Commit-range / incremental / `--since` history scanning → v2 (SUP2-03).
- Scanning all refs/branches by default → possible later `--all` opt-in.
- go-git in-process history backend → out-of-scope default; possible later fallback.
- Including commit SHA in the fingerprint → rejected (breaks baseline/dedup).
- Live verification of history findings → Phase 4; never in the hook.
