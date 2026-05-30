# Phase 2: False-Positive Control (Suppression + Baseline) - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-28
**Phase:** 2-False-Positive Control (Suppression + Baseline)
**Areas discussed:** Inline ignore syntax, .mimirignore + default allowlists, Baseline format & flow, Suppression transparency

---

## Inline Ignore — Placement

| Option | Description | Selected |
|--------|-------------|----------|
| Same-line trailing only | Suppress only when directive is a trailing comment on the same line as the secret. Matches gitleaks `gitleaks:allow`. | ✓ |
| Same-line OR line-above | Also honor a directive on its own line directly above the finding. | |
| Both + block ranges | Same-line, line-above, and `ignore-start`/`-end` block markers. | |

**User's choice:** Same-line trailing only

## Inline Ignore — Targeting

| Option | Description | Selected |
|--------|-------------|----------|
| Blanket only | `mimir:ignore` suppresses all findings on the line. | |
| Blanket + optional rule ID | `mimir:ignore` (all) OR `mimir:ignore:<rule-id>` to scope to one rule. | ✓ |
| Fingerprint-targeted | `mimir:ignore:<fingerprint>` ties suppression to the exact secret hash. | |

**User's choice:** Blanket + optional rule ID

## Inline Ignore — Recognition

| Option | Description | Selected |
|--------|-------------|----------|
| Substring match anywhere | Any line containing the token triggers suppression, no comment parsing. Matches gitleaks. | ✓ |
| Must follow a comment marker | Only honor after a recognized comment prefix per file type. | |

**User's choice:** Substring match anywhere

## Inline Ignore — Hint format

| Option | Description | Selected |
|--------|-------------|----------|
| Opt-in via --verbose | Default output stays one-line; show paste-ready ignore + fingerprint under --verbose. | ✓ |
| Always, indented sub-line | Print a dim `↳ suppress:` line under every finding. | |
| End-of-scan tip only | One generic summary tip, no per-finding fingerprint. | |

**User's choice:** Opt-in via --verbose

---

## .mimirignore + Defaults — Mechanism

| Option | Description | Selected |
|--------|-------------|----------|
| Skip the file entirely | Excluded paths pruned during the walk; never scanned. Gitignore semantics. | ✓ |
| Scan but suppress findings | Files scanned; matching findings dropped at the Finding boundary. | |
| Split: ignore=skip, defaults=suppress | `.mimirignore` prunes; defaults scan-then-suppress for visibility. | |

**User's choice:** Skip the file entirely

## .mimirignore + Defaults — Discovery

| Option | Description | Selected |
|--------|-------------|----------|
| Repo/scan root only | Single `.mimirignore` per scan root, patterns relative to root. | ✓ |
| Nested per-directory | Honor `.mimirignore` in any subdirectory like git. | |

**User's choice:** Repo/scan root only

## .mimirignore + Defaults — Overrides

| Option | Description | Selected |
|--------|-------------|----------|
| Negation patterns (!) + master toggle | `!pattern` re-includes; config flag disables ALL defaults. | ✓ |
| Master toggle only | All-or-nothing config flag; no per-pattern negation. | |
| No override in v1 | Defaults always on, not overridable. | |

**User's choice:** Negation patterns (!) + master toggle

---

## Baseline — Workflow

| Option | Description | Selected |
|--------|-------------|----------|
| Flags on scan | `--baseline-out` writes, `--baseline` consumes. Mirrors gitleaks. | ✓ |
| Dedicated subcommand | `mimir baseline create` + `--baseline` to consume. | |

**User's choice:** Flags on scan

## Baseline — Entry shape

| Option | Description | Selected |
|--------|-------------|----------|
| Full redacted finding records | Complete Finding JSON per entry; reuses OUT-02 schema; raw-secret-free. | ✓ |
| Fingerprint + minimal metadata | Fingerprint + file + rule_id only. | |
| Bare fingerprint list | Array of fingerprint strings only. | |

**User's choice:** Full redacted finding records

## Baseline — Match key

| Option | Description | Selected |
|--------|-------------|----------|
| Fingerprint membership | Suppress iff full fingerprint (path:rule:hash) in baseline set. | (initial) |
| Content-hash only (ignore path) | Match on rule:hash, ignoring path. Fully move-stable. | |

**User's choice (initial):** Fingerprint membership — **flagged as conflicting with success criterion 4 (file-move stability)**, since the fingerprint includes the file path. Re-decided below.

## Baseline — Move-stability reconciliation (criterion 4 conflict)

| Option | Description | Selected |
|--------|-------------|----------|
| OR-match: fingerprint OR content-hash | Suppress if full fingerprint OR path-independent content key (rule+hash) matches. Moved old secret stays suppressed; new secret in new file still alerts. | ✓ |
| Content-hash key only (drop path) | Match purely on rule+hash, ignoring path. Same secret in a different file never re-alerts. | |
| Keep strict fingerprint; relax criterion 4 | Exact path-inclusive membership; amend ROADMAP to drop the file-move clause. | |

**User's choice:** OR-match: fingerprint OR content-hash
**Notes:** Resolves the conflict between path-inclusive fingerprints and criterion 4's "file move" requirement. Accepted blind spot: the identical secret value copied into a brand-new file stays suppressed (same compromised credential, already baselined). No baseline-schema change needed — the content key (rule-id + hash16) is parseable from the stored fingerprint string.

---

## Suppression Transparency — Counts

| Option | Description | Selected |
|--------|-------------|----------|
| Always show suppressed counts | Extend D-02 summary with a suppression breakdown, even on clean runs. | ✓ |
| Show only if non-zero | Append counts only when something was suppressed. | |
| Verbose only | Show counts only under --verbose. | |

**User's choice:** Always show suppressed counts

## Suppression Transparency — Audit

| Option | Description | Selected |
|--------|-------------|----------|
| --show-suppressed flag | Re-include suppressed findings tagged with reason; JSON gains omitempty suppressed fields. | ✓ |
| Counts only, no per-finding list | Aggregate counts only; no enumeration. | |

**User's choice:** --show-suppressed flag

## Suppression Transparency — Path skips

| Option | Description | Selected |
|--------|-------------|----------|
| Count excluded paths only | Report `N paths excluded`; --verbose lists them; do not scan to enumerate. | ✓ |
| Scan excluded paths under --show-suppressed | Re-scan excluded paths on demand to list path-suppressed findings. | |

**User's choice:** Count excluded paths only

---

## Claude's Discretion

- Suppression-layer precedence / attribution order (default: path-prune → inline-ignore → allowlist → baseline, earliest wins).
- Exact flag and config-key names, default baseline filename, baseline top-level schema, and the exact default-noisy glob set.
- `--show-suppressed` interaction with exit codes (suppressed-but-shown should not flip exit code to 1; confirm against IFACE-02).

## Deferred Ideas

- Honoring `.gitignore` automatically — not adopted in v1.
- Nested per-directory `.mimirignore` — v1 is root-only.
- Inline block-range suppression and line-above placement — v1 is same-line only.
- Fingerprint-targeted inline ignore — overlaps with v2 SUP2-01.
- Interactive baseline audit (review/approve) — v2 SUP2-02.
- Baseline staleness / merge / partial-update tooling — regenerate wholesale in v1.
