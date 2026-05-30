# Phase 1: Usable End-to-End Scanner - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-22
**Phase:** 1-Usable End-to-End Scanner
**Areas discussed:** Finding output & redaction, Default ruleset breadth, Entropy detector posture, CLI defaults & flags

---

## Finding output & redaction

### Q: Human-readable finding layout

| Option | Description | Selected |
|--------|-------------|----------|
| Compact one-line | One finding per line, grep-like (`path:line:col rule snippet`) | ✓ |
| Detailed block | Multi-line block per finding (gitleaks-style) | |
| Grouped by file | File header then indented findings | |

**User's choice:** Compact one-line
**Notes:** Densest, grep/pipe-friendly.

### Q: Redaction style (all channels)

| Option | Description | Selected |
|--------|-------------|----------|
| Structural prefix only | Show only non-secret markers (`AKIA****`), mask all secret chars | |
| Prefix + last-4 peek | Structural prefix + last 4 chars (`AKIA****…****MPLE`) | ✓ |
| Fully opaque | Fixed `<REDACTED>` mask, reveal nothing | |

**User's choice:** Prefix + last-4 peek
**Notes:** Guardrail added by Claude — suppress last-4 peek for very short secrets where it would leak too much.

### Q: End-of-scan summary

| Option | Description | Selected |
|--------|-------------|----------|
| Minimal one-liner | Terse status line only | |
| Summary + scan stats | Status + files scanned + duration, shown on clean scans too | ✓ |
| Stats to stderr, findings to stdout | Stream separation for automation | |

**User's choice:** Summary + scan stats
**Notes:** Stats act as a trust signal that the scan actually ran. Findings + summary to stdout (split option not chosen).

---

## Default ruleset breadth

### Q: Built-in ruleset size

| Option | Description | Selected |
|--------|-------------|----------|
| Focused high-signal (~15-25) | Only distinctive, low-FP providers | ✓ |
| Curated mid-set (~40-60) | Core + common SaaS | |
| Comprehensive (~100+) | gitleaks-scale coverage | |

**User's choice:** Focused high-signal (~15-25)
**Notes:** Prioritizes low FP (core value) and a legible rule file.

### Q: Connection-string detection (DET-03)

| Option | Description | Selected |
|--------|-------------|----------|
| Generic URI rule | One `scheme://user:pass@host` pattern, redact password | ✓ |
| Explicit per-scheme rules | Separate rule per known scheme | |
| Generic + a few explicit | Generic catch-all plus a couple explicit (e.g. JDBC) | |

**User's choice:** Generic URI rule
**Notes:** Known gap — JDBC `?password=` query form not covered (noted as deferred).

### Q: Confirm proposed v1 provider set (AWS, GCP, GitHub, GitLab, Slack, Stripe, PEM keys, JWT + generic URI)

| Option | Description | Selected |
|--------|-------------|----------|
| Looks good as-is | Ship that set; exact patterns left to researcher | ✓ |
| Add a few more providers | Round out with common SaaS | |
| Add generic keyword-assignment rule | Also ship `password=`/`api_key=` catcher | |

**User's choice:** Looks good as-is
**Notes:** Exact regex + per-rule entropy/allowlist tuning deferred to researcher (gitleaks as reference).

---

## Entropy detector posture

### Q: Default posture of the generic entropy detector

| Option | Description | Selected |
|--------|-------------|----------|
| On, keyword-gated | Runs by default, flags only high-entropy strings in secret-y context + threshold | ✓ |
| On, extra-conservative | Same gating, high threshold, err toward silence | |
| Opt-in (--entropy) | Off unless user enables | |

**User's choice:** On, keyword-gated
**Notes:** Matches DET-02 intent; lean conservative on threshold since suppression lands in Phase 2. Disable via `--no-entropy`.

### Q: Distinguish heuristic findings from signature matches?

| Option | Description | Selected |
|--------|-------------|----------|
| Mark generic findings | Generic rule ID + subtle `?` marker (`generic-entropy ?`) | ✓ |
| Uniform treatment | All findings look the same | |
| Confidence field | Explicit high/medium confidence value | |

**User's choice:** Mark generic findings
**Notes:** No separate severity/confidence field — that stays deferred to v2 (OUT2-03).

---

## CLI defaults & flags

### Q: Default output format and selector

| Option | Description | Selected |
|--------|-------------|----------|
| Human default, --format | Human by default; `--format json`/`-f`, extensible | ✓ |
| Human default, --json | Boolean `--json` flag | |
| Auto-detect by TTY | Human on TTY, JSON when piped | |

**User's choice:** Human default, --format
**Notes:** Single extensible format flag; future formats (SARIF) slot in without new flags.

### Q: Scan target

| Option | Description | Selected |
|--------|-------------|----------|
| Default cwd + optional paths | No arg = cwd; optional one-or-more paths | ✓ |
| Require explicit path | Path mandatory | |
| Single path, default cwd | Exactly one optional path | |

**User's choice:** Default cwd + optional paths
**Notes:** Matches gitleaks ergonomics and the "scan here" CI/pre-commit case.

### Q: v1 flag set confirmation

| Option | Description | Selected |
|--------|-------------|----------|
| Looks right | `--format/-f`, `--config/-c`, `--exit-zero`, `--no-color`, `--max-file-size`, `--no-entropy`, `--verbose/-v`, `--quiet` + `mimir version` | ✓ |
| Trim to minimal | `--format`, `--config`, `--exit-zero` only | |
| Add rule-selection flags | Plus `--enable-rule`/`--disable-rule` | |

**User's choice:** Looks right
**Notes:** Rule enable/disable lives in config file (CFG-02), not CLI flags, for v1.

### Q: Allow printing the full un-redacted secret?

| Option | Description | Selected |
|--------|-------------|----------|
| Never (always redacted) | No flag reveals raw secrets, ever | ✓ |
| Guarded opt-out flag | Awkward `--show-secrets` for local debug, refuses on non-TTY | |

**User's choice:** Never (always redacted)
**Notes:** Strongest interpretation of redact-by-default; no `--show-secrets`/`--no-redact` in v1.

---

## Claude's Discretion

- Finding ordering: deterministic sort by file path then line/column (reproducible CI logs, stable Phase 2 baseline).
- Coloring/highlighting detail, exact entropy threshold values, JSON schema fields, config file name/discovery, "what counts as binary," exit-code edge cases — standard approaches, decided by researcher/planner within requirements + CLAUDE.md constraints.

## Deferred Ideas

- JDBC `?password=` connection strings (generic URI rule gap).
- Comprehensive (~100+) ruleset — revisit after Phase 2 suppression.
- Severity / confidence field + `--fail-on-severity` (v2, OUT2-03).
- CLI rule-selection flags (`--enable-rule`/`--disable-rule`).
- Guarded `--show-secrets` debug flag.
- SARIF / other output formats (v2, OUT2-01) — `--format` design leaves room.
