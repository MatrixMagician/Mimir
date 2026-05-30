# Phase 1: Usable End-to-End Scanner - Context

**Gathered:** 2026-05-22
**Status:** Ready for planning

<domain>
## Phase Boundary

A complete, usable, trustworthy end-to-end secret scanner. A developer can run
`mimir scan ./repo` and get accurate, redacted findings (human + JSON) with
correct CI exit codes, powered by the layered detection engine
(keyword pre-filter → regex → entropy → connection-string) over the **working
tree and config files**.

Delivers: redacting data model, stable fingerprint scheme, layered detection
engine, filesystem/config source, concurrent pipeline, human + JSON output, the
`mimir scan` CLI, and the CI exit-code contract.

**Explicitly NOT in this phase** (later phases own these):
- Suppression (inline ignore, `.mimirignore`, default allowlists) and baseline → Phase 2
- Git-history scan, staged-changes scan, pre-commit hook installer → Phase 3
- Live verification (AWS/GitHub network calls) → Phase 4

Requirements in scope: DET-01, DET-02, DET-03, DET-04, DET-05, SCAN-01,
SCAN-02, SCAN-05, IFACE-01, IFACE-02, OUT-01, OUT-02, OUT-03, SUP-05, CFG-01, CFG-02.

</domain>

<decisions>
## Implementation Decisions

### Finding Output (human-readable)
- **D-01:** Use a **compact one-line-per-finding** layout, grep-friendly:
  `path:line:col  rule-id  redacted-snippet`. Not gitleaks-style multi-line
  blocks, not file-grouped.
- **D-02:** Print an **end-of-scan summary line with scan stats** — status plus
  what was scanned (file count + duration), shown on clean scans too
  (e.g. `⚠ 3 secrets in 2 files · scanned 1,204 files · 0.8s` /
  `✓ no secrets found · scanned 1,204 files · 0.8s`). The stats reassure the
  user the scan actually ran.
- **D-03:** Findings + summary go to **stdout** for human mode (the dedicated
  stdout/stderr split option was NOT chosen). JSON output also to stdout.
  Verbose/diagnostic logging goes to stderr.

### Redaction (security boundary — applies to EVERY channel: human, JSON, logs, errors)
- **D-04:** Redaction style is **structural prefix + last-4 peek**
  (e.g. `AKIA****…****MPLE`, `ghp_****…****x9Qz`). Enough to recognize/match a
  known key; the bulk of the secret entropy stays masked.
- **D-05:** **Guardrail:** suppress the last-4 peek for very short secrets where
  revealing 4 chars would leak too much of the value — fall back to fully masked.
  (Threshold is an implementation detail for the planner.)
- **D-06:** There is **NO way to print the full, un-redacted secret value** —
  no `--show-secrets`/`--no-redact` flag exists in v1. The prefix+last-4 peek is
  the only reveal in any channel. Strongest interpretation of the
  "redact by default" constraint.

### Default Ruleset
- **D-07:** Ship a **focused high-signal ruleset (~15-25 rules)**, not a
  comprehensive gitleaks-scale set. Prioritizes low false positives (core value)
  and a legible, auditable rule file. Proposed v1 set: AWS keys, GCP keys,
  GitHub tokens, GitLab tokens, Slack tokens, Stripe keys, PEM private keys,
  JWTs, plus the generic connection-string rule (D-08). Confirmed "as-is."
- **D-08:** Connection-string detection (DET-03) is **one generic URI rule**
  matching any `scheme://user:password@host` shape and isolating/redacting the
  embedded password — covers postgres, mongodb, redis, mysql, amqp, and unknown
  schemes with a single well-tested pattern. **Known gap:** JDBC's
  `jdbc:...?password=` query-string form does NOT fit this shape and is not
  covered in v1 (see Deferred Ideas).
- **D-09:** Users extend the embedded defaults via custom TOML rules (CFG-01),
  following the gitleaks `[extend]` model already locked in CLAUDE.md. Exact
  built-in regex patterns + per-rule entropy/allowlist tuning are for the
  researcher (gitleaks patterns are a proven reference).

### Entropy / Generic Detection
- **D-10:** The generic entropy detector is **ON by default but strictly
  keyword/context-gated** — it only flags a high-entropy string that sits in
  secret-y context (assigned to a var/key named token, secret, api_key,
  password, etc.) AND clears an entropy threshold. (DET-02 intent.) Disable via
  `--no-entropy`. Lean toward a conservative threshold out of the box since
  suppression doesn't arrive until Phase 2.
- **D-11:** **Distinguish heuristic findings from signature matches** in output.
  Generic/entropy findings carry a clearly generic rule ID (e.g.
  `generic-entropy`, `generic-api-key`) plus a subtle marker (`?`) so users
  instantly know which findings are heuristic and lower-confidence
  (e.g. `generic-entropy ?`). NO separate severity/confidence field — that stays
  deferred to v2 (OUT2-03).

### CLI Surface & Defaults
- **D-12:** **Default output is human-readable; `--format json` switches it**
  (with `-f` short form). `--format human|json` is the single extensible format
  flag (future formats like SARIF slot in without new boolean flags). NOT
  TTY-auto-detected (output shape must not change implicitly).
- **D-13:** `mimir scan` **defaults to the current directory** and accepts
  **optional one-or-more path args** (`mimir scan`, `mimir scan ./repo`,
  `mimir scan src/ .env`).
- **D-14:** v1 flag set for `mimir scan`: `--format/-f`, `--config/-c`,
  `--exit-zero`, `--no-color` (+ honor `NO_COLOR` env), `--max-file-size`,
  `--no-entropy`, `--verbose/-v`, `--quiet`. Plus a `mimir version` subcommand.
  Rule **enable/disable lives in the config file** (CFG-02), not dedicated CLI
  flags, for v1.

### Claude's Discretion
- **Finding ordering:** deterministic sort by file path then line/column, for
  reproducible CI logs and to keep Phase 2 baselining stable. (Chosen as a
  sensible default rather than asked.)
- **Coloring/highlighting** detail (which fields are colored), exact entropy
  threshold values, JSON schema field set, config file name/discovery path,
  "what counts as binary," and exit-code edge cases — open to standard
  approaches, constrained by the requirements and CLAUDE.md. Researcher/planner
  decide.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Locked technical stack & architecture (READ FIRST)
- `CLAUDE.md` — Exhaustive, already-locked technology stack and architectural
  decisions: cobra CLI, go-toml/v2 config, `gitleaks/go-gitdiff`, stdlib
  `regexp` (RE2) for matching, Aho-Corasick keyword pre-filter, `x/sync`
  errgroup + semaphore concurrency, `go:embed` for the default ruleset,
  `encoding/json` for JSON output, `fatih/color` for ANSI, testify for tests,
  goreleaser/golangci-lint/`go test -race` for tooling. Also the "What NOT to
  Use" list (no regexp2, no viper, no go-git as default, no secret logging).
  These decisions are NOT to be re-litigated.

### Project scope & requirements
- `.planning/PROJECT.md` — Core value, constraints (redact-by-default,
  low-FP-is-make-or-break, lean binary), Key Decisions table.
- `.planning/REQUIREMENTS.md` — v1 requirement definitions; this phase covers
  DET-01..05, SCAN-01/02/05, IFACE-01/02, OUT-01/02/03, SUP-05, CFG-01/02. See
  the Traceability table.
- `.planning/ROADMAP.md` §"Phase 1" — Goal + 5 success criteria this phase must
  satisfy.

No external ADRs/specs beyond the above — requirements and decisions are fully
captured in this repo's `.planning/` docs and `CLAUDE.md`.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- None — this is a **greenfield** Go project. No `go.mod`, no Go source, no
  `.planning/codebase/` maps exist yet. Phase 1 establishes the module and the
  foundational packages.

### Established Patterns
- None in-repo yet. The intended patterns are prescribed by `CLAUDE.md` (RE2 +
  entropy + allowlists; keyword pre-filter → regex → entropy → connection-string
  layering; bounded-concurrency worker pool; redact at the `Finding` boundary).

### Integration Points
- Foundational, build-for-the-future items that LATER phases depend on and that
  must be designed right in Phase 1:
  - **Redacting `Finding` data model** — redaction happens at the Finding
    boundary so no channel can leak the raw value (D-04..D-06).
  - **Stable fingerprint scheme** (SUP-05): repo-relative path + rule ID +
    content hash. Phase 2's baseline and inline-ignore (and Phase 4) build on
    this. Must survive line shifts, file moves, and cross-platform paths. STATE
    flags fingerprint-scheme design for deeper research at planning time.
  - **`Verifier`-ready architecture** — Phase 4 verification must require zero
    changes to the engine/filter/reporters; keep reporting decoupled.

</code_context>

<specifics>
## Specific Ideas

- Human output should feel **grep-like and dense** (one line per finding) — the
  user explicitly preferred the compact format over verbose blocks.
- The scan-stats summary is a deliberate **trust signal** ("did it actually
  scan everything?"), valued even on a clean run.
- Heuristic findings should be **visibly second-class** (`generic-entropy ?`)
  vs high-confidence signature matches (`aws-access-key-id`).
- Security posture is deliberately strict: **no escape hatch to print raw
  secrets at all** in v1.

</specifics>

<deferred>
## Deferred Ideas

- **JDBC `?password=` connection strings** — the chosen generic URI rule (D-08)
  only matches `scheme://user:pass@host`; JDBC's query-param credential form is
  a known gap. Revisit as an explicit rule if needed (could land in a later
  ruleset expansion).
- **Comprehensive (gitleaks-scale ~100+) ruleset** — considered and rejected for
  v1 in favor of the focused high-signal set; revisit once suppression/baseline
  (Phase 2) make broader rules safe to ship.
- **Severity / confidence field + `--fail-on-severity`** — explicitly v2
  (OUT2-03); v1 only marks generic findings, no severity system.
- **CLI rule-selection flags** (`--enable-rule`/`--disable-rule`) — not in v1;
  enable/disable via config file only. Revisit if config-editing friction shows.
- **Guarded `--show-secrets` debug flag** — considered and rejected for v1
  (strict redaction). Could revisit if a genuine local-debugging need emerges.
- **SARIF / other output formats** — already out of scope (v2, OUT2-01); the
  `--format` flag design (D-12) leaves room for them.

</deferred>

---

*Phase: 1-Usable End-to-End Scanner*
*Context gathered: 2026-05-22*
