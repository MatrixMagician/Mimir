# Mimir

## What This Is

Mimir is a fast, Go-based secret scanner that finds leaked credentials — API keys, passwords, tokens, private keys, and connection strings — across a repository's working tree, git history, environment/config files, and staged changes. It runs as a CLI, as a CI/CD gate, and as a pre-commit hook, so teams can catch secrets before they ship and audit repos for secrets already committed. It's built to be both a genuine learning project (idiomatic Go, well-structured) and a tool people can actually rely on.

## Core Value

Accurately catch real leaked secrets — with few enough false positives that developers trust it and keep it in their workflow.

## Requirements

### Validated

<!-- Shipped and confirmed valuable. -->

- [x] Scan working-tree files in a repo/directory for secrets — Validated in Phase 1
- [x] Scan `.env` and config files (yaml/json/etc.) specifically — Validated in Phase 1
- [x] Detect secrets via known-pattern regex signatures (AWS, GitHub, Stripe, private keys, etc.) — Validated in Phase 1
- [x] Detect generic/unknown secrets via entropy analysis — Validated in Phase 1
- [x] Detect database/connection strings (postgres://, mongodb://, etc.) — Validated in Phase 1
- [x] Run as a CLI (`mimir scan ./repo`) with readable, redacted output — Validated in Phase 1
- [x] Run as a CI/CD gate — non-zero exit code when findings exist — Validated in Phase 1
- [x] Emit human-readable output (file:line, rule, redacted snippet) — Validated in Phase 1
- [x] Emit JSON output for automation/tooling — Validated in Phase 1
- [x] Support custom detection rules via a config file (built-in ruleset + user regex) — Validated in Phase 1
- [x] Suppress false positives via inline ignore comments (`// mimir:ignore`) — Validated in Phase 2
- [x] Suppress false positives via an ignore file (`.mimirignore` paths/globs) — Validated in Phase 2
- [x] Suppress via a baseline file — only alert on NEW findings vs a snapshot — Validated in Phase 2
- [x] Scan git history (past commits) for secrets, including deleted ones — Validated in Phase 3
- [x] Scan only staged changes (for the pre-commit use case) — Validated in Phase 3
- [x] Run as a pre-commit hook — block commits containing secrets — Validated in Phase 3
- [x] Live-verify a few key providers in v1 (AWS, GitHub) — confirm a found credential is active — Validated in Phase 4

### Active

<!-- Current scope. Building toward these. -->

<!-- All v1 requirements validated. Next scope is v2 (deferred). -->

### Out of Scope

<!-- Explicit boundaries. Includes reasoning to prevent re-adding. -->

- SARIF output — not selected for v1; revisit if IDE/GitHub code-scanning integration is needed
- Live verification beyond AWS/GitHub — deferred; expand provider coverage after the core is solid
- Automatic remediation / secret rotation — detection is the focus; rotation is a separate concern
- GUI / web dashboard — Mimir is a command-line tool
- Scanning non-git directories' history — history scanning targets git repos

## Context

- **Language:** Go — chosen for fast, concurrent scanning, easy single-binary distribution, and as a learning vehicle.
- **Prior art:** The space has mature tools (gitleaks, trufflehog, detect-secrets). Mimir borrows proven ideas (regex rulesets, entropy heuristics, baseline files) while being a clean, understandable implementation.
- **Distribution:** A single static binary is the ideal — easy to drop into CI images and developer machines.
- **Trust model:** Live verification means secrets-in-flight (network calls to providers). This must be opt-in and handle rate limits and failures gracefully.
- **False positives are the make-or-break factor.** A scanner that cries wolf gets disabled. Suppression mechanisms (inline/ignore-file/baseline) are first-class, not afterthoughts.

## Constraints

- **Tech stack**: Go (single-binary CLI) — chosen for performance, concurrency, and learning value.
- **Performance**: Must scan real-world repos (incl. git history) fast enough to run in CI and as a pre-commit hook without being annoying — implies concurrency.
- **Security**: Findings output must redact secret values by default; live verification must be opt-in and not leak credentials in logs.
- **Usability**: Low false-positive rate is a hard requirement for adoption — suppression must be ergonomic.
- **Distribution**: Prefer zero/standard-library-leaning dependencies where reasonable to keep the binary lean and the codebase legible.

## Key Decisions

<!-- Decisions that constrain future work. Add throughout project lifecycle. -->

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Go as the implementation language | Fast concurrent scanning, single-binary distribution, learning goal | — Pending |
| Three entry points: CLI + CI gate + pre-commit hook | Same engine, different front-ends; meets users where leaks happen | — Pending |
| Detection = regex signatures + entropy + connection-string rules | Layered detection catches both known and generic secrets | — Pending |
| Live verification limited to AWS + GitHub in v1 | Verification is high-value but complex; prove it on two providers first | — Pending |
| Suppression via inline comments + ignore file + baseline | Low false-positive rate drives adoption; all three are standard | — Pending |
| Custom rules via config file (built-in ruleset extensible by users) | Curated defaults that teams can extend without forking | — Pending |
| Output: human-readable + JSON + CI exit codes (SARIF deferred) | Covers interactive use and automation; SARIF added later if needed | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd:complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-05-30 after Phase 4 completion — Opt-in live verification shipped: `--verify` (off by default, never in the pre-commit hook) confirms AWS (STS GetCallerIdentity, static creds, no ambient resolution) and GitHub (GET /user) credentials as active/inactive/unknown, with a per-secret cache, bounded concurrency, Retry-After backoff, 5s timeouts, and sanitized errors that never leak the secret. Detection engine unchanged. 14/14 threats verified closed. This completes ALL v1 requirements (25/25) — the milestone scope is done; remaining work is v2 (deferred).*
