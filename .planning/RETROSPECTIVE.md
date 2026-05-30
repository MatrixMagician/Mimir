# Mimir — Living Retrospective

> Cross-milestone learnings. Newest milestone first.

## Milestone: v1.0 — MVP

**Shipped:** 2026-05-30
**Phases:** 4 | **Plans:** 13 | **Tasks:** 19 | **Timeline:** ~58 days (2026-04-02 → 2026-05-30)

### What Was Built
A fast, trustworthy Go secret scanner shipped as a single binary:
- **Phase 1** — Layered detection engine (Aho-Corasick keyword gate → RE2 regex → entropy → allowlist), redact-at-boundary `Finding` model with stable fingerprints, concurrent file scanner, human + JSON output, `mimir scan` cobra CLI, CI exit-code contract (0/1/2), 18-rule embedded TOML ruleset with three-level config precedence.
- **Phase 2** — False-positive control: inline `// mimir:ignore`, `.mimirignore` path globs, default allowlists, and a fingerprint-based baseline (alert only on NEW findings).
- **Phase 3** — Full source coverage: memory-bounded `git log -p` history scan (finds deleted secrets), `git diff --staged` scan, and an offline, managed pre-commit hook installer with an honest bypass.
- **Phase 4** — Opt-in `--verify` live verification for AWS (STS GetCallerIdentity, static creds, ambient-free) and GitHub (GET /user), three-state active/inactive/unknown, per-secret cache, bounded concurrency, Retry-After backoff, sanitized errors, off by default and never in the hook.

### What Worked
- **Trust front-loaded.** The redact-at-boundary invariant and stable fingerprint scheme were set in Phase 1 and never had to be revisited — Phase 2's baseline and Phase 4's side-channel both built cleanly on them.
- **Single-orchestrator architecture.** Every phase converges through `cmd/mimir/scan.go:runScan`; the integration checker confirmed all 6 cross-phase flows wired with no rework.
- **Deep code review caught real bugs.** Phase 4's deep review found 2 genuine blockers (a panic-deadlock in the verify cache, a repo-relative-path resolution bug that silently broke AWS verification off-CWD) that all phase-level tests had missed — fixed before merge.
- **Security gate paid off** on the one network-touching phase: 14/14 threats verified closed by code evidence, confirming no-leak / no-ambient-creds / hook-offline invariants.

### What Was Inefficient
- **Traceability checkbox drift.** Five Phase-1 requirements stayed marked "Pending" in REQUIREMENTS.md despite being verified-satisfied; the milestone audit had to reconcile them. The per-phase `phase.complete` didn't sync those rows at the time.
- **Empty Phase-2 SUMMARY one-liners** — summary-extract returned blank for 02-0x, so milestone accomplishments under-represented the suppression work.

### Patterns Established
- **Off-struct side channel for sensitive transient data**: carrying the raw secret from detection to verification via a `map[fingerprint]secret` that is never a struct field and never serialized — keeps the redact invariant + its reflection guard test green.
- **Additive pointer+omitempty fields** (CommitSHA, Verification) keep the OUT-02 JSON schema byte-identical when absent — the standard way to extend `Finding` without breaking downstream consumers.
- **Ambient-free external clients**: construct SDK clients with static credentials directly (never `LoadDefaultConfig`) + a test asserting ambient env is ignored — prevents false-positive verification against the operator's own creds.

### Key Lessons
- A blocking package-legitimacy checkpoint before `go get` is worth it for a lean security tool — the executor even hardened further by omitting an unused AWS module to keep the forbidden ambient-cred path un-importable.
- Phase-level verification verifies a phase in isolation; the milestone integration check is where cross-mode inconsistencies surface (e.g., WARNING-1: path-glob suppression not extended to `--git`/`--staged`).

### Known Tech Debt Carried Forward
- **WARNING-1**: `.mimirignore`/default-exclude path-glob suppression applies to working-tree scans only, not `--git`/`--staged` (so the pre-commit hook over-reports secrets in vendored/ignored paths). Documented in `milestones/v1.0-MILESTONE-AUDIT.md`. Candidate for a v1.1 cleanup phase.

### Cost Observations
- Model mix: Opus 4.8 (1M context) orchestrator + subagents throughout.
- Worktree-isolated executors, one per single-plan wave; all merges fast-forwarded cleanly.
- Notable: the 1M context window let the planner/verifier load full cross-phase context (CONTEXT/SUMMARY/RESEARCH) without thinning.

## Cross-Milestone Trends

| Metric | v1.0 |
|--------|------|
| Phases | 4 |
| Plans | 13 |
| Requirements satisfied | 21/21 |
| Blockers caught in review | 2 (Phase 4) |
| Tech debt carried forward | 1 |
