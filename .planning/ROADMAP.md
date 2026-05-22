# Roadmap: Mimir

## Overview

Mimir's journey is dependency-driven and front-loads trust. Phase 1 ships a complete, usable, trustworthy end-to-end scanner: the redacting data model and stable fingerprint scheme (both foundational so no later phase has to invalidate them), the layered detection engine (keyword pre-filter → regex → entropy → connection-string), a filesystem/config source, the concurrent pipeline, human + JSON output (redacted by default), the `mimir scan` CLI, and the CI exit-code contract. Phase 2 makes the scanner trustworthy on real (dirty) repos by adding first-class false-positive control — inline ignore, `.mimirignore`, default allowlists, and a baseline that leverages the Phase 1 fingerprint. Phase 3 adds full source coverage — git history (streamed, memory-bounded), staged-changes scanning, and the pre-commit hook installer. Phase 4 adds the only network-touching, opt-in layer last: live verification for AWS + GitHub, designed to require zero changes to the engine, filter, or reporters. Each phase is a vertical slice that leaves Mimir more capable and still fully usable.

## Phases

**Phase Numbering:**

- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: Usable End-to-End Scanner** - Redacting data model, fingerprint scheme, layered detection engine, filesystem/config source, concurrent pipeline, human + JSON output, `mimir scan` CLI, CI exit codes
- [ ] **Phase 2: False-Positive Control (Suppression + Baseline)** - Inline ignore, `.mimirignore`, default allowlists, and a stable-fingerprint baseline so Mimir alerts only on NEW findings
- [ ] **Phase 3: Full Source Coverage (Git History + Staged + Pre-commit)** - Memory-bounded git-history scan (incl. deleted secrets), staged-changes scan, and the pre-commit hook installer
- [ ] **Phase 4: Opt-in Live Verification (AWS + GitHub)** - Read-only, cached, rate-limited liveness checks behind `--verify` with three-state classification

## Phase Details

### Phase 1: Usable End-to-End Scanner

**Goal**: A developer can run `mimir scan ./repo`, get accurate, redacted findings (human + JSON) with correct CI exit codes, powered by a layered detection engine over the working tree and config files — the first working, trustworthy milestone.
**Mode:** mvp
**Depends on**: Nothing (first phase)
**Requirements**: DET-01, DET-02, DET-03, DET-04, DET-05, SCAN-01, SCAN-02, SCAN-05, IFACE-01, IFACE-02, OUT-01, OUT-02, OUT-03, SUP-05, CFG-01, CFG-02
**Success Criteria** (what must be TRUE):

  1. User can run `mimir scan ./repo` and see real secrets reported as `file:line`, rule matched, and a redacted snippet, with `.git`, binary, and oversized files skipped
  2. Mimir detects known-pattern secrets (AWS/GitHub/Stripe/private keys), keyword-gated entropy secrets, and connection-string credentials, with the keyword pre-filter limiting which rules run
  3. Every output channel (human, JSON, logs, errors) redacts the secret value by default — a scan of Mimir's own output for known fixture secrets finds none
  4. Mimir returns documented exit codes (0 clean / 1 findings / 2 error, with `--exit-zero` soft mode), and a broken config exits 2 (never 0)
  5. User can add custom TOML rules and enable/disable rules; an RE2-incompatible pattern (lookahead/backreference) is rejected at load with a clear error; every finding carries a stable fingerprint (repo-relative path + rule ID + content hash) present in JSON

**Plans**: 3 plans

Plans:
**Wave 1**

- [ ] 01-01-PLAN.md — Walking Skeleton: scaffold, Finding model (redact+fingerprint), aws-access-token engine, file scanner, human output, exit codes

**Wave 2** *(blocked on Wave 1 completion)*

- [ ] 01-02-PLAN.md — Full detection engine: complete v1 ruleset (15-25 rules), entropy generic detector, connection-string extractor
- [ ] 01-03-PLAN.md — Config + output completion: LoadConfig() with extend/RE2 validation, JSON output with stable schema, all D-14 flags wired, OUT-03 self-scan test

### Phase 2: False-Positive Control (Suppression + Baseline)

**Goal**: A developer can adopt Mimir on a real, dirty repo without drowning in noise — suppressing individual false positives, excluding noisy paths, and baselining existing findings so only NEW secrets alert.
**Mode:** mvp
**Depends on**: Phase 1
**Requirements**: SUP-01, SUP-02, SUP-03, SUP-04
**Success Criteria** (what must be TRUE):

  1. User can suppress a single finding with an inline `// mimir:ignore` comment, and the finding message shows the exact ignore syntax + fingerprint to paste
  2. User can exclude paths/globs via a `.mimirignore` file, and out-of-the-box default allowlists keep lockfiles, `vendor/`, `node_modules/`, `*.min.js` and similar noisy paths quiet on first run
  3. User can generate a baseline and re-scan so only findings NEW relative to the snapshot are reported; the committed baseline contains no raw secret values
  4. A baselined finding stays suppressed after a blank-line insertion above it, a file move, and a Windows↔Linux path difference (fingerprint stability holds)

**Plans**: TBD

Plans:

- [ ] 02-01: TBD
- [ ] 02-02: TBD

### Phase 3: Full Source Coverage (Git History + Staged + Pre-commit)

**Goal**: Mimir scans where secrets actually leak — past commits (including deleted secrets) and the staged diff — and installs as a fast, offline pre-commit hook that blocks commits containing secrets.
**Mode:** mvp
**Depends on**: Phase 2
**Requirements**: SCAN-03, SCAN-04, IFACE-03
**Success Criteria** (what must be TRUE):

  1. User can scan a repo's git history and Mimir finds a secret that was added in a past commit and later deleted
  2. History scanning keeps peak memory bounded and wall time acceptable on a large real repo (diff-streamed, blob-deduped) — verified by a benchmark gate
  3. User can scan only staged changes (`git diff --cached`), and a `mimir`-installed pre-commit hook blocks a commit containing a secret while respecting inline `// mimir:ignore`
  4. The pre-commit hook is staged-only, fully offline, and sub-second on a typical staged diff, with an honest documented bypass

**Plans**: TBD

Plans:

- [ ] 03-01: TBD
- [ ] 03-02: TBD

### Phase 4: Opt-in Live Verification (AWS + GitHub)

**Goal**: A developer can opt in with `--verify` to confirm whether found AWS/GitHub credentials are actually live — turning "is this real?" noise into actionable findings — without risking lockouts, rate-limit bans, or leaked credentials, and with no changes to the detection engine.
**Mode:** mvp
**Depends on**: Phase 3
**Requirements**: VERIFY-01, VERIFY-02, VERIFY-03
**Success Criteria** (what must be TRUE):

  1. User can pass `--verify` (off by default, never run in pre-commit) to live-verify post-suppression findings; without the flag, no network calls are made
  2. Mimir verifies AWS (STS GetCallerIdentity) and GitHub (GET /user) credentials via read-only calls and labels each finding active / inactive / unknown, treating a network failure as unknown (not inactive)
  3. A secret appearing in many findings is verified at most once (per-secret cache), rate-limit backoff is honored, a per-call timeout applies, and the secret value never appears in any log or error

**Plans**: TBD

Plans:

- [ ] 04-01: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Usable End-to-End Scanner | 0/3 | Planned | - |
| 2. False-Positive Control (Suppression + Baseline) | 0/TBD | Not started | - |
| 3. Full Source Coverage (Git History + Staged + Pre-commit) | 0/TBD | Not started | - |
| 4. Opt-in Live Verification (AWS + GitHub) | 0/TBD | Not started | - |
