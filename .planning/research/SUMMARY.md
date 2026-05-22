# Project Research Summary

**Project:** Mimir
**Domain:** Go secret/credential scanner (CLI + CI gate + pre-commit hook)
**Researched:** 2026-05-22
**Confidence:** HIGH

## Executive Summary

Mimir is a fast, single-binary Go secret scanner that finds leaked credentials across a repo's working tree, git history, config/`.env` files, and staged changes, running as a CLI, a CI gate, and a pre-commit hook. This is a mature, well-trodden domain — gitleaks, trufflehog, detect-secrets, and ggshield have all converged on the same architecture, so the build is largely a matter of executing proven patterns well rather than inventing new ones. The four research streams agree decisively: **Mimir should follow the gitleaks blueprint** (closest analog: fast, single Go binary, regex + entropy, TOML rules, baseline/fingerprints, CI + pre-commit) while borrowing trufflehog's *opt-in verification* idea (scoped to AWS + GitHub in v1) and detect-secrets' *baseline discipline*.

The recommended stack is conservative and lean: **Go 1.26** (pin `go 1.25` floor), **cobra** for the CLI, **go-toml/v2** decoded directly into structs (no viper), the **standard library `regexp` (RE2)** for rules paired with **Shannon entropy + allowlists/stopwords**, **errgroup + a bounded semaphore** for a CPU-bound worker pool, **shell out to `git log -p`** parsed by **gitleaks/go-gitdiff** for history/staged scanning (NOT go-git as the default), **encoding/json** for output, opt-in **aws-sdk-go-v2 (STS)** and **go-github** verifiers, and **goreleaser** for distribution. The architecture is a layered streaming pipeline: pluggable **Sources** emit `Fragment`s -> a stateless **Engine** (keyword prefilter -> regex -> entropy -> connection-string) produces candidate `Finding`s -> a **suppression/filter** layer drops inline-ignored, ignore-file'd, allowlisted, and baselined findings -> an opt-in **Verifier** registry confirms liveness -> **Reporters** serialize survivors and map to exit codes. A dependency-free leaf `finding/` package holds the shared data model to avoid import cycles.

The decisive risks are not technical novelty but two cross-cutting failure modes that kill secret scanners in the field. **First, false-positive fatigue** — a noisy scanner gets disabled (`--no-verify`), at which point real secrets sail through. The mitigation is architectural, not cosmetic: layered detection (keyword-gate -> regex -> entropy -> stopword/denylist), default allowlists for noisy paths (lockfiles, `vendor/`, minified JS, SVGs), per-rule entropy thresholds, and first-class suppression (inline + ignore-file + baseline) shipped *with* detection, not after. **Second, the scanner leaking the secret it found** — into JSON, report files, error messages, debug logs, or reconstructable snippets. The mitigation is a redacting secret wrapper type at the **data model** layer (redacting `String()`/`MarshalJSON`, raw value reachable only via an explicit `.Reveal()` used in exactly one place: the verification call), so every output channel is safe by construction. Two further risks need deliberate design: **fingerprint stability** (baselines silently break if fingerprints include line numbers, commit hashes, or absolute paths — use repo-relative path + rule ID + content hash) and **git-history memory bounds** (scan diffs/patches and stream commits; never load the whole graph or re-scan unchanged blobs).

## Key Findings

### Recommended Stack

Lean, gitleaks-aligned, stdlib-leaning per PROJECT.md's "legible codebase / lean binary" constraint. Versions verified against the Go module proxy and GitHub releases on 2026-05-22. The one load-bearing constraint that shapes the whole engine is **RE2**: Go's `regexp` has no lookahead, lookbehind, or backreferences (deliberate — linear-time, ReDoS-safe), which is *why* entropy + allowlists + post-match Go logic exist. Do **not** reach for `dlclark/regexp2` (backtracking, ReDoS risk on user rules). See STACK.md for full version table and alternatives.

**Core technologies:**
- **Go 1.26 (pin `go 1.25` floor)**: single static binary, native concurrency, fast stdlib `regexp` — and a learning goal per PROJECT.md.
- **cobra v1.10.2**: CLI framework; models the three entry points (CLI / CI gate / pre-commit) as one binary with different flags + exit codes. Matches gitleaks.
- **go-toml/v2 v2.3.1 (direct decode, no viper)**: TOML is the scanner-domain ruleset convention; multiline literal strings make regex rules readable. Embed defaults via `//go:embed`; user config `[extend]`s them.
- **stdlib `regexp` (RE2) + Shannon entropy + allowlists**: linear-time, ReDoS-safe matching; entropy (~3.0-3.5 hex, ~4.0-4.5 base64, per-rule thresholds) and stopwords compensate for the missing lookahead.
- **`git log -p` + gitleaks/go-gitdiff v0.9.1**: shell out to system `git`, parse the patch stream into per-file/per-line added hunks. Far lighter than go-git's in-process history walk. `git` becomes a documented runtime prerequisite for history mode.
- **golang.org/x/sync (errgroup + semaphore) v0.20.0**: idiomatic bounded worker pool (`errgroup.SetLimit(NumCPU)`) with first-error cancellation.
- **aws-sdk-go-v2 (config/sts) + go-github v78** (opt-in verifiers), **doublestar/v4** (`**` globs for `.mimirignore`), **fatih/color** (NO_COLOR-aware output), **encoding/json** (stable typed schema), **goreleaser v2.15.4** + GitHub Actions (cross-platform release; dogfood Mimir on its own repo), **testify** + golden files + `go test -race` (mandatory given concurrency).

### Expected Features

This is a feature-mature space; missing table stakes makes the tool feel untrustworthy. Mimir's PROJECT.md "Active" scope already maps cleanly to v1. See FEATURES.md for the full landscape and prioritization matrix.

**Must have (table stakes):**
- Working-tree / directory scan, git history scan (incl. deleted secrets), staged-changes scan, `.env`/config-file scan — the four scan modes.
- Regex signature rules + curated default ruleset (an empty scanner is useless) and entropy detection (keyword-gated).
- Keyword pre-filter (performance + precision), human-readable + JSON output **redacted by default**, non-zero exit on findings (+ `--exit-zero` soft mode).
- Inline ignore comment (`// mimir:ignore`), `.mimirignore` path/glob file, config discovery + precedence, pre-commit hook integration with a bypass.

**Should have (competitive — these are Mimir's edge):**
- **Baseline file** (alert only on NEW findings) — the single biggest brownfield-adoption unblocker; depends on stable fingerprints.
- **Stable fingerprints** — foundational identity for baseline + ignore-by-fingerprint + dedupe.
- **Connection-string detection** (postgres/mongodb/redis/JDBC) — under-served by regex-only competitors; needs its own parser to isolate the password for entropy/redaction.
- **Opt-in live verification (AWS + GitHub)** with three-state classification (verified / unverified / unknown) — turns "is this real?" noise into actionable P0s.
- **Layered detection pipeline + stopword/denylist** — the FP-reduction strategy *is* an architectural concern, reportedly cutting FPs 60-80% vs single-technique.
- **Concurrency** and **single static binary** distribution (a genuine edge over the Python competitors).

**Defer (v1.x / v2+):**
- v1.x: ignore-by-fingerprint, severity classification + `--fail-on-severity`, incremental/commit-range history scan, interactive baseline audit, more verification providers, CSV/JUnit output.
- v2+: SARIF output (until GitHub code-scanning/IDE integration is real), archive/encoded-content decoding, ML/gibberish FP filter (conflicts with single-binary goal), additional scan sources (Docker/S3), custom report templates.

### Architecture Approach

A layered, streaming pipeline where the CLI is a thin shell. The core decoupling — **pluggable Sources emit a common `Fragment` type, consumed by a stateless Engine** — is what lets one engine serve all four entry points. Concurrency lives in exactly one place (`pipeline/`); the engine does no I/O and no network, making it trivially unit-testable. A dependency-free leaf `finding/` package holds the shared `Finding` + fingerprint + redaction so `engine`, `filter`, and `report` can all depend on it without import cycles. Code lives under `internal/` (single binary, no public API). See ARCHITECTURE.md for the full package layout and code patterns.

**Major components:**
1. **Source layer** (interface, `Fragments(ctx) <-chan Fragment`) — filesystem walk, git working-tree, git history (commit-diff walk), staged diff; each is one impl. `Fragment.Commit` is nil for dir/WT scans, set for history — one model, four sources.
2. **Engine** (stateless `Detect(Fragment) []Finding`) — Aho-Corasick keyword prefilter -> candidate rules' regex -> entropy gate -> connection-string detector. No I/O.
3. **finding/** (leaf, no deps) — `Finding` struct, stable fingerprint, redacting secret type.
4. **Filter/suppression layer** — inline comment, ignore-file (paths/globs), allowlist regex, baseline (`map[fingerprint]struct{}`), dedupe; runs *before* verification.
5. **Verifier registry** (opt-in, `map[ruleID]Verifier`) — AWS STS GetCallerIdentity, GitHub GET /user; low-concurrency pool, per-secret cache, never logs the secret.
6. **Reporters** (interface) — human (file:line, rule, redacted snippet) + JSON (stable schema incl. fingerprint) -> exit-code map (0 clean / 1 found / 2 error).
7. **pipeline/** — the only place goroutines live: source->engine->filter->verify->report wiring via errgroup + bounded worker pool.

### Critical Pitfalls

The PITFALLS.md research is the make-or-break document. Top items, with prevention:

1. **The scanner leaks the secret it found** (worst-case for a security tool) — redact at the **data model**, not the print layer. Use a secret wrapper type with redacting `String()`/`MarshalJSON`/`Format`; expose raw value only via `.Reveal()` used in exactly one place (the verifier). Audit every `fmt.Errorf`/`log` call site; add a regression test that scans Mimir's *own* output/logs for known fixture secrets.
2. **False-positive explosion kills adoption** — layered detection (keyword-gate -> regex -> entropy -> stopword/denylist), default allowlists for noisy paths (`*.lock`, `go.sum`, `vendor/`, `node_modules/`, `*.min.js`, `*.svg`, fixtures), per-rule (not global) entropy thresholds, prefix/structure validation for known providers (AKIA/ghp_), and a precision/recall fixtures corpus enforced in CI.
3. **Baselines silently break when fingerprints are unstable** — fingerprint on repo-relative (forward-slash) path + rule ID + **content hash**, treat line/commit as advisory; never put the raw secret in the fingerprint/baseline; version the scheme; test that blank-line insertion, file moves, and Windows<->Linux paths still suppress.
4. **Git-history scanning blows up memory/time** — scan **diffs/patches** (added lines per commit), stream commits, dedupe identical blobs, cap blob size + decode depth, bound the worker pool. Benchmark peak RSS + wall time on a large real repo as a phase gate.
5. **Live verification triggers lockouts / rate-limit bans / canary alerts** — verify each distinct secret **at most once** (cache by secret hash), honor `Retry-After`/backoff, opt-in only and **never in pre-commit**, read-only calls (STS GetCallerIdentity), TLS to the correct pinned host, treat network failure as `unknown` not `invalid`, and document the canary/honeytoken risk.

(Also load-bearing: **RE2 has no lookahead/backreferences** — ported PCRE rules silently break into false negatives, so validate custom rules at config-load and ship positive+negative fixtures per built-in rule; **slow pre-commit gets bypassed** — staged-only, offline, sub-second; **exit-code semantics** must not conflate "found" with "errored" — a config error must never exit 0.)

## Implications for Roadmap

All four research streams independently converged on the same build order, driven by the dependency graph in ARCHITECTURE.md ("build leaf packages first") and the pitfall sequencing in PITFALLS.md ("redaction and suppression are foundational, verification is last"). The suggested phases below follow that consensus.

### Phase 1: Core Data Model + Ruleset Foundation
**Rationale:** `finding/` and `rules/` are the dependency-free leaves nothing works without; and the **redacting secret type belongs here, before any output or verification code exists** (Pitfall 2 is foundational). Designing the fingerprint scheme now (Pitfall 5) avoids invalidating everyone's baselines later.
**Delivers:** `Finding` struct; redacting secret wrapper type (`String`/`MarshalJSON` redact, `.Reveal()` accessor); stable fingerprint (repo-relative path + rule ID + content hash) with path normalization; `Rule`/`Config` model; embedded default ruleset (`//go:embed`) + user-config merge; custom-rule validation at load (reject RE2-incompatible PCRE syntax with a clear error).
**Addresses:** custom rules via config, config discovery/precedence, the data foundation for redaction + fingerprints.
**Avoids:** secret leakage (data-model redaction), fingerprint instability, RE2 rule breakage.
**Uses:** go-toml/v2, `//go:embed`, stdlib `regexp` (RE2 compile-time validation).

### Phase 2: Detection Engine
**Rationale:** The engine must exist and be correct *serially* before it's parallelized; it's the pure, heavily-unit-tested core. The layered pipeline here *is* the false-positive strategy (Pitfall 1), so context-gating and stopwords are built in from day one, not bolted on.
**Delivers:** stateless `Detect(Fragment) []Finding` — Aho-Corasick keyword prefilter -> regex matchers -> Shannon entropy gate (per-rule thresholds) -> connection-string detector; stopword/denylist filtering; positive+negative fixtures per rule; a precision/recall benchmark corpus run in CI.
**Implements:** the Engine component (no I/O).
**Avoids:** false-positive explosion, RE2 false negatives (fixture harness catches bad ports).
**Uses:** stdlib `regexp` (RE2), Aho-Corasick prefilter, Shannon entropy (~30-line stdlib function), testify + golden files.

### Phase 3: First Usable Filesystem Scanner (end-to-end)
**Rationale:** The **filesystem source alone is enough to validate the whole pipeline** — git sources are additive and must not block the core. This is the first MILESTONE: an end-to-end working scanner.
**Delivers:** `Source` interface + `Fragment`; filesystem walk (skip binaries by content sniff, skip `.git`, max-file-size cap); `pipeline/` worker pool (errgroup + bounded semaphore); human + JSON reporters (redacted by default, stable JSON schema with fingerprint); documented exit-code contract (0/1/2) with regression tests; `mimir scan` cobra command.
**Addresses:** working-tree/directory scan, `.env`/config-file scan, human + JSON output, exit codes + `--exit-zero`.
**Avoids:** exit-code conflation, unbounded goroutine/large-file OOM, redaction gaps in JSON/snippets.
**Uses:** cobra, x/sync errgroup, doublestar (path globs), fatih/color, encoding/json.

### Phase 4: Suppression + Baseline
**Rationale:** False-positive control is the adoption driver per PROJECT.md — it comes **before** verification. The fingerprint from Phase 1 makes baseline cheap ("scan + persist fingerprints").
**Delivers:** inline `// mimir:ignore`, `.mimirignore` path/glob matcher, allowlist regex (incl. curated default noisy-path allowlists), baseline load/`IsNew()`/write; suppression message that prints the exact inline-ignore syntax + fingerprint to paste.
**Addresses:** inline ignore, ignore file, baseline (alert only on NEW), default allowlists.
**Avoids:** false-positive fatigue (suppression ergonomics), unstable baselines (fingerprint-stability tests: line shift, file move, cross-platform paths).

### Phase 5: Git Sources + Staged/Pre-commit
**Rationale:** Additive Sources behind the existing interface; staged-diff scanning is the prerequisite for the pre-commit hook (which is a thin wrapper). History is the highest-value/highest-risk source (deleted secrets vs. memory blowup).
**Delivers:** git working-tree source, **git history source** (`git log -p` streamed + parsed by go-gitdiff, diff/patch units, blob dedupe, bounded memory), staged-diff source (`git diff --cached`); `mimir scan --git` / `--staged` / `baseline` subcommands; pre-commit hook installer (staged-only, offline, sub-second, respects inline-ignore, honest bypass).
**Addresses:** git history scan (incl. deleted), staged-changes scan, pre-commit hook entry point.
**Avoids:** git-history memory/time blowup (diff streaming, RSS benchmark as phase gate), slow-pre-commit bypass (staged-only/offline/sub-second budget).
**Uses:** `git log -p` + gitleaks/go-gitdiff; system `git` (documented prerequisite).

### Phase 6: Opt-in Live Verification (AWS + GitHub)
**Rationale:** Last because it's the only network-touching, opt-in layer — adding it should require **zero** changes to engine/filter/report. Runs *after* suppression (never verify a finding you'll drop). Retrofitting the cache/rate-limit/canary handling is painful, so build them into the first verifier.
**Delivers:** `Verifier` interface + registry keyed by rule ID; AWS (STS GetCallerIdentity, read-only) + GitHub (GET /user) verifiers; three-state classification (active/inactive/unknown); per-secret verification cache; rate-limit backoff + per-call timeout; low-concurrency verification pool; `--verify` flag (off by default, never in pre-commit); canary/honeytoken warning in docs/UX.
**Addresses:** live verification for AWS + GitHub (opt-in), three-state result classification.
**Avoids:** verification lockouts/rate-limit bans/canary alerts (cache, backoff, opt-in gating), secret leakage on the network path (TLS, pinned host, no logging).
**Uses:** aws-sdk-go-v2 (config/sts) or minimal signed net/http; go-github (or bare net/http to api.github.com/user).

### Phase Ordering Rationale

- **Dependency-driven, agreed by all four agents:** data model + ruleset (leaves) -> engine (correct serially) -> first usable filesystem scanner (validates the whole pipeline) -> suppression/baseline -> additional git sources + staged/pre-commit -> opt-in verification last.
- **Redaction and suppression are sequenced as foundations, not afterthoughts:** the redacting secret type is Phase 1 (before any output exists); suppression/baseline precede verification because low-FP is the make-or-break adoption driver.
- **Verification is deliberately last** because it's network-touching, opt-in, and must be additive — the architecture's verifier registry means adding it touches no other layer.
- **The filesystem source intentionally precedes git sources** so a working end-to-end scanner exists early; git history (the riskiest source) is isolated to its own phase with a memory benchmark gate.

### Research Flags

Phases likely needing deeper research during planning (`/gsd:plan-phase --research-phase <N>`):
- **Phase 5 (Git Sources):** The shell-out (`git log -p`) vs. go-git tradeoff is the one MEDIUM-confidence architectural decision. Default is shell-out per all four agents, but validate the perf/UX tradeoff and decide whether/how to keep go-git behind the same Source interface as a no-git-binary fallback. Also validate diff-streaming memory bounds against a large real repo.
- **Phase 1 (Fingerprint scheme design):** Fingerprint stability is a keystone the whole baseline feature rests on, and getting the components right (content-hash vs. line, path normalization, scheme versioning, migration command) warrants focused design before it ships — changing it later invalidates committed baselines.
- **Phase 6 (Verification dependency weight):** Decide aws-sdk-go-v2 (config/credentials/sts submodules) vs. a minimal signed `net/http` call, and go-github vs. bare `net/http` — both affect the "lean binary" constraint. Also research canary-tell detection (Thinkst beacon in STS caller identity).

Phases with standard, well-documented patterns (can skip research-phase):
- **Phase 2 (Detection Engine):** RE2 + Shannon entropy + Aho-Corasick prefilter are thoroughly documented across gitleaks/trufflehog/detect-secrets and validated here.
- **Phase 3 (Filesystem Scanner / pipeline):** Cobra commands + errgroup worker pool + fan-out/fan-in are standard Go; exit-code contract is well-specified in research.
- **Phase 4 (Suppression/Baseline):** Inline-ignore, ignore-file globs, and baseline-as-fingerprint-set are established patterns (gitleaks/detect-secrets) — *given* the Phase 1 fingerprint design lands.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | Versions verified against the Go module proxy + GitHub releases on 2026-05-22; choices cross-validated against gitleaks v8.30.1 and trufflehog `go.mod`. |
| Features | HIGH | Corroborated across gitleaks, trufflehog, detect-secrets, ggshield official docs/repos; PROJECT.md scope maps cleanly to the v1 table. |
| Architecture | HIGH | Layered Source->Engine->Filter->Verify->Report pipeline validated against gitleaks/trufflehog/detect-secrets source; concurrency patterns are standard Go. |
| Pitfalls | HIGH | Drawn from gitleaks/trufflehog/detect-secrets issue trackers, official docs, and direct prior-art behavior; MEDIUM only where based on community-blog synthesis. |

**Overall confidence:** HIGH

This is a mature domain with a clear reference implementation (gitleaks) and four converging research streams. The primary uncertainty is execution quality on the two make-or-break risks (false positives, secret leakage), not on what to build or which tools to use.

### Gaps to Address

- **Git history backend (shell-out vs. go-git):** MEDIUM confidence — the only architectural fork. Default to `git log -p` + go-gitdiff; validate memory/perf on a large real repo during Phase 5 and decide whether go-git is worth keeping as a no-git-binary fallback behind the Source interface.
- **Fingerprint scheme specifics:** the *direction* (content-hash, path-normalized, line-as-advisory) is HIGH-confidence, but the exact composition, scheme versioning, and migration UX need design in Phase 1 before baselines ship.
- **Verification dependency weight + canary detection:** decide SDK vs. minimal `net/http` per provider against the lean-binary constraint; research Thinkst canary-tell detection in Phase 6.
- **Default ruleset precision tuning:** the curated default rules and per-rule entropy thresholds will need iteration against a real fixtures corpus — treat the precision/recall benchmark as an ongoing CI gate, not a one-time deliverable.
- **Cross-platform / encoding edge cases:** binary detection, max-file-size, UTF-16 (BE/LE + BOM), and bounded decode depth cut across the file-reading layer (Phases 3 and 5) — verify explicitly rather than assuming text.

## Sources

### Primary (HIGH confidence)
- Go module proxy (`proxy.golang.org`) — exact versions verified 2026-05-22 for all dependencies (cobra v1.10.2, go-toml/v2 v2.3.1, go-gitdiff v0.9.1, x/sync v0.20.0, etc.).
- GitHub Releases API — goreleaser v2.15.4, gitleaks v8.30.1 (latest as of 2026-05-22).
- gitleaks repo, `go.mod`, README, "How Gitleaks Works" deep dive, DeepWiki — the closest analog: detect engine, Aho-Corasick prefilter, fingerprint format, allowlists/baselines, config system, RE2 "no lookahead" note, Shannon entropy thresholds, `git log -p` patch scanning. (https://github.com/gitleaks/gitleaks)
- trufflehog repo, `go.mod`, DeepWiki, docs — verification (Active/Inactive/Unknown), verification caching, canary detection, worker-pool multipliers, exit semantics. (https://github.com/trufflesecurity/trufflehog)
- detect-secrets repo + design doc — plugin architecture, baseline-of-hashes, inline `pragma: allowlist secret`. (https://github.com/Yelp/detect-secrets)
- ggshield repo + docs — pre-commit/CI ergonomics, `--exit-zero`, `--ignore-known-secrets`. (https://github.com/gitguardian/ggshield)
- Go concurrency patterns (errgroup.WithContext, worker-pool fan-out/fan-in) — standard Go.
- Context7 `/go-git/go-git` — Log/commit-iteration API + in-memory storage model (used to assess history-walk cost).
- Gitleaks issue tracker (primary pitfall evidence): #2019 (OOM ~24GB / decode depth), #1830 + #97 + #575 (entropy/FP), #1284 + #1565 (fingerprint portability), #478 + #1464 (exit-code semantics).
- go-git issues #447 (~8x memory) + #1087 (`log --all` flattening) — history-backend memory tradeoff.
- TruffleHog docs/blogs — verification caching, AWS canary tells, encoded/archived data handling.
- Checkmarx Go-SCP — RE2 limitations + untrusted-input safety. dlclark/regexp2 docs — backtracking engine caveat.

### Secondary (MEDIUM confidence)
- WebSearch corroboration (rafter.so, jit.io, lookingatcomputer.substack.com, blog.miloslavhomer.cz, securityboulevard, douglasmun/org-secret-scan) — Shannon entropy thresholds (~3.0-4.5 hex/base64), layered detection patterns, 60-80% FP reduction from multi-layer validation.
- betterleaks — Aho-Corasick + RE2 + default parallelization confirming the prefilter pattern.
- Connection-string detection patterns (GitGuardian MongoDB detector, advanced-security custom patterns).
- Pre-commit performance guidance (>10s hated / 30-60s bypassed), GitLab #341639 (binary/large-file timeout), DevSecOps regression-testing for rule drift.

### Tertiary (LOW confidence)
- (None — every claim used in this summary is corroborated by at least one HIGH-confidence primary source plus prior-art behavior.)

---
*Research completed: 2026-05-22*
*Ready for roadmap: yes*
