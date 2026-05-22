# Feature Research

**Domain:** Secret / credential scanner (CLI + CI gate + pre-commit hook)
**Researched:** 2026-05-22
**Confidence:** HIGH (corroborated across gitleaks, trufflehog, detect-secrets, ggshield official docs/repos)

## Feature Landscape

The four reference tools occupy distinct niches, which sets the bar for each feature:

- **gitleaks** (Go, ~21k stars) — the closest analog to Mimir. Fast, single-binary, regex+entropy, TOML rules, allowlists, baseline, fingerprints, multiple report formats, declared "feature complete." This is the bar for CLI/CI ergonomics and config.
- **trufflehog** (Go) — verification leader: 700+ verified detectors that actively call provider APIs. Three-state results (verified/unverified/unknown). Huge source coverage.
- **detect-secrets** (Python, Yelp) — baseline + interactive audit workflow leader; plugin architecture; inline pragma allowlisting. Sets the bar for false-positive management.
- **ggshield** (Python, GitGuardian) — backend-dependent (cloud), strong pre-commit/CI ergonomics, "ignore last-found" UX.

### Table Stakes (Users Expect These)

Missing any of these and the tool feels incomplete or untrustworthy. All four reference tools have most of these.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Working-tree / directory scan | Core use case; "scan this folder" | LOW | gitleaks `dir`/`files` mode. Walk filesystem, skip binaries by default. |
| Git history scan (incl. deleted secrets) | The reason secret scanners exist — secrets live forever in history | HIGH | gitleaks uses `git log -p`; must scan every blob across all commits. Deleted-but-committed secrets are the highest-value find. Big perf/memory concern. |
| Staged-changes scan | Required for the pre-commit use case | MEDIUM | gitleaks `protect --staged`; detect-secrets pipes `git diff --staged`. Must scan only the diff, not whole tree. |
| Regex signature rules (known providers) | Users expect AWS/GitHub/Stripe/private-key detection out of the box | MEDIUM | gitleaks ships ~100+ default rules in TOML. Curated default ruleset is table stakes; an empty scanner is useless. |
| Entropy detection (generic secrets) | Catches random tokens with no known pattern | MEDIUM | Shannon entropy on candidate strings (Base64 ~4.5, Hex ~3.0 thresholds in detect-secrets). High FP risk if used naively — must be gated. |
| Keyword pre-filter | Performance + precision; only run regex near `password`, `secret`, `key`, `token` | LOW-MEDIUM | gitleaks `keywords` per rule are a fast pre-scan before the expensive regex. Also reduces FPs (entropy near a secret-y keyword is more likely real). |
| Human-readable output (file:line, rule, redacted snippet) | Interactive use; devs need to find and fix the leak | LOW | Show file path, line number, rule ID, and a redacted match. Color in TTY. |
| JSON output | Automation, tooling, dashboards | LOW | Stable schema. gitleaks JSON includes fingerprint + entropy + metadata. |
| Secret redaction in output (default) | Don't re-leak the secret into CI logs/terminal scrollback | LOW | gitleaks `--redact` (0-100%). For Mimir this is **default-on** per PROJECT.md security constraint. |
| Non-zero exit code on findings | The entire CI-gate contract | LOW | Exit 1 on findings, 0 on clean. gitleaks default = 1; trufflehog `--fail` = 183. Make configurable via `--exit-code`. |
| `--exit-zero` / soft-fail mode | Report-only / monitoring pipelines that shouldn't block | LOW | ggshield `--exit-zero`. Lets teams adopt gradually before enforcing. |
| Inline ignore comment | Suppress a known false positive at the source | LOW | gitleaks `gitleaks:allow`, detect-secrets `# pragma: allowlist secret`. **Most ergonomic suppression** — must support a `// mimir:ignore` form. |
| Ignore file (path/glob exclusions) | Skip vendored deps, test fixtures, lockfiles, binaries | LOW | gitleaks allowlist `paths`; detect-secrets `--exclude-files`. `.mimirignore` per PROJECT.md. |
| Path / file-type exclusion in config | Same as above but rule-aware | LOW | Glob matching. Often combined with the ignore file. |
| Custom rules via config file | Teams have internal token formats; can't ship for everyone | MEDIUM | gitleaks TOML rules (id, regex, keywords, entropy, secretGroup, path). Built-in ruleset + user-extensible without forking. |
| Config file discovery + precedence | Predictable behavior across CLI/CI/hook | LOW | gitleaks order: `-c` flag → env var → `(target)/.gitleaks.toml` → default. Document clearly. |
| Pre-commit hook integration | One of three named entry points | MEDIUM | Must be installable (`mimir install`-style) and fast on staged diff. Depends on staged-scan + a `SKIP` escape hatch. |
| `.env` / config-file scanning | Explicitly called out in PROJECT.md; `.env` is the #1 leak source | LOW | These are just files, but worth special-casing keyword/format handling for `KEY=value` lines. |

### Differentiators (Competitive Advantage)

Where Mimir competes. Should map to Core Value: *accurately catch real secrets with few false positives*.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| Baseline file (alert only on NEW findings) | Lets teams adopt on a repo that already has legacy secrets without drowning in noise — the single biggest adoption unblocker | MEDIUM | gitleaks `--baseline-path`; detect-secrets `.secrets.baseline` (hashes findings). **Depends on stable fingerprints.** Make-or-break for brownfield adoption. |
| Stable fingerprints | Identity for a finding across scans; powers baseline + ignore-by-fingerprint + dedupe | MEDIUM | gitleaks fingerprint = `commit:file:rule:line`. **Foundational** — baseline and `.gitleaksignore`-style fingerprint ignores both depend on it. Design carefully: line-number-based fingerprints churn on edits. |
| Live verification (AWS, GitHub) opt-in | Eliminates the "is this real?" question — a verified-active AWS key is a P0, an unverified string is noise. trufflehog's killer feature | HIGH | Per-provider API call; **must be opt-in** (network egress + leak risk). Handle rate limits, timeouts, offline gracefully. Classify: verified / unverified / unknown (verification errored). v1 = AWS + GitHub only. |
| Three-state result classification | "Verified active" vs "found, can't confirm" vs "verify failed" guides triage | LOW (given verification) | trufflehog model. Drives severity and CI gating decisions (e.g., fail only on verified). |
| Connection-string detection | postgres/mongodb/redis/JDBC URIs with embedded creds are common and high-value; many regex-only tools under-cover them | MEDIUM | `scheme://user:password@host/db`. PROJECT.md requirement. Distinct rule class with its own parsing (extract the password component for entropy/redaction). |
| Layered detection pipeline (regex → entropy → keyword → context → denylist) | Multi-layer validation reportedly cuts FPs 60-80% vs single-technique | MEDIUM | The ordering and gating *is* the FP-reduction strategy. Entropy gated by keyword proximity; matches filtered by stopword/denylist. This is Mimir's core quality engineering. |
| Stopword / denylist filtering | Drop `EXAMPLE`, `xxxxx`, `your-key-here`, `${VAR}`, placeholder values | LOW | gitleaks `stopwords`; detect-secrets `--exclude-secrets`. Cheap, high-impact FP reduction. |
| Concurrency / parallel scanning | "Fast enough for CI and pre-commit" is a hard PROJECT.md constraint; Go's strength | MEDIUM | Worker pool over files/blobs. gitleaks historically had a concurrency factor. Bounded parallelism + streaming to avoid loading whole repo in memory. |
| Incremental / range-limited history scan | Scanning full history every CI run is slow; scan only new commits | MEDIUM | `--log-opts` style commit-range / `--since` filtering; or scan `BASE..HEAD` in PRs. Pairs with baseline for "new only." |
| Severity classification in findings | Lets CI gate on `--fail-on-severity high` and helps triage | LOW-MEDIUM | gitleaks supports severity + `fail_on_severity`. Assign per-rule severity in the default ruleset. |
| Custom-rule entropy + secretGroup controls | Lets advanced users tune precision of their own rules | MEDIUM | gitleaks `secretGroup` (which capture group is the secret) + per-rule `entropy` threshold + per-rule allowlist. Powerful for internal token formats. |
| Single static binary distribution | Drop into any CI image / dev machine with zero runtime deps; advantage over Python tools (detect-secrets, ggshield) | LOW (Go gives it free) | PROJECT.md distribution goal. A genuine edge over the Python competitors. |

### Anti-Features (Commonly Requested, Often Problematic)

Document these to prevent scope creep. Several are already in PROJECT.md "Out of Scope" — reinforced here with reasoning.

| Feature | Why Requested | Why Problematic | Alternative |
|---------|---------------|-----------------|-------------|
| Automatic remediation / secret rotation | "Just fix it for me" | Rotation is provider-specific, dangerous (can break prod), and a fundamentally different product. Trust/blast-radius nightmare. | Detect + report clearly; link to rotation docs per provider. (PROJECT.md: out of scope.) |
| ML / gibberish model for FP reduction (v1) | Marketing says ML beats regex | Adds model deps/weights (kills single-binary goal), hard to debug, opaque, training-data burden. detect-secrets makes it an optional extra for good reason. | Nail the layered regex→entropy→keyword→stopword pipeline first; ML is a v2 research item. |
| Verifying every provider in v1 | "TruffleHog does 700+" | Each verifier is bespoke API integration + auth quirks + rate limits + maintenance. 700 detectors is years of work and a maintenance treadmill. | AWS + GitHub only in v1 (PROJECT.md). Expand after the verification *framework* is proven. |
| GUI / web dashboard | "Show me a nice report" | Mimir is a CLI tool (PROJECT.md). A dashboard is a server product with auth, storage, hosting — different scope entirely. | JSON output that *other* dashboards (or GitHub code-scanning) can ingest. |
| Cloud backend / accounts (ggshield model) | "Centralized policy + known-secrets DB" | Requires a hosted service, accounts, network dependency. Contradicts single-binary, offline-capable design. | Local-only operation; baseline file is the team-shared state, committed to the repo. |
| Scanning non-git directory *history* | "Scan history of any folder" | History only exists in a VCS; without git there's nothing to walk. | Working-tree scan for non-git dirs; history scan requires git (PROJECT.md). |
| Real-time / event-driven monitoring | "Catch leaks the instant they happen" | That's a daemon/server with webhook plumbing — not a CLI/CI/hook tool. | The three entry points (CI on push/PR, pre-commit on commit) already cover the moments leaks occur. |
| Verification-on-by-default | "Verify everything automatically" | Sends candidate secrets over the network silently; rate-limit/abuse risk; can leak in logs; surprises users. | **Opt-in only** (`--verify`). Loud documentation. (PROJECT.md trust model.) |
| Output that prints full secret values | "I need to see the whole key" | Re-leaks the secret into terminal scrollback, CI logs, artifacts. | Redact by default; require an explicit, scary flag (or never) to unredact. |
| SARIF output (v1) | GitHub code-scanning integration | Real value, but not selected for v1; adds a format + schema-conformance burden. Defer until IDE/code-scanning integration is actually needed. | JSON now; SARIF in v1.x when GitHub integration is prioritized (PROJECT.md). |

## Feature Dependencies

```
Git history scan ──requires──> Git blob/commit walking
Staged-changes scan ──requires──> Git diff parsing
        └──requires──> Pre-commit hook (the hook scans the staged diff)

Stable fingerprints ──required by──> Baseline file (alert only on NEW)
        └──required by──> Ignore-by-fingerprint (mature suppression)
        └──enhances────> JSON/report dedupe & cross-scan tracking

Regex rules ──┐
Entropy      ──┼──compose into──> Layered detection pipeline
Keyword pre  ──┤                        └──gated by──> Stopword/denylist
Conn-strings ──┘

Live verification ──requires──> Regex/connection-string detection (need a candidate first)
        └──produces──> Three-state classification (verified/unverified/unknown)
                            └──enhances──> Severity & CI fail-on-verified

Custom rules (config) ──extends──> Built-in ruleset
        └──requires──> Config discovery + precedence

Severity classification ──enables──> fail-on-severity CI gating
Concurrency ──enhances──> All scan modes (esp. history)
Incremental/range scan ──enhances──> History scan + pairs with Baseline
```

### Dependency Notes

- **Baseline requires stable fingerprints:** A baseline is "the set of fingerprints to ignore." If fingerprints aren't deterministic across runs, the baseline silently breaks (re-flags known secrets or hides new ones). gitleaks fingerprint = `commit:file:rule:line`; detect-secrets hashes the secret. **Design fingerprints before baseline.** Watch out: line-based fingerprints churn when files are edited above the finding — consider including a content hash component.
- **Pre-commit depends on staged-diff scanning:** The hook is just "scan staged changes + exit non-zero." It cannot reuse the full-tree or history path. Build staged-diff scanning first; the hook is a thin wrapper. Also needs a bypass (`SKIP=mimir` / `--no-verify` equivalent) or developers will rip it out.
- **Live verification depends on a candidate detector:** You can only verify something you've already found. Verification is a *post-detection enrichment stage*, not a detection technique. Sequence: detect → (opt-in) verify → classify → report.
- **Layered pipeline is the FP strategy, not a single feature:** Regex finds candidates; keyword proximity raises confidence; entropy catches generic ones; stopword/denylist removes placeholders. The *composition and ordering* is what delivers the low-FP Core Value. Treat the pipeline as an architectural concern, not a bag of independent flags.
- **Connection-string detection enhances both detection and verification:** It needs its own parser (extract user/password/host) so the password can be entropy-checked and redacted independently, and (later) the connection verified.
- **Incremental scan enhances baseline:** "Scan only `BASE..HEAD`" + "alert only on new fingerprints" together make CI fast *and* quiet — the combination is what makes the tool usable on a large legacy repo.

## MVP Definition

### Launch With (v1)

Matches PROJECT.md "Active" scope. These deliver the Core Value (accurate, low-FP detection across the three entry points).

- [ ] Working-tree / directory scan — core use case
- [ ] Git history scan (incl. deleted secrets) — the differentiating reason scanners exist
- [ ] Staged-changes scan — required for pre-commit
- [ ] `.env` / config-file scanning — top leak source, called out explicitly
- [ ] Regex signature rules + curated default ruleset — useless without defaults
- [ ] Entropy detection (keyword-gated) — generic-secret coverage
- [ ] Keyword pre-filter — performance + precision
- [ ] Connection-string detection — PROJECT.md requirement, under-served by competitors
- [ ] Stopword/denylist filtering — cheap, essential FP reduction
- [ ] Human-readable + JSON output, redacted by default — interactive + automation
- [ ] Non-zero exit code (+ `--exit-zero` soft mode) — CI gate contract
- [ ] CLI + CI gate + pre-commit hook entry points — the three named front-ends
- [ ] Inline ignore comment (`// mimir:ignore`) — most ergonomic suppression
- [ ] `.mimirignore` path/glob file — skip vendored/test/lockfiles
- [ ] Baseline file (alert only on NEW) — brownfield adoption unblocker
- [ ] Stable fingerprints — foundation for baseline + ignores
- [ ] Custom rules via config file (extensible default ruleset) — internal token formats
- [ ] Config discovery + precedence — predictable CLI/CI/hook behavior
- [ ] Live verification for AWS + GitHub (opt-in) — three-state classification

### Add After Validation (v1.x)

Add once the core engine + FP story are proven in real repos.

- [ ] Ignore-by-fingerprint (mature suppression beyond inline/file) — trigger: users want to suppress without editing source
- [ ] Severity classification + `--fail-on-severity` — trigger: teams ask to gate only on high-severity/verified
- [ ] Incremental / commit-range history scan (`--since`, `BASE..HEAD`) — trigger: CI scan times become annoying on large repos
- [ ] Interactive baseline audit (label true/false positive) — trigger: teams managing large baselines (detect-secrets `audit` model)
- [ ] More verification providers (Stripe, Slack, etc.) — trigger: AWS/GitHub framework proven stable under rate limits
- [ ] CSV / JUnit report formats — trigger: specific CI/test-reporting integrations requested

### Future Consideration (v2+)

- [ ] SARIF output — defer until GitHub code-scanning / IDE integration is a real requirement (PROJECT.md)
- [ ] Archive / encoded-content decoding (base64, zip, docx recursion) — defer: complex, trufflehog/gitleaks both gate it behind depth limits
- [ ] ML / gibberish FP filter — defer: conflicts with single-binary goal; only after regex+entropy pipeline maxed out
- [ ] Additional scan sources (Docker images, S3, etc.) — defer: trufflehog's breadth is out of Mimir's CLI/repo scope
- [ ] Custom report templates (Go text/template) — defer: nice-to-have power feature

## Feature Prioritization Matrix

| Feature | User Value | Implementation Cost | Priority |
|---------|------------|---------------------|----------|
| Working-tree scan | HIGH | LOW | P1 |
| Git history scan | HIGH | HIGH | P1 |
| Staged-changes scan | HIGH | MEDIUM | P1 |
| Regex rules + default ruleset | HIGH | MEDIUM | P1 |
| Entropy detection (gated) | HIGH | MEDIUM | P1 |
| Keyword pre-filter | MEDIUM | LOW | P1 |
| Connection-string detection | HIGH | MEDIUM | P1 |
| Stopword/denylist filtering | HIGH | LOW | P1 |
| Human + JSON output, redacted | HIGH | LOW | P1 |
| Exit codes + soft-fail | HIGH | LOW | P1 |
| Pre-commit hook | HIGH | MEDIUM | P1 |
| Inline ignore comment | HIGH | LOW | P1 |
| `.mimirignore` file | HIGH | LOW | P1 |
| Stable fingerprints | HIGH | MEDIUM | P1 |
| Baseline file | HIGH | MEDIUM | P1 |
| Custom rules (config) | HIGH | MEDIUM | P1 |
| Config discovery/precedence | MEDIUM | LOW | P1 |
| Live verification (AWS/GitHub) | HIGH | HIGH | P1 |
| Concurrency | MEDIUM | MEDIUM | P1/P2 |
| Severity classification | MEDIUM | LOW | P2 |
| Ignore-by-fingerprint | MEDIUM | LOW | P2 |
| Incremental/range history scan | MEDIUM | MEDIUM | P2 |
| Baseline audit (interactive) | MEDIUM | MEDIUM | P2 |
| More verification providers | MEDIUM | HIGH | P2 |
| CSV/JUnit output | LOW | LOW | P2 |
| SARIF output | MEDIUM | MEDIUM | P3 |
| Archive/encoded decoding | LOW | HIGH | P3 |
| ML / gibberish filter | LOW | HIGH | P3 |

**Priority key:**
- P1: Must have for launch
- P2: Should have, add when possible
- P3: Nice to have, future consideration

## Competitor Feature Analysis

| Feature | gitleaks | trufflehog | detect-secrets | ggshield | Mimir approach |
|---------|----------|------------|----------------|----------|----------------|
| Scan modes | git / dir / stdin | git/github/fs/docker/s3/stdin | scan (fs) + hook | path / pre-commit / CI | working-tree / history / staged / .env (focused, repo-centric) |
| Detection | regex + entropy + keywords | 700+ verified detectors | 27+ plugins (regex/entropy/keyword) | cloud backend (500+) | regex + entropy + keyword + connection-string, layered pipeline |
| Verification | none | yes, 700+ providers | limited (structured) | yes (backend) | opt-in AWS + GitHub in v1, three-state |
| Baseline | `--baseline-path` (JSON) | none | `.secrets.baseline` + audit | known-secrets (cloud) | local baseline file, fingerprint-based |
| Fingerprints | `commit:file:rule:line` | n/a | secret hash | n/a | stable fingerprint (commit:file:rule + content hash) |
| Inline ignore | `gitleaks:allow` | n/a | `# pragma: allowlist secret` | n/a | `// mimir:ignore` |
| Ignore file | allowlist `paths` + `.gitleaksignore` | `--exclude-paths` | `--exclude-files` | `.gitguardian.yml` `paths-ignore` | `.mimirignore` (paths/globs) |
| Custom rules | TOML rules | `--config` regex detectors | `--plugin file://` | cloud rules | config file: built-in + user regex (id/regex/keywords/entropy/secretGroup) |
| Output | json/csv/junit/sarif | json/github-actions/sarif | json baseline | text/json/sarif | human + json (sarif deferred) |
| Redaction | `--redact` (opt-in) | partial | n/a (hashes) | masked | redact by default |
| Exit code | 1 (configurable) | 183 with `--fail` | non-zero on new | configurable, `--exit-zero` | non-zero on findings, `--exit-zero` soft mode |
| Distribution | single Go binary | single Go binary | Python pkg | Python pkg | single Go binary (edge over Python tools) |
| Status | "feature complete" | active | active | active | greenfield |

## Sources

- gitleaks repo & docs — https://github.com/gitleaks/gitleaks (scan modes, TOML rules, allowlists, baseline, fingerprints, `gitleaks:allow`, `.gitleaksignore`, report formats, `--redact`, exit codes, `--log-opts`, decode/archive depth) — HIGH
- gitleaks allowlists & baselines — https://deepwiki.com/gitleaks/gitleaks/4.4-allowlists-and-baselines — HIGH
- gitleaks configuration system — https://deepwiki.com/gitleaks/gitleaks/3.2-configuration-system — HIGH
- gitleaks default config — https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml — HIGH
- trufflehog repo — https://github.com/trufflesecurity/trufflehog (700+ verified detectors, `--results`, `--no-verification`, `--exclude/include-detectors`, `--since-commit`/`--branch`, `--filter-entropy`, custom detectors, exit 183) — HIGH
- trufflehog product page — https://trufflesecurity.com/trufflehog — MEDIUM
- detect-secrets repo — https://github.com/Yelp/detect-secrets (plugins, `.secrets.baseline`, audit, pragma allowlist, `--exclude-files/lines/secrets`, `--word-list`, custom plugins, pre-commit) — HIGH
- detect-secrets design doc — https://github.com/Yelp/detect-secrets/blob/master/docs/design.md — HIGH
- ggshield repo & docs — https://github.com/gitguardian/ggshield , https://docs.gitguardian.com/ggshield-docs/reference/secret/scan/pre-commit (`--banlist-detector`, `--ignore-known-secrets`, `--exclude`, `--exit-zero`, `secret ignore --last-found`) — HIGH
- gitleaks SARIF/report formats — https://deepwiki.com/gitleaks/gitleaks-action/4.2-report-generation , https://github.com/gitleaks/gitleaks/issues/355 — MEDIUM
- Connection-string detection patterns — https://blog.gitguardian.com/mongodb-credentials-detector/ , https://github.com/advanced-security/secret-scanning-custom-patterns , GitHub non-provider patterns changelog — MEDIUM
- FP reduction / entropy techniques — https://securityboulevard.com/2021/02/how-to-reduce-false-positives-while-scanning-for-secrets/ , https://blog.miloslavhomer.cz/secret-detection-shannon-entropy/ , https://github.com/douglasmun/org-secret-scan (multi-layer 60-80% FP reduction) — MEDIUM
- Verification rate-limit / best practices — https://docs.github.com/code-security/secret-scanning/about-secret-scanning , https://www.wiz.io/academy/application-security/secret-scanning — MEDIUM
- gitleaks performance / `--log-opts` / incremental — https://github.com/gitleaks/gitleaks (perf section), search corroboration — MEDIUM

---
*Feature research for: Go-based secret/credential scanner*
*Researched: 2026-05-22*
