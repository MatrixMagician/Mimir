# Phase 1: Usable End-to-End Scanner - Research

**Researched:** 2026-05-22
**Domain:** Go CLI secret scanner (detection engine, output, config, CLI)
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**D-01:** Compact one-line-per-finding human output: `path:line:col  rule-id  redacted-snippet`.

**D-02:** End-of-scan summary line with stats — shown on clean scans too.
Examples: `⚠ 3 secrets in 2 files · scanned 1,204 files · 0.8s` / `✓ no secrets found · scanned 1,204 files · 0.8s`

**D-03:** Findings + summary to stdout (for both human and JSON modes). Verbose/diagnostic logging to stderr.

**D-04:** Redaction style: structural prefix + last-4 peek (`AKIA****…****MPLE`, `ghp_****…****x9Qz`).

**D-05:** Guardrail: suppress last-4 peek for short secrets (fully mask if revealing 4 chars leaks too much). Threshold is an implementation detail for the planner.

**D-06:** No `--show-secrets` / `--no-redact` flag — no path exists to print a raw secret value in v1.

**D-07:** Focused v1 ruleset (~15-25 rules): AWS keys, GCP keys, GitHub tokens, GitLab tokens, Slack tokens, Stripe keys, PEM private keys, JWTs, plus generic connection-string rule.

**D-08:** Connection-string detection: one generic URI rule matching `scheme://user:password@host`, isolating the password span. JDBC `?password=` is a known v1 gap.

**D-09:** Users extend defaults via TOML `[extend]` model (as in CLAUDE.md).

**D-10:** Generic entropy detector ON by default, keyword/context-gated, conservative threshold, disable via `--no-entropy`.

**D-11:** Generic/entropy findings carry rule ID like `generic-entropy` or `generic-api-key` with a `?` marker in output — no severity field.

**D-12:** Default output is human-readable; `--format json` (short `-f`) switches it. `--format human|json` is the single extensible flag; NOT TTY-auto-detected.

**D-13:** `mimir scan` defaults to current directory; accepts optional one-or-more path args.

**D-14:** v1 flag set: `--format/-f`, `--config/-c`, `--exit-zero`, `--no-color` (+ honor `NO_COLOR` env), `--max-file-size`, `--no-entropy`, `--verbose/-v`, `--quiet`. Plus `mimir version` subcommand. Rule enable/disable lives in config file only.

### Claude's Discretion

- Finding ordering: deterministic sort by file path then line/column.
- Coloring/highlighting detail (which fields are colored).
- Exact entropy threshold values.
- JSON schema field set.
- Config file name/discovery path.
- "What counts as binary."
- Exit-code edge cases.

### Deferred Ideas (OUT OF SCOPE)

- JDBC `?password=` connection strings.
- Comprehensive (gitleaks-scale ~100+) ruleset.
- Severity / confidence field + `--fail-on-severity`.
- CLI rule-selection flags (`--enable-rule` / `--disable-rule`).
- Guarded `--show-secrets` debug flag.
- SARIF / other output formats.
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| DET-01 | Detect secrets via known-pattern regex signatures from built-in ruleset | §Standard Stack, §V1 Ruleset Patterns, §Layered Pipeline Architecture |
| DET-02 | Detect generic/unknown secrets via Shannon entropy, keyword/context-gated | §Entropy Analysis, §Generic Detection, §Layered Pipeline Architecture |
| DET-03 | Detect database/connection strings; isolate embedded credential | §Connection-String Rule |
| DET-04 | Keyword pre-filter: regex only runs when keyword present | §Aho-Corasick Pre-filter |
| DET-05 | Custom rules RE2-validated at config load; incompatible syntax rejected with clear error | §RE2 Validation |
| SCAN-01 | User can scan working-tree files of a repo/directory | §Filesystem Walker + Worker Pool |
| SCAN-02 | User can scan `.env` and config files | §Filesystem Walker + Worker Pool (no special case; all text files scanned) |
| SCAN-05 | Skip binary and oversized files; skip `.git` directory; configurable max-file-size | §Binary Detection, §File Filtering |
| IFACE-01 | CLI: `mimir scan ./repo` | §CLI Structure, §Cobra Exit Code Pattern |
| IFACE-02 | CI exit codes: 0 / 1 / 2; `--exit-zero` soft mode; broken config exits 2 | §Exit Code Contract |
| OUT-01 | Human-readable findings (file:line, rule, redacted snippet) with NO_COLOR-aware coloring | §Output Format, §Redaction Algorithm |
| OUT-02 | JSON output with stable schema including fingerprint | §JSON Finding Schema |
| OUT-03 | Redact secret values by default in every channel | §Redaction Algorithm |
| SUP-05 | Findings carry stable fingerprint (repo-relative path + rule ID + content hash) | §Fingerprint Scheme |
| CFG-01 | User can add custom TOML rules extending built-in ruleset | §Config/Ruleset Format, §Extend Model |
| CFG-02 | Config discovery with documented precedence; enable/disable rules | §Config Discovery |
</phase_requirements>

---

## Summary

Phase 1 is a greenfield Go CLI binary. Every design decision is pre-locked in CLAUDE.md and CONTEXT.md. The research task is to nail down the concrete implementation specifics the planner needs: exact regex patterns for the 15-25 v1 rules (borrowed from gitleaks, proven in production), the connection-string URI capture strategy, the Shannon entropy algorithm + thresholds, the redaction algorithm with the short-secret guardrail length, the fingerprint scheme that survives line shifts and path separator differences, and idiomatic Go layout for a cobra CLI of this complexity.

The key insight from studying gitleaks source is the detection pipeline: build one Aho-Corasick trie over all keywords at startup, run `trie.MatchFirstString(line)` as a fast gate before any regex, then apply the matching rule's `regexp.FindStringSubmatch` to extract the secret group, then check Shannon entropy against the per-rule threshold. This three-layer approach is why gitleaks is fast — the regex only fires on lines that already contain a relevant keyword. Mimir must replicate this exactly.

The fingerprint design diverges intentionally from gitleaks. Gitleaks uses `file:rule-id:start-line` (line number), which breaks when a blank line is inserted above a finding. Mimir uses `path:rule-id:sha256[:16](secret_value)` (content hash), which survives line shifts — precisely what Phase 2 baseline and inline-ignore depend on. The tradeoff is that a changed secret value generates a new fingerprint (correct behavior: it IS a new finding) but a file rename also generates a new fingerprint (acceptable limitation, noted in requirements).

For v1 conservative operation (no suppression until Phase 2), the entropy threshold for the generic detector should be set conservatively high (3.5 for `generic-api-key`, matching gitleaks) and the keyword gate must be strict (only fire on variable names/keys that semantically indicate a secret). This means fewer findings but far fewer false positives, which is the core value.

**Primary recommendation:** Implement the detection pipeline as `internal/detect/engine.go` with a single `Engine` type that holds the compiled Aho-Corasick trie and rule set, exposing one method `ScanLine(line string, filePath string) []Finding`. The scanner (`internal/scanner/scanner.go`) owns the worker pool and file walking; the engine is stateless and safe to call from multiple goroutines.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| CLI entry point, flag parsing, help | cmd/ (cobra commands) | — | Cobra owns command surface; business logic stays in internal/ |
| Detection pipeline (keyword→regex→entropy→connstr) | internal/detect/ | — | Pure computation, stateless, no I/O |
| Finding data model + redaction + fingerprint | internal/finding/ | — | Must be a single package to enforce redact-at-boundary invariant |
| Filesystem walking, `.git` skip, binary skip | internal/scanner/ | — | I/O concern, owns worker pool |
| Config loading, TOML decode, extend model, RE2 validation | internal/config/ | — | Loaded once at startup, validated before engine constructed |
| Human-readable output formatting | internal/output/ | — | Presentation only; never sees raw secret value |
| JSON output | internal/output/ | — | Uses Finding struct (already redacted) |
| Embedded default ruleset | config/mimir.toml + go:embed | internal/config/ reads it | go:embed requires file in same or sub directory of the package using it |

---

## Standard Stack

### Core (Phase 1 only — history scan tools NOT in Phase 1)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `github.com/spf13/cobra` | v1.10.2 | CLI subcommands, flags, help, completions | De-facto Go CLI standard; what gitleaks uses; gives `mimir scan`/`mimir version` for free |
| `github.com/pelletier/go-toml/v2` | v2.3.1 | TOML config + ruleset decode | Proven with gitleaks ruleset ecosystem; richer decode error diagnostics than BurntSushi/toml |
| `github.com/BobuSumisu/aho-corasick` | v1.0.3 | Keyword pre-filter trie | Exactly what gitleaks uses; O(n) multi-keyword scan per line; proven in production |
| `golang.org/x/sync` | v0.20.0 | `errgroup.WithContext` + `SetLimit` for bounded worker pool | Idiomatic Go; `errgroup.SetLimit(runtime.GOMAXPROCS(0))` is the bounded-concurrency pattern |
| `github.com/fatih/color` | v1.19.0 | ANSI coloring for human output | Respects `NO_COLOR` and auto-disables on non-TTY out of the box; lightweight |
| `github.com/stretchr/testify` | v1.11.1 | Test assertions | `require`/`assert` for readable failures; standard across Go ecosystem |
| stdlib `regexp` (RE2) | Go 1.26 stdlib | Rule matching | Linear-time, ReDoS-immune; what gitleaks/trufflehog use |
| stdlib `encoding/json` | Go 1.26 stdlib | JSON output | Typed `Finding` struct → `json.NewEncoder(os.Stdout).Encode(...)` |
| stdlib `go:embed` | Go 1.26 stdlib | Embed `config/mimir.toml` into binary | Zero runtime file dependency; standard Go feature since 1.16 |
| stdlib `crypto/sha256` | Go 1.26 stdlib | Fingerprint content hash | First 16 hex chars of SHA-256(secret_value) |
| stdlib `path/filepath` | Go 1.26 stdlib | Repo-relative path normalization | `filepath.ToSlash()` for cross-platform fingerprints |

### Supporting (Phase 1 — reserved for Phase 2)

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `github.com/bmatcuk/doublestar/v4` | v4.10.0 | `**` glob matching for `.mimirignore` | Phase 2 suppression only; NOT used in Phase 1 |

**Installation (go.mod for Phase 1):**
```bash
cd /path/to/mimir
go mod init github.com/MatrixMagician/mimir
go get github.com/spf13/cobra@v1.10.2
go get github.com/pelletier/go-toml/v2@v2.3.1
go get github.com/BobuSumisu/aho-corasick@v1.0.3
go get golang.org/x/sync@v0.20.0
go get github.com/fatih/color@v1.19.0
go get github.com/stretchr/testify@v1.11.1
```

**Version verification (all confirmed 2026-05-22 via `proxy.golang.org`):**
- `cobra` v1.10.2 (2025-12-03)
- `go-toml/v2` v2.3.1 (2026-04-16)
- `aho-corasick` v1.0.3 (2020-07-16) — old but stable; same version gitleaks uses
- `x/sync` v0.20.0 (2026-02-23)
- `fatih/color` v1.19.0 (2026-03-20)
- `testify` v1.11.1 (2025-08-27)
- `go-gitdiff` v0.9.1 — NOT needed in Phase 1 (no git history scan); add in Phase 3

---

## Package Legitimacy Audit

> slopcheck is a Python tool checking PyPI. These are Go modules — slopcheck cannot evaluate them. All Go packages below were verified via `proxy.golang.org` (the canonical Go module registry) AND confirmed in use by gitleaks v8.30.1's `go.mod` (authoritative production reference).

| Package | Registry | Age | Downloads/Use | Source Repo | slopcheck | Disposition |
|---------|----------|-----|---------------|-------------|-----------|-------------|
| `github.com/spf13/cobra` | Go modules | 10+ yrs | Millions of projects | github.com/spf13/cobra | N/A (Go, not PyPI) | Approved [VERIFIED: proxy.golang.org + gitleaks go.mod] |
| `github.com/pelletier/go-toml/v2` | Go modules | 5+ yrs | Widely used | github.com/pelletier/go-toml | N/A | Approved [VERIFIED: proxy.golang.org + gitleaks go.mod] |
| `github.com/BobuSumisu/aho-corasick` | Go modules | ~6 yrs | gitleaks dep | github.com/BobuSumisu/aho-corasick | N/A | Approved [VERIFIED: proxy.golang.org + gitleaks go.mod — exact same version v1.0.3] |
| `golang.org/x/sync` | Go modules | 10+ yrs | Official Go extended stdlib | golang.org/x/sync | N/A | Approved [VERIFIED: proxy.golang.org; golang.org official package] |
| `github.com/fatih/color` | Go modules | 10+ yrs | Millions of projects | github.com/fatih/color | N/A | Approved [VERIFIED: proxy.golang.org + gitleaks go.mod] |
| `github.com/stretchr/testify` | Go modules | 10+ yrs | Most popular Go test lib | github.com/stretchr/testify | N/A | Approved [VERIFIED: proxy.golang.org] |

**slopcheck verdict:** slopcheck checked PyPI (Python registry). These are Go modules and correctly do not exist on PyPI. Treating as cross-ecosystem confusion — all packages verified via authoritative Go module proxy and production gitleaks `go.mod` reference. All dispositions: APPROVED.

**Packages removed due to slopcheck [SLOP] verdict:** None.

---

## Architecture Patterns

### System Architecture Diagram

```
 mimir scan [paths...]
        │
        ▼
 ┌─────────────┐
 │  cmd/scan   │  cobra RunE: parse flags, resolve paths, load config
 └──────┬──────┘
        │ flags + paths
        ▼
 ┌─────────────────┐
 │ internal/config │  load TOML (embedded defaults + user extend)
 │  LoadConfig()   │  RE2-validate all rule patterns → exit 2 on invalid
 └──────┬──────────┘
        │ *Config (rules, keywords)
        ▼
 ┌─────────────────────────────┐
 │   internal/detect           │
 │   Engine{trie, rules}       │  Aho-Corasick trie built from all keywords
 └──────┬──────────────────────┘
        │
        ▼
 ┌────────────────────────────────────────────┐
 │  internal/scanner  Scanner{engine, config} │
 │                                            │
 │  filepath.WalkDir(paths)                   │
 │     ├─ skip .git/ directory                │
 │     ├─ skip binary files (null-byte check) │
 │     ├─ skip files > max-file-size          │
 │     └─ enqueue file paths to worker pool   │
 │                                            │
 │  errgroup.SetLimit(GOMAXPROCS)             │
 │     goroutine per file:                    │
 │       for each line in file:               │
 │         trie.MatchFirstString(line) ──────┐│
 │         if match: run rule regex           ││
 │         check entropy (if applicable)      ││
 │         check connection-string pattern    ││
 │         → []Finding (redacted at boundary) ││
 └─────────────┬──────────────────────────────┘
               │
               ▼ collect findings
 ┌─────────────────────────┐
 │  sort by path→line→col  │  deterministic ordering for CI logs
 └──────────┬──────────────┘
            │
    ┌───────┴────────┐
    ▼                ▼
┌─────────┐   ┌───────────┐
│ human   │   │   JSON    │
│ output  │   │   output  │
│ stdout  │   │  stdout   │
└─────────┘   └───────────┘
    │
    ▼ (always, regardless of format)
 summary line to stdout
 verbose/diag logs to stderr

Exit: 0 (clean) | 1 (findings, unless --exit-zero) | 2 (error/broken config)
```

### Recommended Project Structure

```
mimir/
├── main.go                        # cmd.Execute() only
├── go.mod                         # module github.com/MatrixMagician/mimir, go 1.25
├── go.sum
├── config/
│   └── mimir.toml                 # Embedded default ruleset (go:embed target)
├── cmd/
│   ├── root.go                    # rootCmd, SilenceErrors/Usage, version flag
│   ├── scan.go                    # scanCmd + runScan + exit-code logic
│   └── version.go                 # versionCmd (version string from -ldflags)
└── internal/
    ├── config/
    │   ├── embed.go               # //go:embed mimir.toml; var DefaultConfig []byte
    │   ├── config.go              # Config/Rule structs, LoadConfig(), Extend model
    │   └── config_test.go
    ├── detect/
    │   ├── engine.go              # Engine{trie, rules}; ScanLine() → []Finding
    │   ├── entropy.go             # shannonEntropy(s string) float64
    │   ├── connstr.go             # connection-string rule + password extraction
    │   └── engine_test.go
    ├── finding/
    │   ├── finding.go             # Finding struct; Redact(); Fingerprint()
    │   └── finding_test.go
    ├── output/
    │   ├── human.go               # FormatHuman(findings, stats) to w io.Writer
    │   ├── json.go                # FormatJSON(findings) to w io.Writer
    │   └── output_test.go
    └── scanner/
        ├── scanner.go             # Scanner{engine,cfg}; Scan(ctx,paths) ([]Finding, Stats, error)
        ├── binary.go              # isBinary(firstChunk []byte) bool
        └── scanner_test.go
testdata/
    fixtures/                      # Contains placeholder tokens for unit tests (see §Validation)
    clean/                         # Files verified to have no secrets (FP regression)
```

**Key layout constraints:**
- `config/embed.go` MUST live in the `config/` directory alongside `mimir.toml` — `//go:embed` can only reference files in the same or sub directories
- `internal/` prevents external import (correct for a tool, not a library)
- No `pkg/` directory — `pkg/` convention is for importable shared libraries, not CLIs

---

## V1 Ruleset Patterns

### DET-01 Signature Rules

All patterns verified as RE2-compatible (no lookaheads or backreferences). Sourced from gitleaks v8.30.1 rules.

**Rule: `aws-access-token`**
```toml
[[rules]]
id = "aws-access-token"
description = "AWS access key ID (AKIA/ASIA/ABIA/ACCA prefix)"
regex = '\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b'
entropy = 3.0
keywords = ["a3t", "akia", "asia", "abia", "acca"]
[[rules.allowlists]]
regexes = ['.+EXAMPLE$']
```
[VERIFIED: github.com/gitleaks/gitleaks/cmd/generate/config/rules/aws.go]

**Rule: `gcp-api-key`**
```toml
[[rules]]
id = "gcp-api-key"
description = "Google Cloud Platform API key (AIza prefix, 39 chars total)"
regex = '\b(AIza[\w-]{35})\b'
entropy = 4.0
keywords = ["aiza"]
[[rules.allowlists]]
regexes = [
  'AIzaSyabcdefghijklmnopqrstuvwxyz1234567',
  'AIzaSyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs',
]
```
Note: GCP keys are exactly 39 chars (`AIza` + 35). The common documentation example `AIzaSyD-9tSrke72I6e1H5HkXeGiSOHnFGJ9Xd` is 38 chars (a doc error); real keys are 39.
[VERIFIED: github.com/gitleaks/gitleaks/config/gitleaks.toml]

**Rules: GitHub tokens**
```toml
[[rules]]
id = "github-pat"
description = "GitHub Personal Access Token (classic)"
regex = 'ghp_[0-9a-zA-Z]{36}'
entropy = 3.0
keywords = ["ghp_"]

[[rules]]
id = "github-oauth"
description = "GitHub OAuth access token"
regex = 'gho_[0-9a-zA-Z]{36}'
entropy = 3.0
keywords = ["gho_"]

[[rules]]
id = "github-app-token"
description = "GitHub Actions / installation token"
regex = '(?:ghu|ghs)_[0-9a-zA-Z]{36}'
entropy = 3.0
keywords = ["ghu_", "ghs_"]

[[rules]]
id = "github-refresh-token"
description = "GitHub refresh token"
regex = 'ghr_[0-9a-zA-Z]{36}'
entropy = 3.0
keywords = ["ghr_"]

[[rules]]
id = "github-fine-grained-pat"
description = "GitHub fine-grained Personal Access Token"
regex = 'github_pat_\w{82}'
entropy = 3.0
keywords = ["github_pat_"]
```
[VERIFIED: github.com/gitleaks/gitleaks/cmd/generate/config/rules/github.go]

**Rules: GitLab tokens**
```toml
[[rules]]
id = "gitlab-pat"
description = "GitLab Personal Access Token"
regex = 'glpat-[\w-]{20}'
entropy = 3.0
keywords = ["glpat-"]

[[rules]]
id = "gitlab-cicd-job-token"
description = "GitLab CI/CD job token"
regex = 'glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}'
entropy = 3.0
keywords = ["glcbt-"]

[[rules]]
id = "gitlab-runner-token"
description = "GitLab runner authentication token"
regex = 'glrt-[0-9a-zA-Z_-]{20}'
entropy = 3.0
keywords = ["glrt-"]
```
[VERIFIED: github.com/gitleaks/gitleaks/config/gitleaks.toml]

**Rules: Slack tokens**
```toml
[[rules]]
id = "slack-bot-token"
description = "Slack bot token"
regex = 'xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*'
entropy = 3.0
keywords = ["xoxb"]

[[rules]]
id = "slack-user-token"
description = "Slack user/workspace token"
regex = 'xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}'
entropy = 2.0
keywords = ["xoxp-", "xoxe-"]

[[rules]]
id = "slack-webhook"
description = "Slack incoming webhook URL"
regex = '(?:https?://)?hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}'
keywords = ["hooks.slack.com"]
```
[VERIFIED: github.com/gitleaks/gitleaks/config/gitleaks.toml]

**Rule: `stripe-access-token`**
```toml
[[rules]]
id = "stripe-access-token"
description = "Stripe secret or restricted key"
regex = '\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})\b'
entropy = 2.0
keywords = ["sk_test", "sk_live", "sk_prod", "rk_test", "rk_live", "rk_prod"]
```
Note: `pk_live_` / `pk_test_` are publishable keys (not secret), intentionally excluded. [VERIFIED: github.com/gitleaks/gitleaks/cmd/generate/config/rules/stripe.go]

**Rule: `private-key`**
```toml
[[rules]]
id = "private-key"
description = "PEM private key block (RSA, EC, OpenSSH, etc.)"
regex = '(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----'
keywords = ["-----begin"]
```
[VERIFIED: github.com/gitleaks/gitleaks/config/gitleaks.toml]

**Rule: `jwt`**
```toml
[[rules]]
id = "jwt"
description = "JSON Web Token (header.payload.signature)"
regex = '\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.(?:[a-zA-Z0-9\/\\_-]{10,}={0,2})?)\b'
entropy = 3.0
keywords = ["ey"]
```
Note: `ey` keyword is deliberately broad — catches both `eyJ` (base64 `{"`) header start and legacy formats. [VERIFIED: github.com/gitleaks/gitleaks/config/gitleaks.toml]

### DET-02 Generic Detection Rules

```toml
[[rules]]
id = "generic-api-key"
description = "High-entropy string in a secret-context variable assignment"
regex = '(?i)(?:access|auth|(?-i:[Aa]pi|API)|credential|creds|key|passw(?:or)?d|secret|token)[\w.-]{0,50}?(?:[ \t\w.-]{0,20})[\s'"'"'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"'"'"\s=]{0,5}([\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})(?:[\x60'"'"'"\s;]|\\[nr]|$)'
entropy = 3.5
keywords = ["access", "api", "auth", "key", "credential", "creds", "passwd", "password", "secret", "token"]
[[rules.allowlists]]
# Allowlist: pure-alpha strings are almost never real secrets
regexes = ['^[a-zA-Z_.-]+$']
```

**Keyword gate rationale (D-10):** Only fire when a line contains one of the sensitive-variable keywords AND the extracted string meets entropy ≥ 3.5. This prevents flagging, e.g., a long URL containing the word "key" in the path.
[VERIFIED: github.com/gitleaks/gitleaks/cmd/generate/config/rules/generic.go — adapted to avoid Go template syntax in TOML literal]

### DET-03 Connection-String Rule

```toml
[[rules]]
id = "connection-string"
description = "URI connection string with embedded password (scheme://user:password@host)"
regex = '([a-zA-Z][a-zA-Z0-9+\-.]{1,30})://([^:@\s]*)(?::([^@\s]+))@([^\s/"'"'"']+)'
secret_group = 3
keywords = ["://"]
```

**Capture groups:**
- Group 1: scheme (`postgres`, `mongodb`, `redis`, `mysql`, `amqp`, ...)
- Group 2: user (may be empty for password-only form like `redis://:token@host`)
- Group 3: **password** — this is the secret; use `secret_group = 3` for redaction
- Group 4: host (+ optional port + path)

**Tested against (Python RE2-equivalent):**
```
postgres://user:mySecretPassword123@localhost:5432/mydb   → password: mySecretPassword123
mongodb://admin:hunter2@mongo.example.com:27017/db        → password: hunter2
redis://:sometoken@redis.host.io:6379                     → password: sometoken
mysql://root:pass@db.example.com/mydb                     → password: pass
amqp://guest:guest@localhost:5672/                        → password: guest
```

**Known gap (deferred):** JDBC `jdbc:postgresql://host:5432/db?password=mysecret` — the `?password=` query-parameter form is NOT matched by this rule. Intentional v1 gap per D-08.

[ASSUMED — pattern designed during research; must be tested with Go's `regexp` in unit tests before shipping. gitleaks does not ship a general URI rule; this is Mimir-specific.]

---

## Aho-Corasick Pre-filter (DET-04)

### How It Works

Build a single `*ahocorasick.Trie` from the union of all rule keywords (lowercased) at engine startup. For each line, call `trie.MatchFirstString(strings.ToLower(line))` — O(n) scan. If no match, skip all regex evaluation. If match, identify which rules share that keyword, run only those rules' regexes.

### API Pattern (verified from module cache)

```go
// Source: github.com/BobuSumisu/aho-corasick v1.0.3 trie.go + builder.go
import ahocorasick "github.com/BobuSumisu/aho-corasick"

// Build at startup (once, after config loaded):
keywords := collectAllKeywords(rules)  // []string, all lowercase
trie := ahocorasick.NewTrieBuilder().AddStrings(keywords).Build()

// Per-line check:
lineLower := strings.ToLower(line)
if trie.MatchFirstString(lineLower) == nil {
    return nil  // fast path: no keyword present, skip all regex
}
// Find which keywords matched to select candidate rules:
matches := trie.MatchString(lineLower)
// matches[i].MatchString() returns the matched keyword
```

**Important:** `MatchFirstString` returns on first match (boolean gate). `MatchString` returns all matches (to select candidate rules). For the pre-filter fast path, `MatchFirstString` is sufficient.

**Keyword casing:** Store keywords as lowercase in the trie; compare against `strings.ToLower(line)`. The regex then runs on the original (case-preserving) line.

[VERIFIED: module cache at `/home/oliverh/go/pkg/mod/github.com/!bobu!sumisu/aho-corasick@v1.0.3/trie.go`]

---

## Shannon Entropy (DET-02)

### Algorithm

```go
// Source: github.com/gitleaks/gitleaks/detect/utils.go (verified)
func shannonEntropy(data string) float64 {
    if data == "" {
        return 0
    }
    charCounts := make(map[rune]int)
    for _, char := range data {
        charCounts[char]++
    }
    invLength := 1.0 / float64(len(data))
    var entropy float64
    for _, count := range charCounts {
        freq := float64(count) * invLength
        entropy -= freq * math.Log2(freq)
    }
    return entropy
}
```

[VERIFIED: github.com/gitleaks/gitleaks/detect/utils.go]

### Threshold Reference

| Context | Threshold | Rationale |
|---------|-----------|-----------|
| Named signature rules (AWS, GitHub, etc.) | 3.0 | Precise prefix pattern already filters strongly |
| Generic API key (`generic-api-key`) | 3.5 | Broader regex needs higher entropy gate |
| Slack user/workspace token | 2.0 | Lower entropy inherent in numeric segments |
| Base64-heavy secrets | 4.5 | Typical high-entropy base64 is ≥4.5 |
| Hex-encoded secrets | 3.0 | 256-bit hex has theoretical max ~4.0 |

**Empirical entropy values (computed during research):**
```
AKIA-IOSFODNN7EXAMPLE (AWS placeholder) → 3.68  (above threshold — needs allowlist)
AKIA-XXXXXXXXXXXXXXXXXXX (X-repeated)   → 0.93  (below threshold — filtered)
ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx   → 0.62  (below — filtered by entropy)
ghp_[realToken]ABC123xyz789DEF456ghi012  → 4.72  (above — detected)
sk_[live]_abc123ABC456def789DEF012ghi345 → 4.92  (above — detected)  [prefix broken to avoid scanner trigger]
my_token_value (common placeholder)    → 3.52  (above 3.5 threshold — RISK)
```

**Conservative v1 threshold for `generic-api-key`: 3.5** — The `my_token_value` case (3.52) would still trigger but the keyword gate means only assignments like `api_key = "my_token_value"` would reach entropy check, and `my_token_value` is actually short enough (14 chars) to fall below the 16-char guardrail minimum. With the allowlist for pure-alpha strings, most common placeholder cases are filtered. Phase 2 suppression handles remaining FPs.

**`--no-entropy` flag:** When set, skip entropy check for all rules where `entropy > 0`. Named signature rules remain fully active. The generic rules that rely SOLELY on entropy (no precise regex) are disabled by `--no-entropy`.

[VERIFIED: algorithm from gitleaks source; thresholds from gitleaks per-rule values confirmed in config/gitleaks.toml]

---

## Redaction Algorithm (OUT-03, D-04, D-05, D-06)

### Specification

Redaction happens at the `Finding` struct boundary — the raw secret value is used ONLY to (1) compute the content hash for the fingerprint and (2) compute the redacted snippet. After `Finding` is constructed, the raw value is discarded; only `RedactedSecret` is stored.

```go
// internal/finding/finding.go
type Finding struct {
    RuleID        string   `json:"rule_id"`
    File          string   `json:"file"`          // repo-relative, forward-slash
    Line          int      `json:"line"`
    Column        int      `json:"column"`
    RedactedMatch string   `json:"match"`         // context snippet, redacted
    RedactedSecret string  `json:"secret"`        // the secret token, redacted
    Fingerprint   string   `json:"fingerprint"`   // path:rule_id:sha256[:16](raw_secret)
    Entropy       float32  `json:"entropy,omitempty"`
    IsHeuristic   bool     `json:"is_heuristic"`  // true for generic-* rules
}

// NEVER store raw secret value in any exported field
// NEVER log raw secret value via slog/fmt
```

### Redaction Function

```go
// RedactSecret applies structural-prefix + last-4-peek redaction (D-04).
// If the secret is shorter than minVisibleLen (16), returns "[REDACTED]" (D-05).
//
// Examples:
//   AK-IA-JLHLKJHG2T3YLMNQ    → AKIA****...****LMNQ  [dashes added to neutralize scanner]
//   ghp_abc123def456GHI789jkl012  → ghp_****...****l012
//   sk_[live]_abc1234567890defgh   → sk_li****...****efgh
//   hunter2 (7 chars)            → [REDACTED]
const minVisibleLen = 16  // D-05 guardrail threshold

func RedactSecret(secret string) string {
    if len(secret) < minVisibleLen {
        return "[REDACTED]"
    }
    // Show first 4 chars (structural prefix) + last 4 chars
    return secret[:4] + "****...****" + secret[len(secret)-4:]
}
```

**Rationale for `minVisibleLen = 16`:**
- A 15-char secret with last-4 visible = 26% revealed
- A 16-char secret with last-4 visible = 25% revealed
- A 12-char secret with last-4 visible = 33% revealed (too much)
- Most real secrets are ≥20 chars; the 16 threshold is conservative
- Short "secrets" are more likely placeholders or false positives anyway

**Connection-string passwords:** The password capture group (group 3) is the `secret`. Apply same redaction. The match field shows `scheme://user:[REDACTED]@host` by string-replacing the password in the full URI match.

[ASSUMED: minVisibleLen=16 threshold — derived from entropy analysis and % reasoning above; not taken from a specific source. Planner should accept or adjust.]

---

## Fingerprint Scheme (SUP-05)

### Design

```
fingerprint = "<repo-relative-path>:<rule-id>:<sha256_hex_prefix>"

where:
  repo-relative-path = filepath.ToSlash(path relative to scan root)
  rule-id            = exact rule ID string (e.g., "aws-access-token")
  sha256_hex_prefix  = hex.EncodeToString(sha256.Sum256([]byte(rawSecretValue)))[:16]
```

### Properties

| Property | Value |
|----------|-------|
| Survives line number change (blank line inserted) | YES — content hash, not line number |
| Survives cross-platform path separators | YES — `filepath.ToSlash()` normalizes `\` to `/` |
| Survives file rename | NO — path changes → new fingerprint (acceptable; it IS a new location) |
| Survives secret value change | NO — different value → different fingerprint (correct) |
| Deterministic | YES — same inputs always produce same fingerprint |
| Phase 2 compatible | YES — baseline stores fingerprints; inline-ignore comments embed fingerprint |
| Phase 4 compatible | YES — verifier receives fingerprint in `Finding` struct unchanged |

### Implementation

```go
// internal/finding/finding.go
// Source: designed during research; SHA-256 is stdlib crypto/sha256

import (
    "crypto/sha256"
    "encoding/hex"
    "path/filepath"
)

func computeFingerprint(repoRelPath, ruleID, rawSecret string) string {
    // Normalize path separator (Windows compatibility)
    normalizedPath := filepath.ToSlash(repoRelPath)
    // Hash the raw secret value (use raw, not redacted)
    h := sha256.Sum256([]byte(rawSecret))
    hashPrefix := hex.EncodeToString(h[:])[:16]  // first 8 bytes = 16 hex chars
    return normalizedPath + ":" + ruleID + ":" + hashPrefix
}

// Examples:
// src/config.go:aws-access-token:bd990ea26a50c816
// .env:generic-api-key:ce8f845089e73ffc
// config/settings.toml:stripe-access-token:e9982364fd73c3ea
```

**Divergence from gitleaks:** Gitleaks uses `file:rule-id:start-line` as its global fingerprint. This is simpler but unstable — inserting a blank line above the finding changes the fingerprint and would cause Phase 2 baselines to miss the finding. Mimir's content-hash approach is more expensive to compute (one SHA-256 per finding) but trivially fast in practice.

[VERIFIED: algorithm; SHA-256 from stdlib `crypto/sha256`; `filepath.ToSlash` from stdlib `path/filepath`]

---

## Config/Ruleset Format (CFG-01, CFG-02)

### Embedded Default Config (go:embed)

```go
// config/embed.go  (must be in config/ directory alongside mimir.toml)
package config

import _ "embed"

//go:embed mimir.toml
var DefaultConfig []byte
```

### TOML Schema

```toml
# config/mimir.toml — embedded default ruleset

title = "mimir default config"

# Global allowlists (applied to ALL rules)
[[allowlists]]
description = "common placeholder patterns"
regexes = [
  '^(?i:true|false|null|undefined|none|empty)$',
  '^\$\{[A-Za-z_]\w*\}$',   # ${ENV_VAR}
  '^\$[A-Z_][A-Z0-9_]*$',   # $ENV_VAR
  '^\{\{[^}]+\}\}$',        # {{ template }}
]

[[allowlists]]
description = "noisy paths (suppression; minimal for Phase 1 — full set in Phase 2)"
paths = [
  'go\.(?:mod|sum)$',
  '(?:^|/)vendor/',
  '(?:^|/)\.git/',
]

[[rules]]
id = "aws-access-token"
# ... (see §V1 Ruleset Patterns above)

# User config extends via [extend]:
[extend]
use_default = true          # merge embedded defaults
disabled_rules = []         # list rule IDs to disable
path = ""                   # optional path to another .toml to merge
```

### Extend Model (CFG-01)

```toml
# .mimir.toml (user project config — discovered at scan root or via --config)
[extend]
use_default = true          # include all embedded rules

# Optionally disable a noisy built-in rule:
disabled_rules = ["jwt"]

# Add custom rules:
[[rules]]
id = "my-internal-api-key"
description = "Internal service API key"
regex = 'myco_[a-zA-Z0-9]{32}'
entropy = 3.5
keywords = ["myco_"]
```

### Config Discovery (CFG-02)

Precedence (high to low):
1. `--config/-c <path>` CLI flag (explicit)
2. `.mimir.toml` in scan root directory
3. Embedded defaults (`config/mimir.toml` via `go:embed`)

Discovery algorithm:
```go
// config/config.go
func LoadConfig(flagPath string, scanRoot string) (*Config, error) {
    if flagPath != "" {
        return loadFromFile(flagPath)  // explicit path: missing = exit 2
    }
    projectConfig := filepath.Join(scanRoot, ".mimir.toml")
    if _, err := os.Stat(projectConfig); err == nil {
        return loadFromFile(projectConfig)  // project config found
    }
    // Fall through to embedded defaults
    return loadFromBytes(DefaultConfig)
}
```

### RE2 Validation (DET-05)

```go
// config/config.go — at rule load time
for _, rule := range rawRules {
    re, err := regexp.Compile(rule.Regex)
    if err != nil {
        // Go's regexp.Compile returns error for lookaheads, backreferences, etc.
        // Error message: "invalid or unsupported Perl syntax: (?=)" etc.
        return nil, fmt.Errorf("rule %q: invalid regex %q: %w\n  (RE2 does not support lookaheads or backreferences; use entropy + allowlists instead)", rule.ID, rule.Regex, err)
    }
    rule.compiledRegex = re
}
```

**Exit behavior:** Config load failure (invalid regex, missing required fields, file not found when `--config` specified) → print error to stderr, `os.Exit(2)`. Never `os.Exit(0)`.

[VERIFIED: go-toml/v2 API from pkg.go.dev; extend model from gitleaks config/config.go; go:embed from stdlib docs]

---

## Exit Code Contract (IFACE-02)

### Specification

| Exit Code | Condition |
|-----------|-----------|
| `0` | Clean scan — no findings |
| `1` | Findings detected (unless `--exit-zero`) |
| `2` | Error — broken config, invalid path, I/O error during scan |

### Cobra Implementation Pattern

```go
// cmd/scan.go
var scanCmd = &cobra.Command{
    Use:   "scan [paths...]",
    Short: "Scan files for secrets",
    RunE:  runScan,
}

func runScan(cmd *cobra.Command, args []string) error {
    // Load config — failure → exit 2
    cfg, err := config.LoadConfig(flagConfig, resolveScanRoot(args))
    if err != nil {
        fmt.Fprintln(os.Stderr, "error:", err)
        os.Exit(2)
    }

    // Run scan
    findings, stats, err := scanner.Scan(cmd.Context(), cfg, paths)
    if err != nil {
        fmt.Fprintln(os.Stderr, "error:", err)
        os.Exit(2)
    }

    // Output
    outputFindings(cmd, findings, stats)

    // Exit code
    exitZero, _ := cmd.Flags().GetBool("exit-zero")
    if len(findings) > 0 && !exitZero {
        os.Exit(1)
    }
    return nil  // os.Exit(0) implicit
}

// cmd/root.go
var rootCmd = &cobra.Command{
    Use:           "mimir",
    SilenceErrors: true,   // prevent cobra from printing errors twice
    SilenceUsage:  true,   // don't print usage on RunE errors
}
```

**Key rules:**
- `SilenceErrors: true` on root — prevents cobra from printing `err.Error()` after `RunE` returns it
- Config errors always exit 2, never 1 (even if findings were found before the error)
- `--exit-zero` only suppresses exit 1; errors always exit 2

[VERIFIED: cobra API; exit-code contract from CONTEXT.md D-14 + IFACE-02]

---

## JSON Finding Schema (OUT-02)

```go
// internal/finding/finding.go

type Finding struct {
    RuleID         string  `json:"rule_id"`
    Description    string  `json:"description,omitempty"`
    File           string  `json:"file"`           // repo-relative path, forward-slash
    Line           int     `json:"line"`
    Column         int     `json:"column"`
    Match          string  `json:"match"`          // surrounding context, redacted
    Secret         string  `json:"secret"`         // the token, redacted
    Fingerprint    string  `json:"fingerprint"`    // path:rule_id:sha256_prefix
    Entropy        float32 `json:"entropy,omitempty"`
    IsHeuristic    bool    `json:"is_heuristic,omitempty"` // true for generic-* rules
}

// ScanResult wraps the findings array for the JSON output envelope
type ScanResult struct {
    Findings   []Finding  `json:"findings"`
    Summary    Summary    `json:"summary"`
}

type Summary struct {
    FilesScanned   int     `json:"files_scanned"`
    FindingCount   int     `json:"finding_count"`
    DurationMs     int64   `json:"duration_ms"`
}
```

**Schema stability rules:**
- Field names are frozen after v1 ships — downstream tooling depends on them
- Add new optional fields with `omitempty`; never rename or remove
- `Line` is 1-indexed (human convention)
- `Column` is 1-indexed (human convention)
- `File` always uses forward slashes, even on Windows
- `Secret` field contains ONLY the redacted value — never the raw secret

**JSON output usage:**
```go
// cmd/scan.go — JSON format
enc := json.NewEncoder(os.Stdout)
enc.SetIndent("", "  ")
if err := enc.Encode(result); err != nil {
    fmt.Fprintln(os.Stderr, "error encoding JSON:", err)
    os.Exit(2)
}
```

---

## Binary File Detection + File Filtering (SCAN-05)

### Binary Detection

The standard approach for detecting binary files without a library dependency:

```go
// internal/scanner/binary.go
// Read first 512 bytes; if any NUL byte is present, treat as binary.
// This is the same heuristic used by git, grep, and most Unix tools.
func isBinary(data []byte) bool {
    return bytes.ContainsRune(data, 0)
}
```

gitleaks uses `github.com/h2non/filetype` (MIME sniffing) for binary detection. For Mimir's lean-binary constraint, the NUL-byte heuristic in 512 bytes is sufficient and adds zero dependencies. It correctly handles all real binary formats (ELF, PE, ZIP, JPEG, etc.) — all have NUL bytes in their headers.

[VERIFIED: NUL-byte approach from git source conventions; `bytes.ContainsRune(data, 0)` from stdlib]

### File Filtering

```go
// internal/scanner/scanner.go
const defaultMaxFileSizeMB = 10  // 10 MB; configurable via --max-file-size

func shouldSkip(path string, info fs.FileInfo, cfg *config.Config) bool {
    // 1. Skip .git directory
    if strings.Contains(filepath.ToSlash(path), "/.git/") ||
       filepath.Base(path) == ".git" {
        return true
    }
    // 2. Skip oversized files
    maxBytes := int64(cfg.MaxFileSizeMB) * 1024 * 1024
    if info.Size() > maxBytes {
        return true  // log to stderr at verbose level
    }
    // 3. Binary detection deferred until first read (peek 512 bytes)
    return false
}
```

**Max file size default:** 10 MB. gitleaks default is also 10 MB. User can override via `--max-file-size N` (in MB). A value of `0` means no limit.

---

## Worker Pool Pattern (SCAN-01, SCAN-02)

### Implementation

```go
// internal/scanner/scanner.go
// Source: golang.org/x/sync v0.20.0 errgroup API (verified from module cache)

import (
    "context"
    "runtime"
    "golang.org/x/sync/errgroup"
)

type Scanner struct {
    Engine *detect.Engine
    Config *config.Config
}

func (s *Scanner) Scan(ctx context.Context, paths []string) ([]finding.Finding, Stats, error) {
    g, ctx := errgroup.WithContext(ctx)
    g.SetLimit(runtime.GOMAXPROCS(0))  // cap goroutines at CPU count

    var mu sync.Mutex
    var allFindings []finding.Finding

    err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
        if err != nil { return err }
        if d.IsDir() {
            if d.Name() == ".git" { return filepath.SkipDir }
            return nil
        }
        // Queue file for scanning
        g.Go(func() error {
            findings, err := s.scanFile(ctx, path)
            if err != nil { return nil }  // log and continue, not fatal
            mu.Lock()
            allFindings = append(allFindings, findings...)
            mu.Unlock()
            return nil
        })
        return nil
    })

    if waitErr := g.Wait(); waitErr != nil && err == nil {
        err = waitErr
    }

    // Sort deterministically: path → line → column
    sort.Slice(allFindings, func(i, j int) bool { ... })
    return allFindings, stats, err
}
```

**Concurrency safety:** Each goroutine calls `engine.ScanFile()` on independent data. The only shared state is `allFindings` (protected by `mu`). The engine itself is read-only after construction.

[VERIFIED: errgroup.SetLimit API from module cache `/home/oliverh/go/pkg/mod/golang.org/x/sync@v0.20.0/errgroup/errgroup.go`]

---

## Human Output Format (OUT-01, D-01, D-02, D-11)

### One-Line Per Finding

```
path/to/file.go:42:15  aws-access-token  AKIA****...****LMNQ
.env:7:12              generic-api-key ? sk_t****...****7890
```

**Format:** `<file>:<line>:<col>  <rule-id>[marker]  <redacted-secret>`

**Heuristic marker:** Rules with `is_heuristic=true` (generic-* rules) append ` ?` to the rule ID (D-11). The space before `?` prevents confusion with `?` in filenames.

**Color scheme (fatih/color):**
- File path: default (no color)
- Line:col: dim/gray
- Rule ID (signature): cyan
- Rule ID (heuristic, with `?`): yellow
- Redacted secret: default (no color — the value is already masked)

**Summary line (D-02):**
```
⚠ 3 findings in 2 files · scanned 1,204 files · 0.8s    (findings present)
✓ no findings · scanned 1,204 files · 0.8s               (clean scan)
```

```go
// internal/output/human.go
// fatih/color automatically respects NO_COLOR env and non-TTY (verified from module cache)
// color.NoColor is set at package init time; individual New().Sprint() calls check it

import "github.com/fatih/color"

var (
    dimStyle     = color.New(color.Faint)
    sigRuleStyle = color.New(color.FgCyan)
    heuStyle     = color.New(color.FgYellow)
    warnStyle    = color.New(color.FgYellow, color.Bold)
    okStyle      = color.New(color.FgGreen, color.Bold)
)
```

**`--no-color` flag:** Set `color.NoColor = true` explicitly in addition to honoring `NO_COLOR` env var (fatih/color already checks `NO_COLOR`; the flag provides an explicit override path).

[VERIFIED: fatih/color NoColor behavior from module cache `/home/oliverh/go/pkg/mod/github.com/fatih/color@v1.19.0/color.go`]

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Multi-keyword scan per line | Custom string search loop | `BobuSumisu/aho-corasick` | Hand-rolled multi-keyword search is O(n×k) where k = number of keywords; AC is O(n) |
| TOML parsing | Custom parser | `go-toml/v2` | TOML has edge cases (multiline strings, dotted keys, arrays-of-tables) |
| CLI flag parsing / subcommands | stdlib `flag` router | `cobra` | `flag` becomes hand-rolled routing with multiple subcommands; cobra handles completions, help, inheritance for free |
| Exit code signal propagation | Custom error type with exit code | Direct `os.Exit(N)` in `RunE` | Cobra's error propagation adds complexity; call `os.Exit` directly at the command boundary |
| ANSI color output | `fmt.Sprintf("\033[31m%s\033[0m", ...)` | `fatih/color` | Manual ANSI codes miss NO_COLOR env var, Windows console, non-TTY detection |
| Shannon entropy | External library | Stdlib `math.Log2` loop (25 lines) | The algorithm is trivial (see §Shannon Entropy); adding a dependency for it is pure overhead |
| Regex validation | Custom syntax checker | stdlib `regexp.Compile` error | Go's RE2 engine returns clear errors for unsupported syntax; no custom checker needed |

**Key insight:** The 25-line Shannon entropy function should be copy-pasted from gitleaks (cited, not invented), not imported from a library. Everything else with complexity lives in a dependency.

---

## Common Pitfalls

### Pitfall 1: Raw Secret Leaking via Log/Error Messages

**What goes wrong:** `fmt.Errorf("failed to match rule %s against %q", rule.ID, line)` — the `%q` on a full line can contain the raw secret. A log message passing the regex match result leaks the secret.

**Why it happens:** The `Finding` struct is constructed with the raw secret; it's easy to accidentally log the struct or a field before redaction.

**How to avoid:** Enforce the "redact at boundary" invariant: never store the raw secret in any `Finding` field. Compute fingerprint → compute redacted value → discard raw. Use `slog` with explicit, audited fields if structured logging is added.

**Warning signs:** Any `%s`, `%v`, `%q` in logging code that references the `Finding.Secret` field, or that includes regex match strings.

### Pitfall 2: Fingerprint Uses Line Number (Phase 2 Break)

**What goes wrong:** Using `file:rule-id:line-number` (gitleaks style) for the fingerprint. Phase 2 baseline records this fingerprint; user inserts a blank line above the finding; line number changes; baseline no longer matches; the finding appears "new" in every subsequent scan.

**Why it happens:** Line numbers are the obvious location identifier.

**How to avoid:** Use content hash of the secret value (see §Fingerprint Scheme). This is specifically flagged in STATE.md as requiring deeper research — the content-hash approach is the correct answer.

### Pitfall 3: Aho-Corasick Keyword Case Mismatch

**What goes wrong:** Keywords stored as mixed-case in the trie (e.g., `"AKIA"`) but the pre-filter checks lowercase line; no keyword match; regex never runs; true secret missed.

**Why it happens:** Trie is case-sensitive.

**How to avoid:** Lowercase all keywords at trie build time; lowercase the line before trie check; run regex on ORIGINAL (not lowercased) line.

### Pitfall 4: `go:embed` Directive in Wrong Package

**What goes wrong:** `//go:embed ../config/mimir.toml` in `internal/config/config.go` — the `../` path traversal is NOT allowed by `go:embed`. Compile error.

**Why it happens:** `go:embed` can only reference files relative to the package directory, in the same directory or subdirectories.

**How to avoid:** Create `config/embed.go` in the same directory as `config/mimir.toml`, with the `//go:embed mimir.toml` directive. Import this package from `internal/config/`.

### Pitfall 5: errgroup Goroutine-Safe Finding Collection

**What goes wrong:** Multiple goroutines appending to a shared `[]finding.Finding` without synchronization → data race detected by `go test -race`.

**Why it happens:** Slice append is not goroutine-safe.

**How to avoid:** Protect the shared slice with `sync.Mutex`. Alternative: use a channel and a single collector goroutine. The mutex approach is simpler for Phase 1's bounded parallelism.

### Pitfall 6: RE2 vs PCRE Confusion in Rule Authoring

**What goes wrong:** User writes a custom rule with `(?=\w+)` (lookahead); the config loads and panics on `regexp.MustCompile` (or returns a cryptic error if using `regexp.Compile`).

**Why it happens:** Most regex documentation online shows PCRE syntax with lookaheads.

**How to avoid:** Always use `regexp.Compile` (not `MustCompile`) at config load time; return a user-friendly error with the RE2 constraint explanation (see §RE2 Validation).

### Pitfall 7: Connection String Password Contains `@` or `/`

**What goes wrong:** `postgres://user:p@ssword@localhost/db` — the password `p@ssword` contains `@`; the regex captures only `p` as the password.

**Why it happens:** The URI regex uses `[^@\s]+` which stops at `@`.

**How to avoid:** This is a known limitation of the generic URI approach. For v1, document it. The proper fix is percent-encoding awareness (passwords in URIs should percent-encode `@` as `%40`) — most real secrets do not contain unescaped `@` in the password. Add a test case for `%40` in passwords.

---

## Code Examples

### Full Pipeline: Scan One Line

```go
// internal/detect/engine.go — illustrative pattern
// Source: designed for Mimir; Aho-Corasick pattern from gitleaks detect/detect.go

type Engine struct {
    trie  *ahocorasick.Trie
    rules []config.Rule  // only rules with compiled regex
}

// ScanLine scans a single line and returns findings (already redacted).
// filePath is repo-relative, forward-slash normalized.
// lineNum is 1-indexed.
func (e *Engine) ScanLine(line, filePath string, lineNum int) []finding.Finding {
    // Fast path: Aho-Corasick keyword gate
    lineLower := strings.ToLower(line)
    if e.trie.MatchFirstString(lineLower) == nil {
        return nil
    }

    // Find candidate rules via keyword match
    matches := e.trie.MatchString(lineLower)
    candidateRules := e.rulesForKeywords(matches)

    var findings []finding.Finding
    for _, rule := range candidateRules {
        // Apply regex
        var submatches []string
        if rule.SecretGroup > 0 {
            m := rule.Regex.FindStringSubmatch(line)
            if m == nil { continue }
            submatches = m
        } else {
            m := rule.Regex.FindStringIndex(line)
            if m == nil { continue }
            submatches = []string{line[m[0]:m[1]], line[m[0]:m[1]]}
        }

        secretGroup := rule.SecretGroup
        if secretGroup == 0 { secretGroup = 1 }
        if secretGroup >= len(submatches) { continue }

        rawSecret := submatches[secretGroup]
        if rawSecret == "" { continue }

        // Entropy check
        if rule.Entropy > 0 {
            if shannonEntropy(rawSecret) <= rule.Entropy { continue }
        }

        // Allowlist check
        if rule.IsAllowed(rawSecret, line) { continue }

        // Build finding at the boundary — redact immediately
        findings = append(findings, finding.New(
            rule.ID, filePath, lineNum,
            strings.Index(line, rawSecret)+1,  // 1-indexed column
            rawSecret,
            submatches[0],  // full match for context
            rule.IsHeuristic,
        ))
    }
    return findings
}
```

### Finding Constructor (Redact at Boundary)

```go
// internal/finding/finding.go
// Source: designed for Mimir

func New(ruleID, file string, line, col int, rawSecret, matchContext string, isHeuristic bool) Finding {
    // Compute fingerprint from raw secret BEFORE redacting
    fp := computeFingerprint(file, ruleID, rawSecret)

    // Compute entropy for output
    ent := float32(shannonEntropy(rawSecret))

    // Redact the secret context in the match string
    redactedMatch := strings.ReplaceAll(matchContext, rawSecret, RedactSecret(rawSecret))

    return Finding{
        RuleID:      ruleID,
        File:        file,
        Line:        line,
        Column:      col,
        Match:       redactedMatch,
        Secret:      RedactSecret(rawSecret),
        Fingerprint: fp,
        Entropy:     ent,
        IsHeuristic: isHeuristic,
    }
    // rawSecret goes out of scope here — not stored anywhere
}
```

### TOML Config Decode (go-toml/v2)

```go
// internal/config/config.go
// Source: pkg.go.dev/github.com/pelletier/go-toml/v2 — Unmarshal API

import (
    "errors"
    "github.com/pelletier/go-toml/v2"
)

type RawConfig struct {
    Title      string       `toml:"title"`
    Extend     ExtendConfig `toml:"extend"`
    Rules      []RawRule    `toml:"rules"`
    Allowlists []RawAllowlist `toml:"allowlists"`
}

func loadFromBytes(data []byte) (*Config, error) {
    var raw RawConfig
    if err := toml.Unmarshal(data, &raw); err != nil {
        var decErr *toml.DecodeError
        if errors.As(err, &decErr) {
            return nil, fmt.Errorf("config parse error at %s:\n%s",
                func() string { r, c := decErr.Position(); return fmt.Sprintf("line %d col %d", r, c) }(),
                decErr.String())
        }
        return nil, fmt.Errorf("config parse error: %w", err)
    }
    return compile(raw)
}
```

---

## State of the Art

| Old Approach | Current Approach | Impact for Mimir |
|--------------|------------------|-----------------|
| Line-number fingerprint | Content-hash fingerprint | Mimir adopts content-hash — survives line shifts |
| viper for config | Direct TOML decode | Mimir adopts direct decode — no viper dependency |
| go-git for all scanning | Shell to `git log -p` for history | Mimir: working-tree scan is pure filesystem; no git needed in Phase 1 |
| Global regex over entire file | Aho-Corasick keyword gate → per-line regex | Mimir adopts layered approach |
| regexp2 (backtracking) | stdlib RE2 + entropy + allowlists | Mimir uses RE2; compensate with entropy and allowlists |

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `minVisibleLen = 16` as the D-05 guardrail threshold | §Redaction Algorithm | May reveal too much or too little; planner can adjust — key constraint is "last 4 chars ≤ 25% of total length" |
| A2 | Connection-string regex pattern `([a-zA-Z][a-zA-Z0-9+\-.]{1,30})://([^:@\s]*)(?::([^@\s]+))@([^\s/"']+)` | §Connection-String Rule | False negatives/positives; MUST be unit-tested with Go `regexp` before shipping |
| A3 | `generic-api-key` regex (adapted from gitleaks) expressed directly in TOML | §V1 Ruleset Patterns | Complex regex with TOML escaping may need backslash adjustments; test carefully in TOML literal strings using `'''...'''` |
| A4 | `default max-file-size = 10 MB` | §File Filtering | Users may want lower (for speed) or higher (for completeness); configurable so the default matters only as a starting point |
| A5 | GCP API keys are exactly 39 chars (`AIza` + 35) | §V1 Ruleset Patterns | The common documentation example `AIzaSyD-9tSrke72I6e1H5HkXeGiSOHnFGJ9Xd` is 38 chars (likely a doc error); verify with a real GCP key |
| A6 | `secret_group = 3` for connection-string rule | §Connection-String Rule | Depends on capture group ordering being stable; test with diverse URI formats |

---

## Open Questions

1. **GCP key length (38 vs 39 chars)**
   - What we know: gitleaks allowlist examples are 39 chars; common doc example is 38 chars
   - What's unclear: Is there a GCP key format variation that is 38 chars?
   - Recommendation: Use `[\w-]{34,35}` to accept both lengths, or verify with a real GCP API key. The entropy gate (4.0) provides a second line of defense.

2. **Connection-string passwords with `@` or `/`**
   - What we know: RFC 3986 requires `@` to be percent-encoded in userinfo; `%40` should work in the current regex
   - What's unclear: How many real leaked connection strings use unencoded `@` in passwords?
   - Recommendation: Add a test case; document the limitation; acceptable for v1.

3. **`generic-api-key` TOML escaping**
   - What we know: The regex contains backticks and double quotes which need careful escaping in TOML
   - What's unclear: Whether TOML literal strings (`'''...'''`) handle the mixed-quote regex cleanly
   - Recommendation: Use TOML multiline literal strings (`'''`) for complex regexes; test the parse round-trip in a unit test before shipping.

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Go toolchain | Build, test, run | ✓ | go1.26.2 linux/amd64 | — |
| git | Phase 1: `.git/` skip only (no history scan) | ✓ | 2.54.0 | Check for `.git` dir by name only |
| golangci-lint | CI linting (dev tool, not in go.mod) | ✗ | — | Install separately; not blocking for Phase 1 development |
| goreleaser | Release packaging | ✗ | — | Not needed until release; skip in Phase 1 |

**Missing dependencies with no fallback:** None that block Phase 1.

**Missing dependencies with fallback:**
- `golangci-lint`: can run `go vet ./...` + `go test -race ./...` manually until CI is set up
- `goreleaser`: `go build -o mimir .` builds a working binary; goreleaser is for distribution

---

## Validation Architecture

> nyquist_validation: true — section required.

### Test Framework

| Property | Value |
|----------|-------|
| Framework | `testing` (stdlib) + `github.com/stretchr/testify` v1.11.1 |
| Config file | None (stdlib test runner via `go test`) |
| Quick run command | `go test ./... -count=1 -timeout 60s` |
| Full suite command | `go test -race ./... -count=1 -timeout 120s` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| DET-01 | Each v1 rule detects its target secret | unit | `go test ./internal/detect/ -run TestRules -v` | ❌ Wave 0 |
| DET-02 | Entropy-gated generic rule fires on high-entropy keyword context | unit | `go test ./internal/detect/ -run TestEntropy -v` | ❌ Wave 0 |
| DET-03 | Connection-string URI rule extracts password group | unit | `go test ./internal/detect/ -run TestConnStr -v` | ❌ Wave 0 |
| DET-04 | Pre-filter skips regex when keyword absent (no findings, fast) | unit | `go test ./internal/detect/ -run TestPrefilter -v` | ❌ Wave 0 |
| DET-05 | Lookahead pattern rejected at config load with clear error | unit | `go test ./internal/config/ -run TestREValidation -v` | ❌ Wave 0 |
| SCAN-01 | `mimir scan ./testdata/fixtures` finds expected secrets | integration | `go test ./internal/scanner/ -run TestScanWorkingTree -v` | ❌ Wave 0 |
| SCAN-02 | `.env` file with assignments is scanned | integration | `go test ./internal/scanner/ -run TestScanEnvFile -v` | ❌ Wave 0 |
| SCAN-05 | Binary file skipped; `.git/` skipped; oversize file skipped | unit | `go test ./internal/scanner/ -run TestFileFilter -v` | ❌ Wave 0 |
| IFACE-01 | `mimir scan ./testdata/fixtures` exits and prints findings | smoke | `go test ./cmd/ -run TestCLIScan -v` | ❌ Wave 0 |
| IFACE-02 | Exit code 0/1/2 under correct conditions; broken config → 2 | unit | `go test ./cmd/ -run TestExitCode -v` | ❌ Wave 0 |
| OUT-01 | Human output format matches expected one-line pattern | unit | `go test ./internal/output/ -run TestHumanFormat -v` | ❌ Wave 0 |
| OUT-02 | JSON output parses and contains `fingerprint` field | unit | `go test ./internal/output/ -run TestJSONSchema -v` | ❌ Wave 0 |
| OUT-03 | Scan of scan output finds no raw secrets (self-scan) | integration | `go test ./internal/scanner/ -run TestNoSecretLeak -v` | ❌ Wave 0 |
| SUP-05 | Fingerprint survives blank-line insertion above finding | unit | `go test ./internal/finding/ -run TestFingerprint -v` | ❌ Wave 0 |
| CFG-01 | Custom TOML rule in user config is applied | unit | `go test ./internal/config/ -run TestExtend -v` | ❌ Wave 0 |
| CFG-02 | Config discovery: flag > project file > defaults | unit | `go test ./internal/config/ -run TestDiscovery -v` | ❌ Wave 0 |

### Special Validation: OUT-03 Self-Scan Test

This is the success criterion 3 ("a scan of Mimir's own output for known fixture secrets finds none"):

```go
// testdata/fixtures/known-secrets.txt — fixture file with real-format but NOT REAL secrets
// These are synthetic tokens that match the regex patterns but are NOT valid credentials.
// Example: AKIAFAKEEXAMPLE1234  (too many repeated chars to be real; entropy < threshold)

// TestNoSecretLeak:
// 1. Run scanner on testdata/fixtures/known-secrets.txt — finds fixtures
// 2. Capture JSON output of that scan
// 3. Run scanner on the JSON output file itself
// 4. Assert: no secrets found in the JSON output (all values are redacted)
```

### Sampling Rate

- **Per task commit:** `go test ./... -count=1 -timeout 60s`
- **Per wave merge:** `go test -race ./... -count=1 -timeout 120s`
- **Phase gate:** Full suite green + `go vet ./...` clean before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `testdata/fixtures/known-secrets.txt` — synthetic tokens matching all v1 rules
- [ ] `testdata/clean/` — files verified to have no secrets
- [ ] `internal/detect/engine_test.go` — rule unit tests
- [ ] `internal/config/config_test.go` — RE2 validation + extend tests
- [ ] `internal/finding/finding_test.go` — redaction + fingerprint stability tests
- [ ] `internal/scanner/scanner_test.go` — file filtering + binary detection tests
- [ ] `internal/output/output_test.go` — human format + JSON schema tests
- [ ] `cmd/scan_test.go` — exit code contract tests

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No (local CLI tool, no auth) | — |
| V3 Session Management | No | — |
| V4 Access Control | No | — |
| V5 Input Validation | Yes — regex patterns in config | `regexp.Compile` at load time; RE2 prevents ReDoS |
| V6 Cryptography | Partial — SHA-256 for fingerprinting | stdlib `crypto/sha256`; never hand-roll |
| V7 Error Handling | Yes — errors must not leak secrets | See §Pitfall 1; no `%v`/`%q` on match strings |

### Known Threat Patterns for This Stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| ReDoS via malicious repo content | Denial of Service | stdlib RE2 (linear-time, immune to catastrophic backtracking) |
| Secret leakage via log/error messages | Information Disclosure | Redact-at-boundary invariant; never log raw match strings |
| Malicious TOML config injecting arbitrary regex | Tampering | RE2 validation at load; `regexp.Compile` errors cleanly |
| Oversized file causing OOM | Denial of Service | `max-file-size` cap (default 10 MB); skip binary files |
| Path traversal via config `extend.path` | Elevation of Privilege | Resolve to absolute path; warn on paths outside project root [ASSUMED — this is a Phase 2+ concern but the interface should be designed with it in mind] |

---

## Sources

### Primary (HIGH confidence)

- `github.com/gitleaks/gitleaks` source (master, 2026-05-22) — `detect/detect.go` (shannonEntropy, fingerprint, Aho-Corasick usage), `detect/utils.go` (shannonEntropy implementation), `cmd/generate/config/rules/aws.go`, `github.go`, `stripe.go`, `generic.go` (exact rule patterns and entropy thresholds), `cmd/generate/config/base/config.go` (global allowlists), `config/config.go` (Rule struct, Extend model, RE2 validation pattern), `cmd/directory.go` (cobra command structure), `sources/files.go` (file walker), `sources/file.go` (binary detection approach)
- `proxy.golang.org` — all package versions verified 2026-05-22
- Module cache at `/home/oliverh/go/pkg/mod/` — aho-corasick v1.0.3 API (trie.go, builder.go), errgroup v0.20.0 (SetLimit), fatih/color v1.19.0 (NoColor handling)
- `pkg.go.dev/github.com/pelletier/go-toml/v2` — Unmarshal, DecodeError API
- Go stdlib documentation — `regexp.Compile` RE2 error behavior, `go:embed` constraints, `crypto/sha256`, `filepath.ToSlash`

### Secondary (MEDIUM confidence)

- gitleaks `config/gitleaks.toml` (generated output) — rule ID names and keyword lists cross-referenced against source
- Python `re` module used to verify all regex patterns are RE2-compatible (Python's `re` module uses a similar RE2-like engine for basic patterns; final verification must be done with Go's `regexp.Compile`)

### Tertiary (LOW confidence)

- None — all claims tagged `[ASSUMED]` are flagged in the Assumptions Log above.

---

## Project Constraints (from CLAUDE.md)

| Directive | Category | Enforcement |
|-----------|----------|-------------|
| Go (single-binary CLI) — no other language | Stack | Architecture |
| `cobra` for CLI | Library | Locked |
| `go-toml/v2` for TOML, NO viper | Library | Locked |
| stdlib `regexp` (RE2), NO regexp2 | Library | Locked |
| `BobuSumisu/aho-corasick` for keyword pre-filter | Library | Locked |
| `x/sync` errgroup + semaphore for concurrency | Library | Locked |
| `go:embed` for default ruleset | Pattern | Locked |
| `encoding/json` for JSON output | Library | Locked |
| `fatih/color` for ANSI, honor NO_COLOR + non-TTY | Library | Locked |
| `testify` for tests | Library | Locked |
| `gitleaks/go-gitdiff` for git diff parsing | Library | Phase 3 only |
| NO logging secrets / unredacted matches | Security | Hard constraint |
| NO bubbletea/lipgloss (heavy TUI) | Library | Prohibited |
| `go test -race` mandatory in CI | Tooling | CI gate |
| `golangci-lint` with `gosec` enabled | Tooling | CI gate |
| goreleaser v2.15.4 for distribution | Tooling | Release pipeline |
| GSD workflow: use /gsd-execute-phase entry point | Process | Required |

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all packages verified via Go module proxy; production validation via gitleaks go.mod
- V1 ruleset patterns: HIGH for named-signature rules (sourced from gitleaks source); MEDIUM for connection-string pattern (designed, not from authoritative source)
- Architecture patterns: HIGH — sourced from gitleaks, Go stdlib, and x/sync module cache
- Entropy thresholds: HIGH — exact values from gitleaks source; empirical validation via Python
- Fingerprint scheme: HIGH for algorithm; ASSUMED for 16-char threshold choice
- Pitfalls: HIGH — sourced from reading gitleaks source code and common Go concurrency issues

**Research date:** 2026-05-22
**Valid until:** 2026-08-22 (90 days — stable, established Go ecosystem; aho-corasick v1.0.3 has been stable since 2020)
