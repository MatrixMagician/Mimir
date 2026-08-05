# Mimir — project context

Background notes for anyone (human or AI assistant) working on this codebase:
what it is, what it must not regress, and why the dependencies were chosen.

See `README.md` for user-facing documentation.

## Project

**Mimir**

Mimir is a fast, Go-based secret scanner that finds leaked credentials — API keys, passwords, tokens, private keys, and connection strings — across a repository's working tree, git history, environment/config files, and staged changes. It runs as a CLI, as a CI/CD gate, and as a pre-commit hook, so teams can catch secrets before they ship and audit repos for secrets already committed. It's built to be both a genuine learning project (idiomatic Go, well-structured) and a tool people can actually rely on.

**Core Value:** Accurately catch real leaked secrets — with few enough false positives that developers trust it and keep it in their workflow.

### Constraints

- **Tech stack**: Go (single-binary CLI) — chosen for performance, concurrency, and learning value.
- **Performance**: Must scan real-world repos (incl. git history) fast enough to run in CI and as a pre-commit hook without being annoying — implies concurrency.
- **Security**: Findings output must redact secret values by default; live verification must be opt-in and not leak credentials in logs.
- **Usability**: Low false-positive rate is a hard requirement for adoption — suppression must be ergonomic.
- **Distribution**: Prefer zero/standard-library-leaning dependencies where reasonable to keep the binary lean and the codebase legible.

## Technology Stack

## Recommended Stack
### Core Technologies
| Technology | Version | Purpose | Why Recommended |
|------------|---------|---------|-----------------|
| Go (toolchain) | 1.26.x | Language/runtime | Single static binary, native concurrency, fast `regexp`. 1.26 is current locally (`go1.26.2`). Pin `go 1.25` in `go.mod` as the floor for broad CI compatibility unless a 1.26 feature is needed. |
| `github.com/spf13/cobra` | v1.10.2 | CLI framework (subcommands, flags, help, completions) | The de-facto Go CLI standard and exactly what gitleaks uses. Gives `mimir scan`, `mimir scan --staged`, `mimir scan --git`, `mimir verify`, shell completions, and auto-generated help for free. The three entry points (CLI / CI gate / pre-commit) are all the same binary with different flags + exit codes — cobra models this cleanly. |
| `github.com/pelletier/go-toml/v2` | v2.3.1 | Config + ruleset parsing (TOML) | TOML is the established format for secret-scanner rulesets (gitleaks' `gitleaks.toml`). go-toml/v2 is fast, well-maintained, has good struct-decoding and error messages, and is what gitleaks pulls in transitively. Decode directly into typed structs — do **not** wrap it in viper (see What NOT to Use). |
| `github.com/gitleaks/go-gitdiff` | v0.9.1 | Parse `git log -p` / `git diff` patch output into per-file, per-line hunks | This is the load-bearing decision for history scanning. Mimir should run the system `git` binary (`git log -p`, `git diff --staged`) and parse the patch stream with go-gitdiff, exactly as gitleaks does. It yields added lines with file path + line number — precisely what a finding needs. Avoids go-git's history-walk performance and memory costs (see ARCHITECTURE / What NOT to Use). |
| Standard library `regexp` (RE2) | stdlib (Go 1.26) | Signature rule matching | RE2 is linear-time and immune to catastrophic backtracking (ReDoS), which matters when running attacker-influenced repo content through hundreds of patterns. Every serious Go scanner (gitleaks, trufflehog) uses it. Its lack of lookahead/backreferences is a real constraint — handled with entropy + allowlists, not a different engine. |
| `golang.org/x/sync` (`errgroup`, `semaphore`) | v0.20.0 | Bounded-concurrency file/commit scanning | The idiomatic worker-pool pattern: `errgroup.WithContext` for fan-out + first-error cancellation, with a `semaphore.Weighted` (or `errgroup.SetLimit`) to cap parallelism at ~`GOMAXPROCS`. gitleaks uses the equivalent `fatih/semgroup`; `x/sync` is the standard, lower-dependency choice that does the same thing. |
### Supporting Libraries
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `encoding/json` (stdlib) | stdlib | JSON output for automation/CI | Always. No third-party JSON lib needed — define a typed `Finding` struct and `json.NewEncoder(os.Stdout).Encode(...)`. Use `omitempty` and explicit field tags so the JSON schema is stable for downstream tooling. |
| `github.com/bmatcuk/doublestar/v4` | v4.10.0 | `**` glob matching for `.mimirignore` paths/globs | When implementing the ignore-file. `path/filepath.Match` does **not** support `**` recursive globs; doublestar does and is the common choice. Gitignore-style semantics are what users expect. |
| `github.com/fatih/color` | v1.19.0 | ANSI color for human-readable output | For the readable CLI output (severity colors, redaction highlighting). Respects `NO_COLOR` and auto-disables on non-TTY, which is correct behavior for CI logs. Lightweight; skip heavier TUI libs (lipgloss/bubbletea) — Mimir is non-interactive. |
| `github.com/aws/aws-sdk-go-v2/config` (+ `service/sts`) | config v1.32.17 | AWS live verification | For the opt-in AWS verifier: validate a discovered access key by calling `sts:GetCallerIdentity` with static creds. Pull only the `config`, `credentials`, and `service/sts` submodules — the AWS SDK is heavily modular, so you do not import the whole SDK. |
| `github.com/google/go-github/v78` | v78.0.0 | GitHub live verification | For the opt-in GitHub verifier: confirm a discovered token by calling an authenticated endpoint (e.g. `GET /user` or checking `X-OAuth-Scopes`). Use the latest major (v78) for current API coverage. A bare `net/http` call to `api.github.com/user` is also viable and lighter if you want to avoid the dependency. |
| `github.com/stretchr/testify` | v1.11.1 | Test assertions + suites | `require`/`assert` for readable test failures; `testify/suite` if you want setup/teardown grouping. Standard across the Go ecosystem and used by gitleaks itself. |
| `golang.org/x/sync/semaphore` | (part of x/sync v0.20.0) | Explicit weighted concurrency limiting | When you need finer control than `errgroup.SetLimit` (e.g. weight large files heavier). Otherwise `errgroup.SetLimit(n)` is sufficient. |
### Development Tools
| Tool | Purpose | Notes |
|------|---------|-------|
| `goreleaser` | Cross-platform builds, archives, checksums, release | v2.15.4. The standard for Go single-binary distribution. Configure `builds` for linux/darwin/windows × amd64/arm64, embed version via `-ldflags "-X main.version={{.Version}}"`, produce `.tar.gz`/`.zip` + `checksums.txt`, and optionally Homebrew tap + Docker image. Run it from GitHub Actions on tag push. |
| `golangci-lint` | Aggregated linting (vet, staticcheck, etc.) | Use a pinned version in CI. Enable `gosec` — appropriate for a security tool. Catches the kinds of bugs (unchecked errors, ineffectual assignments) that cause scanner false negatives. |
| `go test -race` | Race detection | Mandatory in CI given the concurrent scanner. The worker-pool design makes data races easy to introduce; `-race` catches them. |
| GitHub Actions | CI + release pipeline | Build matrix, `go test -race ./...`, golangci-lint, and a `goreleaser` release job gated on git tags. Mimir should also dogfood itself: run `mimir scan` on its own repo in CI. |
| `go:embed` (stdlib directive) | Embed the default ruleset TOML into the binary | Embed `config/mimir.toml` so the single binary ships with built-in rules and zero runtime file dependencies. User config then *extends* the embedded defaults — same model as gitleaks' `[extend]`. |
## Installation
# Initialize module (Go ecosystem — not npm)
# Core
# Supporting
# Live verification (opt-in feature)
# Dev / test
# Distribution tooling (installed separately, not a module dep)
## Alternatives Considered
| Recommended | Alternative | When to Use Alternative |
|-------------|-------------|-------------------------|
| cobra | `urfave/cli` (v3) | If you want a lighter dependency tree and a more minimal API. urfave/cli is excellent and fully capable here. cobra wins on ecosystem familiarity (matches gitleaks), completion generation, and docs — but urfave/cli is a legitimate choice if dependency leanness is prioritized per the PROJECT.md "lean binary" constraint. |
| cobra | stdlib `flag` | Only if you stay truly single-command. With subcommands (`scan`, `verify`, `version`) and the CI/pre-commit variants, stdlib `flag` becomes a hand-rolled router fast. Not worth it here. |
| go-toml/v2 (direct decode) | `koanf/v2` | If you later need layered config (file + env + flags merged with precedence) without viper's bloat. koanf v2.3.4 is modular and clean. For v1, direct TOML decode into structs is simpler and sufficient. |
| go-toml/v2 | `BurntSushi/toml` (v1.6.0) | Equally valid mature TOML lib. Pick go-toml/v2 because gitleaks uses it (parser-compatibility with the rule ecosystem) and it has slightly richer decode diagnostics. |
| `git log -p` + go-gitdiff | `go-git/go-git v5` (v5.19.1) | If you must support scanning bare/remote repos where no `git` binary is available, or want a pure-Go binary with zero external runtime deps. trufflehog uses go-git v5 for this reason. The cost is significantly higher memory/CPU when walking full history (it reconstructs trees/objects in-process). For Mimir's "fast in CI/pre-commit" constraint, shelling out is the right default; consider go-git as an optional backend later. **Do not use go-git v6 — it is `v6.0.0-alpha.4`, pre-release.** |
| TOML config | YAML (`gopkg.in/yaml.v3`) | Only if user research shows your audience strongly prefers YAML. TOML is the scanner-domain convention (gitleaks) and avoids YAML's indentation/footgun reputation. Regex-heavy rule files are also more readable in TOML's multiline literal strings (`'''...'''`) which need no escaping. |
| errgroup + semaphore | `sourcegraph/conc` (v0.3.0) | If you want higher-level pool/iterator abstractions and panic propagation. Nice ergonomics, but adds a dependency for what `errgroup.SetLimit` already does. Reasonable if the team prefers its API. |
| go-github SDK | bare `net/http` to `api.github.com/user` | If you want zero extra dependencies for the single GitHub verification call. The full SDK is convenient but heavy for one endpoint. For v1's narrow verification scope, a hand-rolled `net/http` request is defensible and lighter. |
## What NOT to Use
| Avoid | Why | Use Instead |
|-------|-----|-------------|
| `github.com/dlclark/regexp2` for rule matching | It supports lookahead/backreferences but is **backtracking-based**, so it is far slower and vulnerable to catastrophic backtracking (ReDoS) on adversarial repo content — the opposite of what a fast, safe scanner needs. No mature scanner uses it for the hot path. | Stdlib `regexp` (RE2). Compensate for missing lookahead/backreferences with (a) entropy thresholds per rule, (b) allowlists/stopwords, and (c) capture groups + post-match Go code for context checks. This is exactly gitleaks' strategy. |
| `spf13/viper` | Heavy transitive dependency tree for what Mimir needs (one TOML file decoded into structs). Conflicts with the PROJECT.md "lean binary / stdlib-leaning" constraint. gitleaks uses it largely for legacy reasons; you are greenfield and can skip it. | Decode TOML directly with go-toml/v2. If you later need env/flag layering, reach for `koanf/v2`, not viper. |
| `go-git/go-git` as the **default** history backend | Walking full history in-process is memory- and CPU-heavy versus parsing `git log -p` output; gitleaks deliberately shells out for this reason. Also adds a large dependency surface. | Shell out to the system `git` binary and parse with `gitleaks/go-gitdiff`. Keep go-git as an optional fallback for no-git-binary environments only. |
| `go-git v6` (`v6.0.0-alpha.4`) | Pre-release alpha; API not stable. Not appropriate for a tool people should rely on. | If you do adopt go-git, pin v5.19.1 (stable). |
| Regex with unbounded `.*` across whole files / multiline by default | Even with RE2's linear guarantee, scanning huge minified/vendored files line-by-line with hundreds of greedy patterns is slow and noisy. | Pre-filter with a keyword pass before running expensive regexes (gitleaks uses Aho-Corasick / `BobuSumisu/aho-corasick` for this), cap max file size (e.g. skip >5–10 MB, gitleaks' default), and skip detected binaries. |
| Heavy TUI libs (bubbletea, full lipgloss) | Mimir is non-interactive (CLI/CI/hook). A TUI adds weight and complexity for no value, and breaks in CI logs. | `fatih/color` for simple ANSI output; plain text/JSON otherwise. Honor `NO_COLOR` and non-TTY detection. |
| Logging secrets / unredacted matches to stdout/stderr | Security requirement from PROJECT.md: findings must redact by default and verification must not leak creds in logs. A logging library that dumps structured fields can accidentally print the secret. | Redact at the `Finding` boundary (store only a masked snippet + offsets). If you add structured logging, `log/slog` (stdlib) with explicit, audited fields — never log the raw match. |
## Stack Patterns by Variant
- Use `urfave/cli` or stdlib `flag` instead of cobra; bare `net/http` instead of go-github; `koanf` or direct go-toml decode instead of viper.
- Because the project explicitly values a legible codebase and lean binary; every dropped dependency reduces supply-chain surface (apt for a security tool).
- Add `go-git/go-git v5.19.1` as an alternate history backend behind an interface.
- Because shelling out to `git log -p` requires git on PATH; CI images sometimes lack it. Keep go-gitdiff/`git log -p` as the fast default and select go-git only when no binary is present.
- Add an Aho-Corasick keyword pre-filter (`BobuSumisu/aho-corasick` v1.0.3) and per-rule entropy thresholds + allowlists/stopwords before investing in more regexes.
- Because layered filtering (keyword gate → regex → entropy → allowlist) is how gitleaks/detect-secrets keep noise down, and it is also faster than running every regex on every line.
- Define a `Verifier` interface (`Verify(ctx, secret) (active bool, err error)`) now so providers are pluggable. Per-provider SDK or `net/http`, with context timeouts and rate-limit handling.
- Because PROJECT.md scopes v1 to AWS+GitHub but anticipates expansion; an interface avoids a rewrite.
## Version Compatibility
| Package A | Compatible With | Notes |
|-----------|-----------------|-------|
| cobra v1.10.2 | Go 1.25+ | cobra recent releases track recent Go; fine on 1.26. |
| go-toml/v2 v2.3.1 | Go 1.21+ | No issues; pure Go. |
| gitleaks/go-gitdiff v0.9.1 | system `git` ≥ 2.x | Parses standard `git log -p` / unified-diff output; requires the git binary on PATH at runtime. Document git as a runtime prerequisite for history mode. |
| x/sync v0.20.0 | Go 1.25+ | `errgroup.SetLimit` available since x/sync v0.4.0 — well covered. |
| aws-sdk-go-v2 `config` v1.32.17 | matching `credentials`/`service/sts` modules | The v2 SDK is multi-module; keep the `config`, `credentials`, and `service/sts` versions in the same release window to avoid mismatches. |
| go-github v78 | Go 1.22+ | Major version is in the import path (`/v78`); upgrading majors is a manual import-path bump. |
| goreleaser v2.15.4 | Go 1.25/1.26 builds | Build with the same Go toolchain you test with; set `gobinary`/toolchain in `.goreleaser.yaml` if you need reproducibility. |
## Reference: how the comparable tools are built (validates the above)
| Tool | CLI | Config | History scan | Concurrency | Regex | Entropy |
|------|-----|--------|--------------|-------------|-------|---------|
| **gitleaks** (v8.30.1) | cobra | viper + go-toml/v2 (TOML) | shell `git log -p` → `gitleaks/go-gitdiff` | `fatih/semgroup` (bounded errgroup) + `aho-corasick` keyword pre-filter | stdlib RE2 + allowlists | Shannon, per-rule threshold |
| **trufflehog** | `alecthomas/kingpin/v2` | flags/env | `go-git/go-git v5` (in-process) | `x/sync` errgroup | RE2 + **live verification** as the differentiator | entropy candidate-finding then verify |
| **detect-secrets** (Python) | argparse | YAML baseline | git plugin | — | regex plugins | Shannon (Base64/Hex high-entropy plugins) |
## Sources
- Go module proxy (`proxy.golang.org`) — exact current versions verified 2026-05-22: cobra v1.10.2, go-git v5.19.1 / v6.0.0-alpha.4, koanf v2.3.4, viper v1.21.0, go-toml/v2 v2.3.1, BurntSushi/toml v1.6.0, x/sync v0.20.0, testify v1.11.1, go-gitdiff v0.9.1, semgroup v1.3.0, aho-corasick v1.0.3, doublestar/v4 v4.10.0, fatih/color v1.19.0, aws-sdk-go-v2/config v1.32.17, go-github v78.0.0. **HIGH.**
- GitHub Releases API — goreleaser v2.15.4, gitleaks v8.30.1 (latest releases as of 2026-05-22). **HIGH.**
- gitleaks `go.mod` (master, raw.githubusercontent.com) — confirmed cobra + viper + go-toml/v2 + `gitleaks/go-gitdiff` + `fatih/semgroup` + `BobuSumisu/aho-corasick`; confirmed it does **not** depend on go-git for history. **HIGH.**
- trufflehog `go.mod` (main) — confirmed `alecthomas/kingpin/v2`, `go-git/go-git v5.17.1`, `go-github`, `x/sync`. **HIGH.**
- gitleaks README + Go docs (github.com/gitleaks/gitleaks; pkg.go.dev) — `git log -p` patch scanning, Cobra subcommands, TOML config/allowlists, RE2 "no lookaheads" note, Shannon entropy field/threshold. **HIGH.**
- Context7 `/go-git/go-git` — `Log(LogOptions)` commit iteration API and in-memory storage model (used to assess history-walk cost). **HIGH.**
- dlclark/regexp2 docs (pkg.go.dev) — confirms regexp2 is a backtracking .NET-style engine; recommended only when RE2 features are insufficient. **HIGH.**
- WebSearch (rafter.so, jit.io, lookingatcomputer.substack.com, blog.miloslavhomer.cz, detect-secrets source) — tool comparison, Shannon entropy thresholds (~3.0–4.5 hex/base64), layered detection patterns. **MEDIUM** (corroborated across multiple sources + primary `go.mod` evidence).
