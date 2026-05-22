# Walking Skeleton — Mimir

**Phase:** 1
**Generated:** 2026-05-22

## Capability Proven End-to-End

A developer can run `mimir scan testdata/fixtures` and receive a redacted finding
(`path:line:col  aws-access-token  AKIA****...****MPLE`) to stdout, a scan-stats
summary line, and exit code 1 — exercising the complete pipeline: file walk →
Aho-Corasick keyword gate → RE2 match → `Finding` redacted at boundary →
human-readable output → exit code contract.

## Architectural Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Language | Go (go1.26.2 / go 1.25 floor in go.mod) | Single static binary, native concurrency, fast RE2; learning goal |
| CLI framework | `github.com/spf13/cobra` v1.10.2 | De-facto Go CLI standard; models `mimir scan`, `mimir version`, flags, help for free |
| Config / ruleset format | TOML via `github.com/pelletier/go-toml/v2` v2.3.1 | Established scanner-domain convention; gitleaks compatibility; multiline literal strings clean for complex regexes |
| Default ruleset delivery | `go:embed config/mimir.toml` | Zero runtime file dependency; standard Go feature |
| Keyword pre-filter | `github.com/BobuSumisu/aho-corasick` v1.0.3 | O(n) multi-keyword line scan; exact library gitleaks uses; prevents regex from running on unmatched lines |
| Regex engine | stdlib `regexp` (RE2) | Linear-time; immune to ReDoS; no lookahead/backreference (compensate with entropy + allowlists) |
| Concurrency | `golang.org/x/sync` v0.20.0 (`errgroup.WithContext` + `SetLimit`) | Bounded worker pool capped at GOMAXPROCS; idiomatic Go; first-error cancellation |
| JSON output | stdlib `encoding/json` | No extra dependency; typed `Finding` struct → `json.NewEncoder` |
| ANSI color | `github.com/fatih/color` v1.19.0 | Respects `NO_COLOR` env + non-TTY; lightweight; what gitleaks uses |
| Test assertions | `github.com/stretchr/testify` v1.11.1 | Standard Go ecosystem; `require`/`assert` for readable failures |
| Redaction model | Redact at `Finding` boundary (prefix+last-4-peek; `[REDACTED]` for short secrets) | No raw secret value survives past `finding.New()` constructor; enforced invariant |
| Fingerprint scheme | `<repo-relative-path>:<rule-id>:<sha256[:16](raw_secret)>` | Content-hash survives line shifts; cross-platform via `filepath.ToSlash()`; Phase 2 baseline-compatible |
| Directory layout | `cmd/` (cobra commands) + `internal/` (detect, finding, output, scanner, config) + `config/` (go:embed target) | `internal/` prevents accidental import; `config/embed.go` must co-locate with `mimir.toml` for `go:embed` |
| Exit-code contract | 0 clean / 1 findings / 2 error; `--exit-zero` suppresses 1 | CI-friendly; broken config always exits 2 |
| Output routing | Findings + summary to stdout; verbose/diagnostic to stderr | grep-pipeable; `--format json` switches format, never auto-detects TTY |

## Module Path

`github.com/MatrixMagician/mimir` (module path in go.mod)

## Stack Touched in Phase 1

- [x] Project scaffold — `go mod init`, full package layout (`cmd/`, `internal/detect/`, `internal/finding/`, `internal/output/`, `internal/scanner/`, `internal/config/`, `config/`), build (`go build -o mimir ./cmd/mimir`), lint (`go vet ./...`), test runner (`go test -race ./...`)
- [x] "Routing" — cobra command tree: `mimir scan [paths...]` + `mimir version`
- [x] "Data source" — filesystem walk over working tree (reads real file contents); no database
- [x] "Write" equivalent — emits real `Finding` to stdout (the tool's primary output)
- [x] End-to-end invocation — `go build -o mimir ./cmd/mimir && ./mimir scan testdata/fixtures/` finds fixture secrets, prints redacted findings, exits 1

## Out of Scope (Deferred to Later Slices)

- Suppression: inline `// mimir:ignore`, `.mimirignore`, default allowlists, baseline — Phase 2
- Git history scan, staged-changes scan, pre-commit hook installer — Phase 3
- Live verification (AWS STS / GitHub API calls) — Phase 4
- SARIF / additional output formats — v2
- Severity / confidence field — v2
- JDBC `?password=` connection-string form — known v1 gap, deferred
- Comprehensive (gitleaks-scale ~100+) ruleset — Phase 2+ after suppression lands
- CLI `--enable-rule`/`--disable-rule` flags — config-file-only in v1
- goreleaser release pipeline — after Phase 1 is working

## Subsequent Slice Plan

Each later phase adds one vertical slice on top of this skeleton without altering its architectural decisions:

- Phase 2: False-positive control (inline suppress, `.mimirignore`, allowlists, baseline — uses Phase 1 fingerprint scheme)
- Phase 3: Full source coverage (git history via `git log -p` + go-gitdiff, staged scan, pre-commit hook)
- Phase 4: Opt-in live verification (AWS STS + GitHub API, behind `--verify`, Verifier interface on Phase 1 Finding struct)
