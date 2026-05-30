# Phase 4: Opt-in Live Verification (AWS + GitHub) - Research

**Researched:** 2026-05-30
**Domain:** Go credential live-verification — AWS STS + GitHub REST, redact-preserving plumbing, bounded-concurrency network calls
**Confidence:** HIGH (codebase facts verified via graphmind + Read; AWS/GitHub APIs verified via official docs + Go proxy; carry mechanism derived from the actual reflection test)

## Summary

Phase 4 adds an opt-in `--verify` flag that, after suppression, takes the reportable finding
set and live-checks AWS and GitHub credentials, labelling each `active` / `inactive` / `unknown`.
The detection engine is not modified; the only network calls are AWS STS `GetCallerIdentity`
(via aws-sdk-go-v2 minimal modules) and GitHub `GET /user` (via bare `net/http`). Off by
default, never in the pre-commit hook.

The single hard problem is the **raw-secret carry**: the raw secret exists in exactly one place —
`detect.Engine.ScanLine` (`internal/detect/engine.go:114`, local var `rawSecret`) — and is
dropped the instant `finding.New(...)` is called at line 144. Findings only carry a redacted
`Secret`, and the reflection guard `TestNoRawSecretInAnyField` (`finding_test.go:171`) fails if
any exported string field of a `Finding` contains the raw value. The recommended mechanism is a
**side-channel `map[fingerprint]rawSecret` populated inside `ScanLine`** (the one site where the
raw value still exists), returned alongside `[]Finding`, threaded through the scanner/gitscan
return signatures, and consumed by the verifier in `runScan` — never stored on `Finding`, never
serialized, never logged. The fingerprint is already a per-(path,rule,secret) key, so it is a safe,
collision-resistant lookup token. A separate per-*secret* cache (keyed by the secret value held
only in-memory) dedups the actual network calls so one leaked secret in N findings is verified once.

**Primary recommendation:** Add `internal/verify` (Verifier interface + AWS/GitHub impls + registry
keyed by rule ID + in-memory per-secret cache). Carry raw secrets via a `map[string]string`
(fingerprint→raw) produced by `ScanLine` and propagated through `Scan`/`ScanHistory`/`ScanStaged`
return tuples. Use aws-sdk-go-v2 `sts.New(sts.Options{Region:"aws-global", Credentials: staticProvider})`
(direct client construction — bypasses LoadDefaultConfig and therefore the ambient credential
chain). Use bare `net/http` GET to `https://api.github.com/user`. Classify by error code / status:
inactive only on definitive auth rejection; everything else (network/timeout/429-after-retry) →
unknown. Add an `omitempty` non-string `*Verification` field to `Finding` for JSON; render a colored
tag + one-line tally in human output.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- `--verify` is **label-only** — does NOT change exit codes. Exit contract (0 clean / 1 findings / 2 error) unchanged.
- `--verify` allowed for manual `--staged` runs, but the **installed pre-commit hook never passes `--verify`** (hook stays fully offline).
- Findings with no matching verifier (not AWS/GitHub rule types) are **silently left unlabeled** (status omitted).
- **No pre-flight network/connectivity check** — each call times out and yields `unknown` (network failure = unknown, never inactive).
- AWS access-key-ID → secret-access-key pairing is **best-effort**: scan the same file for a co-located `aws_secret_access_key`; if none found → `unknown`.
- AWS client uses **aws-sdk-go-v2 minimal modules** (`config` + `credentials` + `sts`). Use the **global STS endpoint** (`sts.amazonaws.com`); no region configuration required.
- GitHub client uses **bare `net/http`** to `api.github.com/user`. No go-github SDK. **`api.github.com` only** (no Enterprise / custom base URL).
- JSON uses a **nested object**: `"verification": {"status": "active|inactive|unknown", "provider": "aws|github"}`, `omitempty` so non-`--verify` scans stay byte-identical to OUT-02.
- Human output: **colored tag** per verified finding — `ACTIVE` (red/bold), `INACTIVE` (dim), `UNKNOWN` (yellow) — honoring `NO_COLOR` / non-TTY.
- Under `--verify`, a **one-line tally**: `Verified: N active, M inactive, K unknown`.
- **No reordering** of findings.
- Per-call timeout default: **5 seconds** (`context.WithTimeout`).
- Rate-limit / 429: **honor `Retry-After` once, then mark `unknown`** — no aggressive retry loop.
- Concurrency: **bounded worker pool via `errgroup.SetLimit`** (reuse scanner pattern), small limit (~5).
- A **`Verifier` interface** (`Verify(ctx, secret) (status, error)`) in a new `internal/verify` package, registry keyed by rule ID.
- **Per-secret cache**: a secret in many findings is verified at most once, keyed by distinct secret value (in-memory only).

### Claude's Discretion

- Exact internal package layout, type names, and cache key derivation.
- How the transient raw secret is carried from detection to the verifier without violating redact-at-boundary or `TestNoRawSecretInAnyField` (e.g. a parallel non-serialized side channel keyed by fingerprint, populated where the raw value still exists, never marshalled).
- Precise wording/format of the human tag and summary line.

### Deferred Ideas (OUT OF SCOPE)

- Additional providers beyond AWS/GitHub (GCP, Slack, etc.) — v2.
- GitHub Enterprise / custom base URL support (`--github-base-url`) — v2.
- Configurable `--verify-timeout` flag — v2 (fixed 5s default for v1).
- `--fail-on-verified` exit-code mode — v2 (v1 keeps verification label-only).
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| VERIFY-01 | User can opt in (`--verify`, off by default, never in pre-commit) to live-verify findings | Flag registered in `scan.go init()` alongside existing flags; verification invoked only when `--verify` true (no network otherwise). Hook installer (Phase 3) never emits `--verify` — confirm in hook template. See "Output integration" + "Pitfall 7". |
| VERIFY-02 | Verifies AWS and GitHub via read-only calls (STS GetCallerIdentity, GET /user) with three-state classification | AWS verifier (sts.New + GetCallerIdentity), GitHub verifier (net/http GET /user). Three-state mapping in "AWS verification" / "GitHub verification" sections. Registry keyed by rule ID maps findings → verifier. |
| VERIFY-03 | Caches per distinct secret, honors rate-limit backoff, never logs the secret value | Per-secret in-memory cache (keyed by secret value); Retry-After honored once then unknown; sanitized verifier errors (provider + reason enum only). See "Concurrency + cache + rate-limit" + "Pitfall 1". |
</phase_requirements>

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Raw-secret capture | Detection engine (`ScanLine`) | — | Only site where the raw value exists before redaction; must emit the side channel here, not reconstruct it later |
| Raw-secret transport | Scanner / gitscan return tuples | cmd `runScan` | The walk/parse layers already aggregate findings; the side-channel map rides the same return path |
| Verification orchestration | `cmd/mimir/scan.go runScan` (post-suppression) | `internal/verify` | Runs on `newFindings` after baseline/suppression, before output — the slot the pipeline already reserves |
| AWS/GitHub API calls | `internal/verify` (Verifier impls) | aws-sdk-go-v2 / net/http | Network boundary; isolates SDK + HTTP and sanitized error handling in one package |
| Status rendering | `internal/output` (json.go, human.go) | finding.Finding (`*Verification` field) | Output already owns schema-stable rendering; verification field is additive + omitempty |

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `github.com/aws/aws-sdk-go-v2/service/sts` | v1.42.3 | STS `GetCallerIdentity` call | First-party AWS module; SigV4 signing is too error-prone to hand-roll (CONTEXT lock). `[VERIFIED: Go proxy 2026-05-29]` |
| `github.com/aws/aws-sdk-go-v2/credentials` | v1.19.19 | `NewStaticCredentialsProvider(id, secret, "")` | Supplies the discovered key pair as static creds, bypassing the ambient chain. `[VERIFIED: Go proxy 2026-05-29]` |
| `github.com/aws/aws-sdk-go-v2/config` | v1.32.20 | (CONTEXT-locked module) — `aws.Config` types | Locked by CONTEXT. **See note below: direct `sts.New(sts.Options{...})` is preferred over `config.LoadDefaultConfig` to guarantee no ambient creds.** `[VERIFIED: Go proxy 2026-05-29]` |
| `github.com/aws/aws-sdk-go-v2` (root, `aws` pkg) | v1.41.9 | `aws.Config`, `aws.Credentials`, `aws.NewCredentialsCache` | Pulled transitively; provides the `aws.Config`/`aws.Credentials` types. `[VERIFIED: Go proxy 2026-05-29]` |
| `github.com/aws/smithy-go` | v1.26.0 | `smithy.APIError` for error-code classification | Transitive dep of the SDK; `errors.As(err, &apiErr)` + `apiErr.ErrorCode()` is the canonical way to read `InvalidClientTokenId` etc. `[VERIFIED: Go proxy 2026-05-27]` |
| `net/http` (stdlib) | stdlib (Go 1.25) | GitHub `GET /user` | CONTEXT lock — keep binary lean, single read-only call. `[CITED: CLAUDE.md]` |
| `golang.org/x/sync/errgroup` | v0.20.0 (already in go.mod) | Bounded verification worker pool | Already the project's concurrency primitive (`scanner.go:70-71`). `errgroup.SetLimit(5)`. `[VERIFIED: go.mod]` |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `encoding/json` (stdlib) | stdlib | Decode GitHub `/user` response if any field needed | Status comes from HTTP code alone; decoding the body is optional. Prefer NOT decoding (status-only) to avoid pulling username into memory. |
| `errors` (stdlib) | stdlib | `errors.As` for smithy + `net.Error` classification | Distinguish definitive auth failure (inactive) from network/timeout (unknown). |
| `regexp` (stdlib RE2) | stdlib | Co-located `aws_secret_access_key` pairing scan | Re-read the finding's file; match a 40-char base64 secret near an `aws_secret_access_key`/`aws...secret` assignment. |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `sts.New(sts.Options{...})` direct | `config.LoadDefaultConfig(...WithCredentialsProvider...)` | LoadDefaultConfig still initializes the ambient chain machinery (reads env/region resolvers) before the static provider overrides creds. Direct `sts.New` provably reads **nothing** ambient — strictly safer for a security tool. CONTEXT locks the `config` module but not the entry point; recommend direct construction and keep `config` as a permitted dep. |
| bare `net/http` for GitHub | `go-github/v78` | CONTEXT locks bare net/http (lean binary). Confirmed. |
| `map[fingerprint]raw` side channel | unexported field on `Finding` | An unexported field would NOT trip the reflection test (it skips `!field.IsExported()`), but it co-locates the raw secret with the serializable struct forever — one careless `json` tag or a future `reflect`-marshals-unexported change leaks it. A separate map keeps the raw value physically off the `Finding` type. **Side channel preferred.** |

**Installation:**
```bash
# Go modules — added to go.mod (NOT npm). Pin in the same release window:
go get github.com/aws/aws-sdk-go-v2/service/sts@v1.42.3
go get github.com/aws/aws-sdk-go-v2/credentials@v1.19.19
go get github.com/aws/aws-sdk-go-v2/config@v1.32.20
# root module + smithy-go arrive transitively; verify after:
go mod tidy
```

**Version verification:** All AWS module versions confirmed against `proxy.golang.org/<mod>/@latest`
on 2026-05-29 (the SDK is multi-module; keeping `config`/`credentials`/`sts` in the same publish
window avoids resolver mismatches — they share commit hash `5841d3a`). `[VERIFIED: Go proxy]`

## Package Legitimacy Audit

> Go modules, not npm/PyPI. slopcheck (v0.6.1, installed) targets npm/PyPI registries and does not
> evaluate Go modules; legitimacy here is established by first-party org ownership + Go proxy + repo HTTP 200.

| Package | Registry | Age | Source Repo | slopcheck | Disposition |
|---------|----------|-----|-------------|-----------|-------------|
| aws-sdk-go-v2/service/sts | Go proxy | mature (v1.42.3, 2026-05-29) | github.com/aws/aws-sdk-go-v2 (HTTP 200, first-party AWS) | n/a (Go) | Approved |
| aws-sdk-go-v2/credentials | Go proxy | mature (v1.19.19) | github.com/aws/aws-sdk-go-v2 | n/a (Go) | Approved |
| aws-sdk-go-v2/config | Go proxy | mature (v1.32.20) | github.com/aws/aws-sdk-go-v2 | n/a (Go) | Approved (CONTEXT-locked) |
| aws-sdk-go-v2 (root) | Go proxy | mature (v1.41.9) | github.com/aws/aws-sdk-go-v2 | n/a (Go) | Approved (transitive) |
| smithy-go | Go proxy | mature (v1.26.0, 2026-05-27) | github.com/aws/smithy-go | n/a (Go) | Approved (transitive) |

**Packages removed due to slopcheck [SLOP] verdict:** none
**Packages flagged as suspicious [SUS]:** none

All five are published by the official `github.com/aws` org (canonical AWS SDK), already named in
CLAUDE.md's recommended stack, and verified present on the Go module proxy with consistent shared
commit hashes. No supply-chain risk signals. Run `go mod verify` after `go get` as the final gate.

## Architecture Patterns

### System Architecture Diagram

```
mimir scan --verify
        │
        ▼
   runScan (cmd/mimir/scan.go)
        │
        │  ── scan source select (unchanged) ──────────────┐
        ▼                                                   │
  Scanner.Scan / gitscan.ScanHistory / ScanStaged           │
        │  (ScanLine builds Finding AND emits raw side-chan) │
        ▼                                                   │
  ([]Finding, rawByFingerprint map[string]string, Stats) ◄──┘
        │
        ▼
  baseline + suppression marking (unchanged)
        │
        ▼
  newFindings  ← reportable set (post-suppression)
        │
        │  if --verify:
        ▼
  verify.Run(ctx, newFindings, rawByFingerprint)
        │            │
        │            ├─ registry[ruleID] → Verifier (AWS | GitHub | none)
        │            ├─ per-secret cache (value → status)   [dedup]
        │            ├─ errgroup.SetLimit(5)  [bounded fan-out]
        │            │
        │            ├─ AWS:  pair key+secret(same file) → sts.GetCallerIdentity
        │            │         200→active · InvalidClientTokenId→inactive · else→unknown
        │            │
        │            └─ GitHub: net/http GET api.github.com/user
        │                       200→active · 401→inactive · 403/429→Retry-After once→unknown
        ▼
  finding.Verification set on each verified Finding (in-memory only)
        │
        ▼
  output.WriteJSON / WriteHuman  (verification field / colored tag + tally)
        │
        ▼
  exit code from newFindings (UNCHANGED — label-only)
```

File-to-implementation mapping is in the Component Responsibilities below; the diagram shows data flow.

### Recommended Project Structure
```
internal/verify/
├── verify.go        # Verifier interface, Status enum, Registry (ruleID→Verifier), Run() orchestrator + per-secret cache + errgroup
├── aws.go           # awsVerifier: static-cred STS GetCallerIdentity + key/secret pairing helper
├── github.go        # githubVerifier: net/http GET /user + status/rate-limit classification
├── verify_test.go   # interface + registry + cache + classification (httptest/mock) tests
├── aws_test.go      # AWS error-code → status mapping (table)
└── github_test.go   # httptest server: 200/401/403+Retry-After/timeout → status
```

### Pattern 1: Side-channel raw-secret carry (THE critical pattern)
**What:** Emit `map[fingerprint]rawSecret` from `ScanLine`; thread it through the return tuples;
consume it in the verifier. The raw value never touches the `Finding` struct.
**When to use:** Always under this redact-at-boundary regime.
**Mechanism (concrete):**
- `engine.ScanLine` currently returns `[]finding.Finding`. Change it to also return a
  `map[string]string` (fingerprint→rawSecret), OR accept a caller-provided `map[string]string`
  it writes into (preferred — avoids allocating a map per line). The raw value is in scope at
  `engine.go:114` (`rawSecret`) right before `finding.New` is called at `:144`; capture
  `raw[f.Fingerprint] = rawSecret` there.
- `scanner.scanFile` / `scanner.Scan` and `gitscan.parsePatch` / `ScanHistory` / `ScanStaged`
  propagate the same map up. In `Scan`, the per-file maps merge under the existing `mu` mutex
  (same critical section that appends `allFindings`).
- `runScan` holds `rawByFingerprint` and passes it to `verify.Run` alongside `newFindings`. The
  verifier looks up `rawByFingerprint[f.Fingerprint]` to get the value to send to the API.
**Why fingerprint is a safe key:** `computeFingerprint = path:ruleID:sha256[:16](rawSecret)`
(`finding.go:computeFingerprint`) — already unique per (path, rule, secret) and collision-resistant.

**Interaction with `TestNoRawSecretInAnyField` (`finding_test.go:171`):** The test builds one
`Finding` via `New()` and reflect-walks its **exported string fields**. The side-channel map is NOT
a field of `Finding` and never reaches that test — it passes unchanged. **Add a complementary guard**
(new test) asserting the side-channel map is never marshalled and never logged (e.g. assert
`verify.Run` and output paths don't serialize the raw map; grep-style unit test that the
`Verification` struct contains no raw value).

**Interaction with the redact invariant:** The map lives only for the duration of the run, is
populated at the same trust boundary the invariant already trusts (`ScanLine`, where `finding.New`
also briefly sees the raw value), and is dropped when `runScan` returns. No new persistence, no
new serialization surface.

### Pattern 2: AWS static-credential STS call WITHOUT ambient creds
**What:** Construct the STS client directly so the default credential chain is never consulted.
**When to use:** Always — a secret scanner must NOT accidentally validate the *operator's own*
ambient AWS creds (Pitfall 4).
**Example:**
```go
// Source: pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/sts +
//         pkg.go.dev/github.com/aws/aws-sdk-go-v2/credentials (verified 2026-05-30)
import (
    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/credentials"
    "github.com/aws/aws-sdk-go-v2/service/sts"
    smithy "github.com/aws/smithy-go"
)

func (v *awsVerifier) verify(ctx context.Context, accessKeyID, secretKey string) Status {
    creds := credentials.NewStaticCredentialsProvider(accessKeyID, secretKey, "") // no session token
    client := sts.New(sts.Options{
        Region:      "aws-global",                       // resolves to sts.amazonaws.com (global endpoint)
        Credentials: aws.NewCredentialsCache(creds),
        // NB: sts.New does NOT call LoadDefaultConfig → no env/profile/IMDS chain is read.
    })
    _, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
    if err == nil {
        return Active
    }
    var apiErr smithy.APIError
    if errors.As(err, &apiErr) {
        switch apiErr.ErrorCode() {
        case "InvalidClientTokenId", "SignatureDoesNotMatch",
             "ExpiredToken", "AccessDenied", "InvalidSignatureException":
            return Inactive // definitive: AWS rejected the credential
        }
    }
    return Unknown // network/timeout/throttling/anything non-definitive
}
```
**Note on region:** `"aws-global"` is the pseudo-region the SDK resolves to the global STS endpoint
`sts.amazonaws.com`. `[VERIFIED: AWS endpoint docs]` Confidence MEDIUM on the exact pseudo-region
string — verify at implementation by asserting the resolved endpoint host in a unit test, or set
`BaseEndpoint: aws.String("https://sts.amazonaws.com")` on `sts.Options` explicitly (CONTEXT permits
"no region configuration required"; BaseEndpoint pin is the most explicit, ambient-free form).

### Pattern 3: GitHub token verification via bare net/http
**What:** Single authenticated GET; classify by status code.
**Example:**
```go
// Source: docs.github.com REST users + rate-limits (apiVersion 2022-11-28), verified 2026-05-30
func (v *githubVerifier) verify(ctx context.Context, token string) Status {
    req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
    req.Header.Set("Authorization", "Bearer "+token)            // "token "+token also valid; Bearer is current
    req.Header.Set("Accept", "application/vnd.github+json")
    req.Header.Set("X-GitHub-Api-Version", "2022-11-28")        // stable default; do NOT use a newer guessed date
    req.Header.Set("User-Agent", "mimir")                       // GitHub rejects requests with no User-Agent

    resp, err := v.client.Do(req)
    if err != nil {
        return Unknown // network / context-deadline → unknown, never inactive
    }
    defer resp.Body.Close()
    io.Copy(io.Discard, resp.Body) // drain for keep-alive; body content not needed
    switch resp.StatusCode {
    case http.StatusOK: // 200
        return Active
    case http.StatusUnauthorized: // 401 — token invalid/revoked (definitive)
        return Inactive
    case http.StatusForbidden, http.StatusTooManyRequests: // 403/429 — rate limited
        // honor Retry-After ONCE then give up → unknown (CONTEXT lock)
        if v.firstRateLimit { /* sleep min(Retry-After, cap) within ctx; retry once */ }
        return Unknown
    default:
        return Unknown
    }
}
```
**Header detail:** `User-Agent` is REQUIRED by GitHub — omitting it yields 403. `Authorization: Bearer`
is the current form (`token <pat>` still works). `X-GitHub-Api-Version: 2022-11-28` is the stable
default; omitting the header also defaults to `2022-11-28`. `[CITED: docs.github.com api-versions]`

### Anti-Patterns to Avoid
- **Storing the raw secret on `Finding`** (even unexported): keeps the raw value attached to the
  serializable type forever. Use the off-struct side channel.
- **`config.LoadDefaultConfig` for AWS:** initializes the ambient chain before static override —
  risk of resolving operator env/profile/IMDS. Use direct `sts.New`.
- **Logging the verifier's underlying error:** AWS/GitHub errors can embed request context; never
  log `err` verbatim. Carry only `{provider, sanitizedReason}` (Pitfall 1).
- **Aggressive retry loops on 403/429:** triggers secondary-rate-limit bans. Honor Retry-After once → unknown.
- **Verifying on the full finding set:** run only on `newFindings` (post-suppression) per CONTEXT.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| AWS SigV4 request signing | Custom HMAC/canonical-request signer | aws-sdk-go-v2 `sts` + static creds | SigV4 is a multi-step canonicalization spec; one mistake = false "inactive". CONTEXT-locked. |
| AWS error classification | String-matching `err.Error()` | `errors.As(&smithy.APIError)` + `ErrorCode()` | Error messages change; codes are stable contract. |
| GitHub OAuth flows | Token exchange / scopes parsing | single `GET /user`, status-only | Liveness needs only auth success/failure. |
| Rate-limit backoff scheduler | Exponential-backoff loop | honor Retry-After once → unknown | CONTEXT lock; avoids ban; keeps verify bounded-time. |
| Bounded concurrency | `chan`/`sync.WaitGroup` hand-roll | `errgroup.SetLimit(5)` | Already the repo pattern (`scanner.go:70`); first-error + ctx cancel for free. |

**Key insight:** Every "active vs inactive" decision is a security-critical classification. Hand-rolled
signing or string-matched error parsing produces *wrong* labels — worse than no label, because a
hand-rolled signing bug labels a LIVE key "inactive" and the user ignores a real leak.

## Runtime State Inventory

> Phase 4 is greenfield feature code (new package + additive fields), not a rename/refactor.

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | None — verification is in-memory only; per-secret cache is run-scoped, never persisted | none |
| Live service config | None — Mimir calls *out* to AWS/GitHub; it registers nothing on them (read-only GetCallerIdentity / GET /user) | none |
| OS-registered state | None | none |
| Secrets/env vars | None added. CRITICAL: must NOT read ambient `AWS_*` env or `~/.aws` (Pitfall 4) — direct `sts.New` avoids this | verify no ambient read (unit test) |
| Build artifacts | go.mod/go.sum gain aws-sdk-go-v2 + smithy-go entries after `go get`/`go mod tidy` | run `go mod tidy` + `go mod verify`; commit go.sum |

**Nothing found in categories 1-3:** verified — verification makes only outbound read-only calls and persists nothing.

## Common Pitfalls

### Pitfall 1: Secret leakage in verifier error messages
**What goes wrong:** An AWS/GitHub error (or a wrapped URL) embeds or echoes the credential; logging
`err` leaks it, violating OUT-03 / redact invariant.
**Why it happens:** SDK/HTTP errors include request context; `fmt.Errorf("...%w", err)` propagates it.
**How to avoid:** Verifier returns only `(Status, sanitizedErr)` where `sanitizedErr` carries
`{provider, reasonEnum}` — never the raw error, never the secret. Never put the token in a URL query.
**Warning signs:** any `fmt.Fprintln(stderr, err)` in `internal/verify`; any `%w`/`%v` of an SDK/HTTP error.

### Pitfall 2: AWS SDK reading the operator's ambient credentials
**What goes wrong:** `config.LoadDefaultConfig` resolves env/`~/.aws`/IMDS; on a misconfigured call the
client validates the *operator's* creds, not the leaked key → false "active".
**Why it happens:** LoadDefaultConfig is the documented "happy path" and most examples use it.
**How to avoid:** Construct `sts.New(sts.Options{Credentials: static, ...})` directly. Add a test that
runs with bogus `AWS_ACCESS_KEY_ID` env set and asserts the verifier still uses ONLY the passed pair.
**Warning signs:** `LoadDefaultConfig` anywhere in `internal/verify`; passing `aws.Config{}` from env.

### Pitfall 3: Rate-limit bans from retry loops
**What goes wrong:** Retrying 403/429 hammers GitHub's secondary limit → temporary IP/token ban.
**How to avoid:** Honor `Retry-After` exactly once (sleep within ctx, capped at the 5s budget), then unknown.
**Warning signs:** any loop around the HTTP call; backoff multipliers.

### Pitfall 4: Tripping the reflection guard / leaking via JSON
**What goes wrong:** Adding raw secret as a `Finding` string field fails `TestNoRawSecretInAnyField`;
adding it as an exported field with a json tag leaks it into OUT-02 output.
**How to avoid:** Side-channel map (off-struct). The new `Verification` field carries ONLY
`{status, provider}` enums — no secret. Confirm: `Verification` has no field that could hold a value.
**Warning signs:** any new exported string field on `Finding` populated from `rawSecret`.

### Pitfall 5: Breaking OUT-02 byte-identical JSON when --verify is absent
**What goes wrong:** A non-omitempty `verification` field serializes as `"verification":null` on every
finding, breaking the frozen schema and existing golden tests.
**How to avoid:** `Verification *Verification \`json:"verification,omitempty"\`` (pointer + omitempty);
nil unless `--verify` set AND the finding was verified. Mirror the existing CommitSHA omitempty pattern
(`finding.go`, `TestCommitMetaOmitempty`).
**Warning signs:** `verification` appears in JSON of a plain `mimir scan` (no `--verify`).

### Pitfall 6: Pre-commit hook accidentally going online
**What goes wrong:** The installed hook gains a network call → slow commits, offline-commit failures,
leaked-key API calls from a dev machine.
**Why it happens:** Hook template change, or `--verify` defaulting on.
**How to avoid:** `--verify` defaults false; hook installer template (Phase 3) must never emit it.
Add a test asserting the generated hook command string does NOT contain `--verify`.
**Warning signs:** `--verify` in the hook template; any network attempt under `--staged` without `--verify`.

### Pitfall 7: AWS secret-key pairing false-negatives
**What goes wrong:** The finding only has the access-key-ID; the matching `aws_secret_access_key`
isn't found in the same file → labelled unknown even when both are present (e.g. different files,
or non-standard variable name).
**Why it happens:** There is **no AWS-secret rule in the ruleset** (confirmed — secret keys are
40-char base64, not pattern-distinguishable), so the verifier must re-scan the finding's file itself.
**How to avoid:** Best-effort per CONTEXT: re-read the finding's `File`, regex for a 40-char base64
value (`[A-Za-z0-9/+]{40}`) co-located (same file, ideally near an `aws_secret_access_key` /
`secret_access_key` / `aws.*secret` token). If none → unknown (documented, acceptable).
**Warning signs:** treating "no secret found" as inactive (must be unknown).

## Code Examples

### Verifier interface + registry + three-state enum
```go
// internal/verify/verify.go
type Status string
const ( Active Status = "active"; Inactive Status = "inactive"; Unknown Status = "unknown" )

type Verifier interface {
    Provider() string                                   // "aws" | "github"
    // Verify uses the RAW secret transiently; it MUST NOT log or return the secret.
    Verify(ctx context.Context, raw string, f finding.Finding) Status
}

// registry maps detection rule IDs → Verifier.
var registry = map[string]Verifier{
    "aws-access-token":          awsV,
    "github-pat":                ghV,
    "github-oauth":              ghV,
    "github-app-token":          ghV,
    "github-refresh-token":      ghV,
    "github-fine-grained-pat":   ghV,
}
```
**Rule IDs verified in `config/mimir.toml`:** `aws-access-token` (line 27), `github-pat` (50),
`github-oauth` (57), `github-app-token` (64, ghu/ghs), `github-refresh-token` (71),
`github-fine-grained-pat` (78). Note `gitlab-*`, `slack-*`, `gcp-api-key`, `stripe-access-token`
have NO verifier in v1 → left unlabeled (CONTEXT lock). `[VERIFIED: config/mimir.toml]`

### Per-secret cache + bounded fan-out
```go
// internal/verify/verify.go — Run is called from runScan on newFindings.
func Run(ctx context.Context, findings []finding.Finding, rawByFP map[string]string) {
    type res struct{ idx int; status Status }
    cache := map[string]Status{} // key: raw secret value; run-scoped, in-memory only
    var mu sync.Mutex
    g, ctx := errgroup.WithContext(ctx)
    g.SetLimit(5) // small, polite to provider APIs (CONTEXT)
    for i := range findings {
        v, ok := registry[findings[i].RuleID]
        if !ok { continue } // unlabeled
        raw, ok := rawByFP[findings[i].Fingerprint]
        if !ok || raw == "" { setUnknown(&findings[i], v.Provider()); continue }
        i, v, raw := i, v, raw
        g.Go(func() error {
            mu.Lock(); st, cached := cache[raw]; mu.Unlock()
            if !cached {
                cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
                st = v.Verify(cctx, raw, findings[i]); cancel()
                mu.Lock(); cache[raw] = st; mu.Unlock()
            }
            findings[i].Verification = &finding.Verification{Status: string(st), Provider: v.Provider()}
            return nil
        })
    }
    _ = g.Wait() // verification never errors the scan (label-only)
}
```

### Additive Finding field (omitempty, no secret)
```go
// internal/finding/finding.go — NEW, additive. Mirrors CommitSHA omitempty discipline.
type Verification struct {
    Status   string `json:"status"`   // "active" | "inactive" | "unknown"
    Provider string `json:"provider"` // "aws" | "github"
}
// add to Finding:
//   Verification *Verification `json:"verification,omitempty"`
// Pointer + omitempty → nil unless --verify ran AND a verifier matched → OUT-02 byte-identical otherwise.
// Carries only two enums; TestNoRawSecretInAnyField only checks String fields, and this is a
// pointer field → unaffected. Add a focused test: nil-by-default omits "verification" from JSON.
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| aws-sdk-go v1 `session.New` + `sts.New` | aws-sdk-go-v2 modular `sts.New(sts.Options{})` | v2 GA (2021) | Per-service module; smaller binary; CONTEXT-locked v2 |
| Custom `EndpointResolver` | `BaseEndpoint` / `EndpointResolverV2` | aws-sdk-go-v2 ~2023 | Set `BaseEndpoint` for explicit global STS host |
| `awserr.Error` type asserts | `errors.As(&smithy.APIError)` + `ErrorCode()` | aws-sdk-go-v2 | smithy-go is the v2 error contract |
| GitHub `Authorization: token <pat>` | `Authorization: Bearer <pat>` | GitHub REST (both still valid) | Use Bearer; token form remains accepted |

**Deprecated/outdated:**
- aws-sdk-go **v1** (end-of-support) — do not use; v2 only.
- Guessing a "newer" `X-GitHub-Api-Version` date — use the stable `2022-11-28` (also the omit-default).

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `Region: "aws-global"` resolves to `sts.amazonaws.com` global endpoint | Pattern 2 | Wrong endpoint → all AWS verifies fail (unknown). Mitigation: pin `BaseEndpoint: "https://sts.amazonaws.com"` explicitly. MEDIUM. |
| A2 | AWS returns `InvalidClientTokenId` / `SignatureDoesNotMatch` for bad key/secret (definitive inactive) | AWS verification | If a different code is returned, a dead key shows unknown not inactive (degrades gracefully — unknown is the safe default). MEDIUM. |
| A3 | GitHub `GET /user` returns exactly 401 for revoked/invalid tokens (not 403) | GitHub verification | A 403-on-invalid would be classed unknown not inactive (safe degrade). 401 is documented. LOW risk. |
| A4 | `aws_secret_access_key` is co-located in the same file as the access-key-ID often enough to be useful | Pitfall 7 | If rarely co-located, most AWS findings show unknown — acceptable per CONTEXT best-effort. MEDIUM. |
| A5 | Adding a pointer `*Verification` field doesn't perturb existing golden/JSON tests when nil | Pitfall 5 | If a golden test serializes the zero struct, output diff. Mitigation: pointer+omitempty + a dedicated nil-omit test. LOW. |

## Open Questions

1. **Exact global-STS configuration form.**
   - Known: CONTEXT says global endpoint, no region config required; `aws-global` pseudo-region and explicit `BaseEndpoint` both target `sts.amazonaws.com`.
   - Unclear: which the planner should mandate.
   - Recommendation: set `BaseEndpoint: aws.String("https://sts.amazonaws.com")` AND a region (any, e.g. `"aws-global"`) — most explicit, ambient-free; assert resolved host in a test.

2. **AWS secret-key pairing scope.**
   - Known: best-effort, same file (CONTEXT).
   - Unclear: proximity window (same line? whole file? near the access key?).
   - Recommendation: whole-file scan for `[A-Za-z0-9/+]{40}` preferring a match near an `aws.*secret`/`secret_access_key` assignment; if multiple, pick nearest by line distance; if none → unknown.

3. **Caching across providers when the same string matches two rule types.**
   - Known: cache keyed by secret value.
   - Recommendation: key the cache by `(provider, secret)` not secret alone, so an unlikely cross-provider value collision can't cross-contaminate a status.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Go toolchain | build/test | ✓ | go1.26.2 (go.mod floor 1.25) | — |
| git binary | history/staged scan (existing) | ✓ | /usr/bin/git | — |
| Network egress to sts.amazonaws.com | AWS verify (runtime, opt-in) | n/a (runtime) | — | call times out → unknown (by design) |
| Network egress to api.github.com | GitHub verify (runtime, opt-in) | n/a (runtime) | — | call times out → unknown (by design) |
| aws-sdk-go-v2 modules | AWS verifier | ✗ (not yet in go.mod) | to add (sts v1.42.3 etc.) | `go get` adds them; verify with `go mod verify` |

**Missing dependencies with no fallback:** none (network is intentionally fallible → unknown).
**Missing dependencies with fallback:** aws-sdk-go-v2 modules — added via `go get` at plan execution.

## Validation Architecture

> nyquist_validation = true (`.planning/config.json`) — section included.

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Go stdlib `testing` + `stretchr/testify` v1.11.1 (already used) |
| Config file | none (standard `go test`) |
| Quick run command | `/usr/local/go/bin/go test ./internal/verify/... -run TestX -count=1` |
| Full suite command | `/usr/local/go/bin/go test -race ./... -count=1` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| VERIFY-01 | `--verify` off by default; no network without it | integration | `go test ./cmd/... -run TestScanNoVerifyNoNetwork` | ❌ Wave 0 |
| VERIFY-01 | hook template never contains `--verify` | unit | `go test ./internal/... -run TestHookOffline` | ❌ Wave 0 |
| VERIFY-02 | AWS error-code → status mapping (active/inactive/unknown) | unit (table) | `go test ./internal/verify -run TestAWSClassify` | ❌ Wave 0 |
| VERIFY-02 | GitHub 200/401/403+RetryAfter/timeout → status | unit (httptest) | `go test ./internal/verify -run TestGitHubClassify` | ❌ Wave 0 |
| VERIFY-02 | registry maps rule IDs → correct verifier; non-AWS/GH unlabeled | unit | `go test ./internal/verify -run TestRegistry` | ❌ Wave 0 |
| VERIFY-03 | per-secret cache verifies one value once | unit | `go test ./internal/verify -run TestCacheDedup` | ❌ Wave 0 |
| VERIFY-03 | Retry-After honored once then unknown | unit (httptest) | `go test ./internal/verify -run TestRetryAfterOnce` | ❌ Wave 0 |
| VERIFY-03 | secret never appears in any verifier error/log | unit | `go test ./internal/verify -run TestNoSecretInError` | ❌ Wave 0 |
| (carry) | side-channel raw never on Finding / JSON | unit | `go test ./internal/finding -run TestNoRawSecretInAnyField` (existing, must still pass) | ✅ |
| (schema) | non-verify JSON byte-identical (verification omitted) | unit | `go test ./internal/output -run TestVerifyOmittedByDefault` | ❌ Wave 0 |
| (ambient) | AWS verifier ignores ambient `AWS_*` env | unit | `go test ./internal/verify -run TestNoAmbientCreds` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `/usr/local/go/bin/go test ./internal/verify/... -count=1`
- **Per wave merge:** `/usr/local/go/bin/go test -race ./... -count=1`
- **Phase gate:** full `-race` suite green + `go vet` + golangci-lint (gosec) before `/gsd-verify-work`.

### Wave 0 Gaps
- [ ] `internal/verify/verify_test.go` — registry, cache dedup, three-state, no-secret-in-error (VERIFY-02/03)
- [ ] `internal/verify/aws_test.go` — error-code→status table; no-ambient-creds test (VERIFY-02; Pitfall 2)
- [ ] `internal/verify/github_test.go` — httptest 200/401/403+Retry-After/timeout; Retry-After-once (VERIFY-02/03)
- [ ] `cmd/mimir/*verify_test.go` — `--verify` off-by-default no-network; OUT-02 omit-default (VERIFY-01; Pitfall 5)
- [ ] hook-offline test in the existing hook-installer test file (VERIFY-01; Pitfall 6)
- [ ] No new framework install — testify already present.

## Security Domain

> security_enforcement absent in config ⇒ enabled. Section included.

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | yes (we *test* others' creds) | Read-only liveness calls only; never store/forward the credential |
| V6 Cryptography | yes | AWS SigV4 via SDK (never hand-rolled); TLS to both APIs (default `net/http` + SDK) |
| V7 Error Handling & Logging | yes | Sanitized verifier errors — `{provider, reason}` only; secret never logged (OUT-03) |
| V9 Communications | yes | HTTPS only (`https://api.github.com`, `https://sts.amazonaws.com`); 5s timeouts |
| V5 Input Validation | partial | Re-scan of finding file for secret-key uses RE2 (bounded); cap file read size |
| V3 Session Management | no | Stateless single calls |
| V4 Access Control | no | No local authz surface added |

### Known Threat Patterns for {Go secret-verifier with network egress}

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Secret value leaked via error/log | Information Disclosure | Sanitized error type carrying provider+reason enum only; no `%w` of SDK/HTTP errors |
| Verifier validates operator's ambient creds (false active) | Spoofing/Tampering | Direct `sts.New` with static creds; no LoadDefaultConfig; ambient-ignored test |
| Token echoed in a request URL/referrer | Information Disclosure | Token only in `Authorization` header, never in URL/query |
| Rate-limit ban / DoS-self | Denial of Service | errgroup limit 5; Retry-After once then unknown; 5s timeout per call |
| Pre-commit hook silently goes online | Tampering (scope creep) | `--verify` default false; hook template asserted offline |
| Malicious repo content as "credential" triggering SSRF-ish call | Tampering | Only fixed hosts (api.github.com / sts.amazonaws.com); secret is payload not URL |
| Side-channel raw map serialized/persisted | Information Disclosure | Map is off-struct, run-scoped, never marshalled; complementary guard test |

## Sources

### Primary (HIGH confidence)
- Codebase (graphmind + Read): `internal/detect/engine.go` (ScanLine, rawSecret@114, finding.New@144), `internal/finding/finding.go` (New, computeFingerprint, redact), `internal/finding/finding_test.go` (TestNoRawSecretInAnyField@171, TestCommitMetaOmitempty), `internal/scanner/scanner.go` (Scan errgroup@70, scanFile), `internal/gitscan/parse.go` (parsePatch, attachCommitMeta), `cmd/mimir/scan.go` (runScan pipeline, newFindings@150), `internal/output/{json,human}.go`, `config/mimir.toml` (rule IDs), `go.mod`.
- Go module proxy (`proxy.golang.org`, 2026-05-29): aws-sdk-go-v2/service/sts v1.42.3, credentials v1.19.19, config v1.32.20, root v1.41.9, smithy-go v1.26.0.
- pkg.go.dev — aws-sdk-go-v2/credentials (`NewStaticCredentialsProvider`), service/sts (`GetCallerIdentity`, Options Region/Credentials/BaseEndpoint).
- docs.github.com — REST users `GET /user` (200/401), rate-limits (x-ratelimit-*, Retry-After, 403/429), api-versions (`2022-11-28` stable + omit-default).

### Secondary (MEDIUM confidence)
- AWS SDK Go v2 docs (configure-endpoints, handle-errors) + repo discussions — smithy `errors.As`/`ErrorCode`, direct client construction bypassing LoadDefaultConfig, BaseEndpoint usage.
- CLAUDE.md recommended-stack table (aws-sdk-go-v2 modular config/credentials/sts; bare net/http for GitHub; Verifier interface).

### Tertiary (LOW confidence)
- WebSearch snippets on `InvalidClientTokenId` HTTP 403 / classification — corroborated against AWS error docs; treat exact error-code list as a starting set to confirm at implementation.

## Metadata

**Confidence breakdown:**
- Carry mechanism: HIGH — derived directly from the actual reflection test + the single rawSecret site.
- Standard stack/versions: HIGH — verified on Go proxy 2026-05-29; first-party AWS org.
- AWS API shape: HIGH (NewStaticCredentialsProvider, GetCallerIdentity); MEDIUM on exact global-endpoint string + full error-code list (A1/A2).
- GitHub API: HIGH (status codes, headers, version, rate-limit headers from official docs).
- Pitfalls/security: HIGH — grounded in existing invariants (OUT-03, redact-at-boundary, hook-offline).

**Research date:** 2026-05-30
**Valid until:** 2026-06-29 (AWS SDK modules move weekly — re-pin versions at execution; API shapes stable)
