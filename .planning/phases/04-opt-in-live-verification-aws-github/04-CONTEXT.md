# Phase 4: Opt-in Live Verification (AWS + GitHub) - Context

**Gathered:** 2026-05-30
**Status:** Ready for planning

<domain>
## Phase Boundary

This phase adds an opt-in `--verify` capability that live-checks whether detected
AWS and GitHub credentials are actually active, labelling each verifiable finding
`active` / `inactive` / `unknown`. It runs only on the post-suppression (reportable)
finding set, makes read-only API calls (AWS STS `GetCallerIdentity`, GitHub
`GET /user`), and is **off by default** with **no network calls** unless `--verify`
is passed. The detection engine is NOT modified. Security invariant (redact-at-boundary)
is preserved — the raw secret value is used only transiently to make the call and
never appears in any log, error, or exported field.

In scope: `--verify` flag, AWS + GitHub verifiers, three-state labelling, per-secret
cache, rate-limit backoff, per-call timeout, output (human + JSON) representation of
status.

Out of scope: changes to detection rules/engine; additional providers beyond AWS/GitHub;
GitHub Enterprise / custom base URLs; verification in the installed pre-commit hook.

</domain>

<decisions>
## Implementation Decisions

### CLI & Exit Semantics
- `--verify` is **label-only** — it does NOT change exit codes. New (non-suppressed)
  findings still exit 1 regardless of active/inactive/unknown status; exit contract
  (0 clean / 1 findings / 2 error) is unchanged.
- `--verify` is allowed for manual `--staged` runs, but the **installed pre-commit hook
  never passes `--verify`** — the hook stays fully offline (per success criteria).
- Findings with no matching verifier (not AWS/GitHub rule types) are **silently left
  unlabeled** (status omitted) — only verifiable rule types receive a status.
- **No pre-flight network/connectivity check** — each call simply times out and yields
  `unknown` on failure (network failure = unknown, never inactive).

### AWS/GitHub Verification Mechanics
- AWS access-key-ID → secret-access-key pairing is **best-effort**: scan the same file
  for a co-located `aws_secret_access_key`; if no secret key is found, the finding is
  labelled `unknown` (cannot call STS without the pair).
- AWS client uses **aws-sdk-go-v2 minimal modules** (`config` + `credentials` + `sts`) —
  SigV4 signing is too error-prone to hand-roll. Use the global STS endpoint
  (`sts.amazonaws.com`); no region configuration required.
- GitHub client uses **bare `net/http`** to `api.github.com/user` — a single read-only
  call, keeping the binary lean (per CLAUDE.md lean-binary constraint). No go-github SDK.
- **GitHub Enterprise / custom base URL is deferred to v2** — `api.github.com` only.

### Output Representation
- JSON uses a **nested object**: `"verification": {"status": "active|inactive|unknown",
  "provider": "aws|github"}`, with `omitempty` so non-`--verify` scans stay byte-identical
  to the existing OUT-02 schema.
- Human output shows a **colored tag** next to each verified finding: `ACTIVE` (red/bold),
  `INACTIVE` (dim), `UNKNOWN` (yellow) — honoring `NO_COLOR` and non-TTY detection.
- Under `--verify`, add a **one-line summary tally**: `Verified: N active, M inactive,
  K unknown`.
- **No reordering** of findings — existing sort order is kept; status is conveyed by the
  colored tag.

### Safety & Concurrency Controls
- Per-call timeout default: **5 seconds** (`context.WithTimeout` per verification call).
- Rate-limit / 429 handling: **honor `Retry-After` once, then mark `unknown`** — no
  aggressive retry loop (avoids lockouts/bans per success criteria).
- Concurrency: **bounded worker pool via `errgroup.SetLimit`** (reuse the existing
  scanner concurrency pattern) with a small limit (~5) to avoid hammering provider APIs.
- A **`Verifier` interface** (`Verify(ctx, secret) (status, error)`) lives in a new
  `internal/verify` package, with a registry keyed by rule ID so providers are pluggable
  (per CLAUDE.md guidance, anticipating v2 expansion).
- **Per-secret cache**: a secret appearing in many findings is verified at most once,
  keyed by the distinct secret value (held only in-memory during the run).

### Claude's Discretion
- Exact internal package layout, type names, and cache key derivation.
- How the transient raw secret is carried from detection to the verifier without violating
  the redact-at-boundary invariant or the `TestNoRawSecretInAnyField` reflection guard —
  to be settled during plan-phase research (e.g., a parallel non-serialized side channel
  keyed by fingerprint, populated where the raw value still exists, never marshalled).
- Precise wording/format of the human tag and summary line.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `internal/finding/finding.go` — `Finding` struct (redact-at-boundary invariant;
  `TestNoRawSecretInAnyField` reflection guard). A new `omitempty` verification field
  will be added here; the raw secret must NOT be stored in any exported field.
- `cmd/mimir/scan.go` `runScan` — the pipeline already reserves a **post-suppression
  stage** (after baseline marking, where `newFindings` is computed). The verification
  step slots in there, operating on the reportable set before output.
- `internal/output/json.go` `WriteJSON` and `internal/output/human.go` `WriteHuman` —
  the two render paths where the status tag / JSON field are added.
- Existing bounded-concurrency pattern in the scanner (errgroup) — reuse for verification.

### Established Patterns
- Redact-at-boundary: raw secret used only transiently inside `finding.New`; never stored.
- Fail-loud on misuse → `os.Exit(2)` (e.g., `--git` + `--staged` mutual exclusion).
- CLI flags registered in `scan.go` `init()`; runtime flags override config-file values.
- Three-state and "network failure = unknown" semantics are pinned by success criteria.

### Integration Points
- New flag `--verify` registered in `cmd/mimir/scan.go` `init()`.
- New package `internal/verify` (Verifier interface + AWS/GitHub implementations + cache).
- Verification invoked in `runScan` after suppression/baseline, before output rendering.
- Output additions in `internal/output/{json,human}.go`.

</code_context>

<specifics>
## Specific Ideas

- Map verifiers to findings by **rule ID** (AWS access key rule → AWS verifier; GitHub
  token rule → GitHub verifier). Rule IDs come from the detection engine's ruleset.
- The secret value must **never** appear in any log or error — verifier errors must be
  sanitized (carry provider + sanitized reason only), consistent with the redact invariant.

</specifics>

<deferred>
## Deferred Ideas

- Additional providers beyond AWS/GitHub (GCP, Slack, etc.) — v2.
- GitHub Enterprise / custom base URL support (`--github-base-url`) — v2.
- Configurable `--verify-timeout` flag — v2 (fixed 5s default for v1).
- `--fail-on-verified` exit-code mode — v2 (v1 keeps verification label-only).

</deferred>
