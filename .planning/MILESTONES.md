# Milestones

## v1.0 MVP (Shipped: 2026-05-30)

**Phases completed:** 4 phases, 13 plans, 19 tasks

**Key accomplishments:**

- Go secret scanner pipeline: Aho-Corasick keyword gate + RE2 aws-access-token rule + redact-at-boundary Finding constructor + concurrent file scanner + human output formatter + exit-code contract (0/1/2)
- 18-rule v1 TOML ruleset (AWS/GCP/GitHub/GitLab/Slack/Stripe/PEM/JWT/generic-entropy/connection-string) with keyword-gated entropy detection, SecretGroup=3 password extraction, and zero false positives on clean fixtures
- LoadConfig with three-level precedence + extend model, JSON output with stable fingerprinted schema, all D-14 CLI flags wired, and OUT-03 self-scan test completing the full v1 feature set
- `mimir scan --git` streams current-branch `git log -p` through go-gitdiff into the existing detection engine, finding secrets added in past commits (incl. added-then-deleted) with commit provenance, fingerprint dedup, and a short-SHA one-liner — OUT-02 byte-identical for non-history scans.
- `mimir scan --staged` streams the `git diff --staged` patch through Plan 01's shared parse loop to find secrets in what is about to be committed — honoring inline `// mimir:ignore`, attaching no commit metadata (OUT-02 stable), mutually exclusive with `--git` (exit 2), and backed by a criterion-2 benchmark gate proving history-scan memory is streaming-bounded.
- `mimir hook install/uninstall/status` writes a managed, offline, staged-only pre-commit hook that blocks any commit containing a staged secret (IFACE-03) — resolving the hook dir via `git rev-parse --git-path hooks`, refusing to clobber a foreign hook without `--force` (D-05), honoring an honest bypass (`--no-verify` + `git config hooks.mimir false`, D-06), and shipping a `.pre-commit-hooks.yaml` manifest (D-07) plus README docs.
- 1. [Rule 2 / lean-binary] `aws-sdk-go-v2/config` module intentionally NOT added.
- `mimir scan --verify` (off by default) now live-labels each reportable AWS/GitHub finding ACTIVE/INACTIVE/UNKNOWN in human + JSON output, strictly label-only (exit codes untouched), with zero network and byte-identical OUT-02 JSON when the flag is absent — and the pre-commit hook stays provably offline.

---
