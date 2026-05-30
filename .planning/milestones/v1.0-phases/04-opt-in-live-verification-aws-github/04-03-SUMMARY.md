---
phase: 04-opt-in-live-verification-aws-github
plan: 03
subsystem: cli/verification-wiring
tags: [verify, cli-flag, off-by-default, output-rendering, omitempty, label-only, no-network-default]
requires:
  - "finding.Verification type + Finding.Verification omitempty pointer field (Plan 04-01)"
  - "fingerprint->raw side-channel map returned by Scanner.Scan / gitscan.ScanHistory / gitscan.ScanStaged (Plan 04-01)"
  - "internal/verify.Run(ctx, findings, rawByFP) — label-only orchestrator + Status enum (Plan 04-02)"
  - "cmd/mimir black-box os/exec runMimir + TestMain harness (Phase 1)"
  - "internal/output human.go row/summary renderers + sanitizeForTTY (Phase 1-3)"
  - "pre-existing TestHookOffline guard (hook_test.go:275, Phase 3)"
provides:
  - "--verify scan flag (off by default; the ONLY switch that enables outbound calls)"
  - "verify.Run wired into runScan on the post-suppression newFindings set, before output"
  - "raw side-channel map captured from all three scan sources (was discarded with _)"
  - "human ACTIVE/INACTIVE/UNKNOWN colored tag + 'Verified: N active, M inactive, K unknown' tally"
  - "JSON nested verification object via omitempty pointer (byte-identical OUT-02 when absent)"
  - "TestScanNoVerifyNoNetwork (no flag -> no network, exit codes unchanged)"
  - "TestHumanVerificationTag / TestHumanVerifiedTally / TestVerifyOmittedByDefault"
affects:
  - "Phase 4 is the terminal wave; downstream verifier additions reuse the registry + this rendering path unchanged"
tech-stack:
  added: []
  patterns:
    - "Off-by-default capability gate: --verify defaults false; without it verify.Run is never called -> zero network + byte-identical OUT-02 JSON (no flag-touches-exit-code coupling)"
    - "Conditional row suffix mirroring the CommitSHA discipline: a nil Verification appends no suffix, keeping the pre-Phase-4 row byte-identical"
    - "Fixed-enum tag (no verifier free-string) bypasses sanitizeForTTY by construction (T-04-tty)"
key-files:
  created:
    - cmd/mimir/scan_verify_test.go
    - internal/output/human_test.go
    - internal/output/json_test.go
  modified:
    - cmd/mimir/scan.go
    - internal/output/human.go
key-decisions:
  - "--verify is strictly label-only: the exit-code block (newFindings>0 -> exit 1, errors -> exit 2, clean -> 0) is untouched; verification never flips CI status"
  - "verify.Run runs ONLY on newFindings (post-suppression reportable set), never the full findings slice (RESEARCH Anti-Pattern) — display=newFindings aliases the same backing array so labels carry into output"
  - "No mutual-exclusion / fail-loud branch added for --verify: it composes with --staged/--git for manual runs"
  - "Verification tags rendered bracketed ([ACTIVE]/[INACTIVE]/[UNKNOWN]) so they are distinct assertable substrings (a bare 'ACTIVE' matches '[INACTIVE]')"
  - "Tally line printed only when at least one finding carries a Verification (verActive+verInactive+verUnknown>0) — non-verify summary stays byte-identical"
patterns-established:
  - "Capability flag default-off as a security property: the test asserts the ABSENCE of a code path (no 'verification' key) to prove no network egress"
  - "in-place slice mutation + alias: verify.Run writes findings[i].Verification on the newFindings backing array; the later display := newFindings aliases it, so no re-plumb of the output call is needed"
requirements-completed: [VERIFY-01, VERIFY-02, VERIFY-03]
duration: 18min
completed: 2026-05-30
---

# Phase 4 Plan 03: Wire --verify End-to-End Summary

**`mimir scan --verify` (off by default) now live-labels each reportable AWS/GitHub finding ACTIVE/INACTIVE/UNKNOWN in human + JSON output, strictly label-only (exit codes untouched), with zero network and byte-identical OUT-02 JSON when the flag is absent — and the pre-commit hook stays provably offline.**

## Performance

- **Duration:** ~18 min
- **Started:** 2026-05-30T10:34Z
- **Completed:** 2026-05-30T10:52Z
- **Tasks:** 3 completed
- **Files modified:** 2 source modified, 3 test files created

## Accomplishments

- **Task 1 — flag + invocation (`cmd/mimir/scan.go`):** Registered the off-by-default `--verify` bool flag. Re-edited the three scan dispatch call sites (working-tree `s.Scan`, `gitscan.ScanHistory`, `gitscan.ScanStaged`) to **capture** the Plan 01 fingerprint→raw side-channel map (`var raw map[string]string`) instead of discarding it with `_`. Inserted `if doVerify { verify.Run(cmd.Context(), newFindings, raw) }` immediately after the post-suppression `newFindings` loop and before output — running only on the reportable set, never the full findings. The exit-code contract is left untouched (label-only). Added `TestScanNoVerifyNoNetwork`: a plain `scan -f json` over a fixture with `AKIAFAKEKEYABCDE2345` exits 1 (unchanged) and the JSON contains no `verification` substring, proving the network path never ran without the flag.
- **Task 2 — rendering (`internal/output/human.go`, JSON):** Added `verifyActiveStyle` (red+bold), `verifyInactiveStyle` (dim/FgHiBlack), `verifyUnknownStyle` (yellow) and a `verificationTag` helper. The active-finding row appends a bracketed colored tag only when `f.Verification != nil` (mirroring the CommitSHA conditional discipline so the nil path is byte-identical). Accumulated per-status counts and printed a single `Verified: N active, M inactive, K unknown` line, gated on a non-zero total. Added `TestHumanVerificationTag` (right tag per status; nil row unchanged), `TestHumanVerifiedTally` (correct counts; absent when none), and `TestVerifyOmittedByDefault` (omitempty pointer drops `verification` by default; nested `{status,provider}` emitted when set).
- **Task 3 — guard confirmation + phase gate:** Confirmed exactly one `func TestHookOffline` exists (hook_test.go:275, **not** redeclared), `cmd/mimir/hook.go` byte-unchanged, the in-line `--verify` assertion at hook_test.go:62 intact. Ran the full phase gate: `go build ./...`, `go vet ./...` (clean), and `go test -race ./... -count=1` (entire repo green). No signature-drift fixups were required — prior waves already updated all call sites to the raw-map-before-Stats return arity.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Test bug] Substring collision in verification-tag assertions**
- **Found during:** Task 2 (GREEN run)
- **Issue:** The first draft of `TestHumanVerificationTag` asserted `NotContains("ACTIVE")` for an inactive finding, but `"INACTIVE"` contains the substring `"ACTIVE"`, so the negative assertion spuriously failed against correct production output.
- **Fix:** Switched the test to assert the bracketed tags (`[ACTIVE]` / `[INACTIVE]` / `[UNKNOWN]`), which are distinct substrings. Production rendering was correct and unchanged.
- **Files modified:** internal/output/human_test.go
- **Commit:** d638a55

No production-behavior deviations. The plan executed as written otherwise.

## Authentication Gates

None. `--verify` is off by default and no live verification was exercised during execution (the no-network test asserts the absence of the network path; the verifier unit tests from Plan 04-02 cover the network classifiers without real calls).

## Known Stubs

None. The `--verify` path is fully wired end-to-end: flag → raw-map capture → `verify.Run` on `newFindings` → human/JSON rendering. Findings whose rule ID has no registered verifier are intentionally left unlabeled (Verification stays nil) per the Plan 02 contract — this is documented behavior, not a stub.

## Threat Surface Notes

`--verify` is the single switch gating outbound calls (T-04-default/T-04-hook) and remains default-false; the pre-commit hook template is byte-unchanged and still passes `TestHookOffline`. The verification tag is a fixed enum, so no verifier-sourced free-string reaches the terminal (T-04-tty). No new network endpoints, auth paths, or trust-boundary surface were introduced beyond what Plan 02 already registered — nothing outside the plan's threat_model.

## Verification Evidence

- `go build ./...` — OK
- `go vet ./...` — clean
- `go test ./cmd/... -run TestScanNoVerifyNoNetwork -count=1` — ok
- `go test ./internal/output -run 'TestHumanVerificationTag|TestHumanVerifiedTally|TestVerifyOmittedByDefault' -count=1` — ok
- `go test ./... -run TestHookOffline -count=1` — ok (single, pre-existing guard)
- `go test -race ./... -count=1` — entire repo green

## Commits

- `0e67fe3` feat(04-03): register --verify and invoke verify.Run on the post-suppression set
- `d638a55` feat(04-03): render verification tag + tally in human output; confirm JSON omit-default

## Self-Check: PASSED

All created/modified files exist on disk; both task commits resolve in git history.
