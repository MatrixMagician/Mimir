---
phase: 04-opt-in-live-verification-aws-github
plan: 01
subsystem: detection/finding-model
tags: [verification, side-channel, redact-at-boundary, finding-schema]
requires:
  - "internal/finding.New + computeFingerprint (Phase 1)"
  - "internal/detect.Engine.ScanLine (Phase 1)"
  - "internal/scanner.Scanner.Scan + gitscan.ScanHistory/ScanStaged (Phase 1)"
provides:
  - "finding.Verification type + Finding.Verification *Verification omitempty field"
  - "fingerprint->raw side-channel map emitted at ScanLine"
  - "Scanner.Scan / gitscan.ScanHistory / gitscan.ScanStaged return the raw map (before Stats)"
affects:
  - "cmd/mimir/scan.go (3 dispatch call sites discard raw with _; Plan 04-03 consumes it)"
tech-stack:
  added: []
  patterns:
    - "Off-struct side channel: raw secret carried in a run-scoped map keyed by fingerprint, never on Finding, never serialized"
    - "Pointer + omitempty for schema-stable optional nested object (mirrors CommitSHA discipline)"
key-files:
  created: []
  modified:
    - internal/finding/finding.go
    - internal/finding/finding_test.go
    - internal/detect/engine.go
    - internal/detect/engine_test.go
    - internal/scanner/scanner.go
    - internal/scanner/scanner_test.go
    - internal/scanner/scanner_stats_test.go
    - internal/gitscan/gitscan.go
    - internal/gitscan/parse.go
    - internal/gitscan/gitscan_test.go
    - internal/gitscan/bench_test.go
    - internal/output/output_test.go
    - cmd/mimir/scan.go
decisions:
  - "Raw secret carried off-struct via map[fingerprint]raw, NOT a Finding field (preserves redact-at-boundary; TestNoRawSecretInAnyField stays green)"
  - "Verification is a pointer with json omitempty so non-verify scans stay byte-identical to OUT-02"
  - "Raw map ordered BEFORE Stats in every return tuple for cross-source consistency"
metrics:
  tasks_completed: 3
  files_modified: 13
  completed: 2026-05-30
---

# Phase 4 Plan 01: Verification Field + Raw-Secret Side Channel Summary

Adds the `Finding.Verification` pointer field and threads an off-struct
`map[fingerprint]rawSecret` side channel from the one site where the raw secret
still exists (`engine.ScanLine`) out through `Scanner.Scan`,
`gitscan.ScanHistory`, and `gitscan.ScanStaged`, keeping the redact-at-boundary
invariant intact while making the raw value reachable for Wave 2 live verification.

## What Was Built

- **Task 1 — `Verification` type + field.** New exported `Verification` struct
  with exactly two non-secret enum fields (`Status`, `Provider`). Added
  `Finding.Verification *Verification` with `json:"verification,omitempty"`,
  documented like the `CommitSHA` block (populated post-`New()` by
  internal/verify in Wave 2; never enters `computeFingerprint`). `computeFingerprint`,
  `New`, and `RedactSecret` are byte-unchanged.
- **Task 2 — raw side channel through the working-tree scanner.** `ScanLine`
  now accepts a caller-provided `raw map[string]string` sink and writes
  `raw[f.Fingerprint] = rawSecret` immediately after `finding.New(...)`.
  `scanFile` allocates a per-file `fileRaw` and returns it as a new 4th value;
  `Scan` merges it into a run-level `rawByFP` inside the existing `mu` critical
  section and returns it (raw before `Stats`).
- **Task 3 — raw side channel through gitscan.** `parsePatch` builds a `raw`
  map, passes it to `engine.ScanLine`, and returns it; `ScanHistory` and
  `ScanStaged` both return `([]finding.Finding, map[string]string, scanner.Stats, error)`.
  `dedupByFingerprint` is unchanged — collapsed duplicates share the fingerprint
  key harmlessly.
- The three `cmd/mimir/scan.go` dispatch call sites discard the new raw return
  with `_` to keep `go build ./...` green; Plan 04-03 re-edits them to consume it.

## Security Invariant Verification

- The raw map is written ONLY in `ScanLine` and merged under lock; it is never
  assigned to a `Finding` field and never passed to `json.Marshal`
  (grep-confirmed: no `Marshal(...raw...)`, no Finding-field assignment).
- `TestNoRawSecretInAnyField` (the reflection guard) still passes.
- `Verification` carries only two enum strings; pointer + omitempty means
  non-verify scans omit `"verification"` from JSON (`TestVerificationOmittedByDefault`),
  keeping OUT-02 byte-identical (T-04-01/02/03 mitigations satisfied).

## Tests Added

- `TestVerificationOmittedByDefault` (finding) — nil omits, set serializes status/provider.
- `TestScanLineEmitsRawIntoSink` (detect) — raw[fingerprint]==exact secret, never on Finding.
- `TestHistoryRawSideChannel` / `TestStagedRawSideChannel` (gitscan) — deleted/staged
  secret resolvable by surviving fingerprint.

Existing detect/scanner/output/gitscan/bench call sites updated to the new signatures.

## Verification Results

- `/usr/local/go/bin/go build ./...` — succeeds.
- `/usr/local/go/bin/go test -race ./... -count=1` — all packages pass, race-clean.
- `/usr/local/go/bin/go test ./internal/finding -run TestNoRawSecretInAnyField -count=1` — passes.

## Deviations from Plan

None - plan executed exactly as written.

## TDD Gate Compliance

Each task followed RED (failing/compile-failing test commit) → GREEN (implementation
commit): `test(04-01)` then `feat(04-01)` commits exist for all three tasks. No
REFACTOR pass was needed.

## Self-Check: PASSED

- SUMMARY.md present at the plan directory.
- All six task commits (e9b16c7, 0117b4f, b7c13e5, 3a0e7c8, c6e7e3c, bfc1c98) verified in git log.
