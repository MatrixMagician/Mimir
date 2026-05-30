---
phase: 02-false-positive-control
plan: 04
status: complete
wave: 4
requirements: [SUP-03]
---

## Summary

Delivered the baseline vertical slice plus the cross-cutting transparency layer:
`--baseline-out` snapshots reportable findings, `--baseline` alerts only on NEW
ones, a baselined finding survives file move + blank-line shift via OR-match
(criterion 4), the baseline is raw-secret-free (criterion 3), suppressed
findings never flip the exit code, and `--show-suppressed` audits all reasons.

## What was built

- **Task 1** — `internal/suppress/baseline.go`: `Baseline` with full-fingerprint
  AND content-key sets; `contentKey` via `strings.LastIndex` (rule-id:hash16,
  last two segments); `LoadBaseline` (missing → empty/no-error, malformed →
  error), `WriteBaseline` (version envelope, redacted Finding schema),
  `IsBaselined` (fingerprint OR content-key — survives file move). Unit tests
  cover fingerprint match, file-move, new-finding miss, missing-file, round-trip.
- **Task 2** — `--baseline` + `--baseline-out` flags; a decoupled post-`g.Wait()`
  baseline filter in `runScan` (marks `reason=baseline`, counts D-11); `newFindings`
  (reportable set) drives the exit code so suppressed findings never fail CI
  (Pitfall 5). `--baseline-out` snapshots `newFindings` (Open Q5/A5). CLI tests:
  new-only, file-move + blank-line criterion-4 (end-to-end), exit-code, no-raw-secret.
- **Task 3** — Shared `--show-suppressed` human renderer (reason-tagged rows for
  baseline | inline-ignore | allowlist) + always-on D-11 summary breakdown;
  additive omitempty JSON `paths_excluded` + `suppressed`-by-reason in ScanSummary
  (OUT-02 preserved; `emptyToNil` keeps the default schema byte-identical).
  TestShowSuppressed asserts the baseline audit + default-omits.

## Key files

- created: `internal/suppress/baseline.go`, `internal/suppress/baseline_test.go`
- modified: `cmd/mimir/scan.go` (baseline stage, flags, exit-code), `cmd/mimir/scan_test.go`
  (6 CLI tests), `internal/output/human.go` (show-suppressed renderer + breakdown),
  `internal/output/json.go` (ScanSummary additions), `internal/output/output_test.go`
  (WriteHuman arity fix)

## Deviations

- Plan named the method `IsBaselined`; the first 02-04 commit shipped it as
  `IsSuppressed` and was renamed to match the contract. Final tree consistent.

## Self-Check: PASSED

- `go build ./...`, `go vet ./...` exit 0; `go test ./... -race` fully green.
- Criterion 3 verified (baseline contains no raw secret) and criterion 4 verified
  end-to-end (file-move + blank-line shift stay suppressed; all-baselined exits 0).
