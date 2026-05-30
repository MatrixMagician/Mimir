---
phase: 02-false-positive-control
plan: 02
status: complete
wave: 2
requirements: [SUP-01]
---

## Summary

Delivered the inline-ignore vertical slice end-to-end (scanner → output → exit
code): a developer can paste `// mimir:ignore` (blanket) or
`mimir:ignore:<rule-id>` (scoped) on a secret's line to suppress it. This plan
also owns the `--show-suppressed` flag and the scanner annotate-vs-drop branch
that makes the D-12 inline-ignore audit reachable.

## What was built

- **Task 1** — `internal/suppress/inline.go`: `InlineSuppresses(line, ruleID)`,
  a package-scope RE2 regex (compiled once) matching blanket and scoped
  `mimir:ignore` directives case-insensitively on a single line, comment-syntax
  agnostic, with a word boundary so `ignored` does not trigger. Scoped rule IDs
  compared case-sensitively. Unit table test covers blanket, scoped match,
  scoped-to-other-rule (Pitfall 3), comma lists, case-insensitivity, and the
  word-boundary edge.
- **Task 2** — Wired into `scanFile`: each inline-ignored finding is counted
  (D-11), then dropped by default or kept+annotated when `Scanner.ShowSuppressed`
  is set (D-12). Per-file counts merge under the existing mutex (race-free,
  verified with `-race`). Added the `--show-suppressed` flag (owned here) and
  threaded it into the scanner; threaded `--verbose` into `WriteHuman` to print
  the paste-ready `// mimir:ignore` hint + fingerprint (D-04). The exit code now
  counts only non-suppressed findings. CLI integration tests cover blanket drop
  (exit 0), scoped no-over-suppression (exit 1, github reported / aws hidden),
  the verbose hint, and the `--show-suppressed` JSON audit (suppressed=true,
  reason=inline-ignore, exit 0).

## Key files

- created: `internal/suppress/inline.go`, `internal/suppress/inline_test.go`
- modified: `internal/scanner/scanner.go` (ShowSuppressed field, scanFile
  annotate-vs-drop + per-file count merge), `internal/scanner/scanner_stats_test.go`
  (drop + annotate unit tests), `internal/output/human.go` (verbose hint, active
  vs suppressed split, inline-ignored summary count), `cmd/mimir/scan.go`
  (--show-suppressed flag, verbose threading, non-suppressed exit code),
  `cmd/mimir/scan_test.go` (4 CLI tests)

## Deviations

- The Plan-01 commit named the predicate `LineSuppresses`; renamed to
  `InlineSuppresses` here to match this plan's artifact/key-link contract
  (`suppress.InlineSuppresses`). Final tree is consistent.
- The human-output suppressed-row renderer is intentionally NOT implemented here
  (Plan 04 owns the shared tagged renderer); the D-12 inline-ignore audit is
  verified via JSON in this plan, as the plan permits.

## Self-Check: PASSED

- `go build ./...`, `go vet ./...` exit 0.
- `go test ./... -race` all packages ok.
- Targeted CLI tests (TestInlineIgnoreBlanket, TestInlineIgnoreScoped,
  TestVerboseHint, TestShowSuppressedInline) pass under `-race`.
- `internal/detect/engine.go` unmodified (engine remains a pure detector).
