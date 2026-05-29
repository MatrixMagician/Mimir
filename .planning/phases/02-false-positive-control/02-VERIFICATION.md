---
status: passed
phase: 02-false-positive-control
verified: 2026-05-29
method: manual-inline (gsd-execute-phase --auto, "run plans manually inline")
---

## Phase 2 — False-Positive Control: Verification

All four plans executed with atomic commits; full `go test ./... -race` suite
green (7 packages), `go build ./...` and `go vet ./...` clean.

### Requirement coverage

| Req | Capability | Evidence |
|-----|-----------|----------|
| SUP-01 | Inline `mimir:ignore` (blanket + scoped) | `internal/suppress/inline.go` `InlineSuppresses`; scanner drop-vs-annotate; CLI TestInlineIgnoreBlanket/Scoped, TestVerboseHint, TestShowSuppressedInline |
| SUP-02 | `.mimirignore` globs (`**` + `!negation`) | `internal/suppress/pathmatch.go` `PathMatcher.Excluded`; CLI TestMimirignoreNegation; unit TestPathMatch* |
| SUP-03 | Baseline snapshot — alert only on NEW | `internal/suppress/baseline.go` OR-match `IsBaselined`; CLI TestBaselineNewOnly/FileMove/BlankLineShift |
| SUP-04 | Default noisy-path excludes + master toggle | `DefaultPathExcludes`; `use_default_allowlists` toggle; `--no-default-excludes`; CLI TestDefaultExcludes/TestDefaultsToggleOff |

### Success criteria (ROADMAP)

1. **Inline + path + baseline suppression all work end-to-end** — verified via CLI tests.
2. **First-run defaults keep a dirty repo quiet** (criterion 2) — TestDefaultExcludes:
   vendor/, node_modules/, *.min.js, lockfile not reported; top-level secret reported.
3. **Baseline contains no raw secret** (criterion 3) — TestBaselineOutNoRawSecret +
   TestBaselineNoRawSecret: written baseline JSON has no raw fixture-secret substring.
4. **Baselined finding survives file move + blank-line shift** (criterion 4) — OR-match
   on content key (rule-id:hash16); TestBaselineFileMove + TestBaselineBlankLineShift exit 0.

### Cross-cutting (D-11/D-12/D-13)

- **D-11**: summary always prints suppressed-by-reason counts + paths-excluded.
- **D-12**: `--show-suppressed` re-includes all reasons (baseline | inline-ignore |
  allowlist) tagged in human + JSON; default JSON omits the omitempty fields (OUT-02 preserved).
- **D-13**: excluded paths counted (`Stats.PathsExcluded`), never enumerated as findings.
- **Exit code (IFACE-02 / Pitfall 5)**: only non-suppressed `newFindings` flip exit to 1;
  all-baselined / all-inline-ignored scans exit 0 even under `--show-suppressed`
  (TestSuppressedExitCode).

### Decoupling constraint honored

The baseline filter is a single post-`g.Wait()` stage in `runScan` (not inside the
per-file goroutine), reserving the Phase 4 live-verification slot — as documented in
`internal/suppress/doc.go`.

### Notes

- `phase complete 2` emitted a traceability warning for OUT2-*/SUP2-*/VERIFY2-* IDs;
  those are future (v2) requirements, not Phase 2 scope — expected noise.
- The mid-execution `phase complete` was run while the cmd/mimir test build was
  transiently red (missing testify imports); fixed in commits c9bbc86 + 632e066,
  after which the full -race suite is green. Verification reflects the final tree.
- Two path-toggle CLI tests (TestMimirignoreNegation, TestDefaultsToggleOff) were
  initially placed under `vendor/`, which is ALSO suppressed by the engine-level
  content-allowlist (`config/mimir.toml [[allowlists]] paths`) independent of the
  Phase 2 path-prune toggle — masking the real (working) behavior. Fixed (commit
  8266bb9) by moving those fixtures to `build/` (excluded only by the `**/build/**`
  default glob). A pathmatch glob-validation fix (edd8763) and a backslash-norm fix
  (c9bbc86) also landed. Final `go build`/`go vet`/`go test ./... -race` all green
  (7/7 packages); this record reflects the verified final tree.
