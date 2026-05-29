// Package suppress owns Mimir's false-positive suppression mechanisms.
//
// It centralizes the three layers that decide whether a detected finding is
// withheld from the report (per decisions D-01..D-10):
//
//   - the inline-directive matcher (mimir:ignore / mimir:allow comments),
//   - the path matcher (.mimirignore globs plus the built-in default-exclude
//     globs such as vendor/, node_modules/, *.min.js, lockfiles), and
//   - the baseline OR-match filter (suppress a finding whose full fingerprint
//     OR whose path-independent content key matches a baseline entry).
//
// Load-bearing decoupling constraint (do not violate): the baseline filter runs
// as a SINGLE post-`g.Wait()` stage in the scanner pipeline — it is NOT executed
// inside the per-file goroutine. Keeping it as one sequential stage after the
// concurrent walk completes means Phase 4 live-verification can slot into the
// exact same pipeline position without re-architecting the worker pool.
package suppress
