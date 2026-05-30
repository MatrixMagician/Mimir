// Package gitscan provides git-aware secret sources for Mimir. It shells out to
// the system git binary, streams the unified-diff patch through go-gitdiff, and
// feeds each added line to the existing detection engine — reusing the redact,
// fingerprint, suppression, and exit-code contract from the working-tree path
// unchanged. git (>= 2.x) is a runtime prerequisite for these modes.
package gitscan

import (
	"context"
	"fmt"
	"sort"

	"github.com/MatrixMagician/mimir/internal/detect"
	"github.com/MatrixMagician/mimir/internal/finding"
	"github.com/MatrixMagician/mimir/internal/scanner"
)

// ScanHistory scans the current-branch git history of repoRoot for secrets,
// including secrets that were added in a past commit and later deleted (SCAN-03
// criterion 1). It streams `git log -p -U0 --full-history --no-color` through
// go-gitdiff, scans each added line with engine, attaches commit provenance
// (D-08), dedups by content fingerprint (D-09), and returns findings sorted
// deterministically.
//
// It returns a non-nil error — surfaced by runScan as exit 2 — when git is
// absent or repoRoot is not a git repository (Pitfall 4: never silently report
// "clean"). The engine is reused as-is (stateless, goroutine-safe); no new
// engine is constructed here.
func ScanHistory(ctx context.Context, engine *detect.Engine, repoRoot string, showSuppressed bool) ([]finding.Finding, scanner.Stats, error) {
	cmd, stdout, err := startGit(ctx, historyArgs(repoRoot))
	if err != nil {
		return nil, scanner.Stats{}, err
	}
	// Always reap the git process. parsePatch drains stdout fully (ranging the
	// go-gitdiff channel to completion), so Wait will not block on an unread
	// pipe (Pitfall 2).
	defer func() { _ = cmd.Wait() }()

	findings, suppressed, parseErr := parsePatch(stdout, engine, showSuppressed)
	if parseErr != nil {
		// Reap before returning so a parse failure does not leak the process.
		_ = cmd.Wait()
		return nil, scanner.Stats{}, fmt.Errorf("parsing git history patch: %w", parseErr)
	}

	// Fail loud on a non-zero git exit (e.g. repoRoot is not a git repo). We must
	// Wait() explicitly here to read the exit status; the deferred Wait then
	// becomes a harmless no-op.
	if waitErr := cmd.Wait(); waitErr != nil {
		return nil, scanner.Stats{}, fmt.Errorf("git history scan failed (is %q a git repository?): %w", repoRoot, waitErr)
	}

	deduped := dedupByFingerprint(findings)

	// Deterministic order: File → Line → Column (mirrors scanner.Scan so output
	// and baselines stay diff-stable across modes).
	sort.Slice(deduped, func(i, j int) bool {
		if deduped[i].File != deduped[j].File {
			return deduped[i].File < deduped[j].File
		}
		if deduped[i].Line != deduped[j].Line {
			return deduped[i].Line < deduped[j].Line
		}
		return deduped[i].Column < deduped[j].Column
	})

	stats := scanner.Stats{
		FilesScanned: len(deduped),
		Suppressed:   suppressed,
	}
	return deduped, stats, nil
}

// ScanStaged scans the staged diff of repoRoot (`git diff --staged`) for secrets
// — the source the pre-commit hook invokes (SCAN-04, criterion 3). It streams the
// patch through the SAME parse loop as ScanHistory (parsePatch: gitdiff.Parse →
// OpAdd → engine.ScanLine → inline-ignore), so inline `// mimir:ignore` is honored
// on staged lines exactly as in the working-tree scanner.
//
// Staged diffs carry no commit preamble, so every PatchHeader is empty and
// attachCommitMeta (Pitfall 5) leaves the omitempty commit fields unset — staged
// findings therefore have an empty CommitSHA and OUT-02 stays byte-identical for
// non-history scans. There is no cross-commit dedup (a single diff), but the
// content-fingerprint dedup is reused unchanged: it is a no-op for distinct
// secrets and harmlessly collapses an exact-duplicate staged line.
//
// Like ScanHistory it fails loud (non-nil error → exit 2) when git is absent or
// repoRoot is not a git repository (Pitfall 4), never silently reporting "clean".
func ScanStaged(ctx context.Context, engine *detect.Engine, repoRoot string, showSuppressed bool) ([]finding.Finding, scanner.Stats, error) {
	cmd, stdout, err := startGit(ctx, stagedArgs(repoRoot))
	if err != nil {
		return nil, scanner.Stats{}, err
	}
	// Always reap the git process. parsePatch drains stdout fully, so Wait will
	// not block on an unread pipe (Pitfall 2).
	defer func() { _ = cmd.Wait() }()

	findings, suppressed, parseErr := parsePatch(stdout, engine, showSuppressed)
	if parseErr != nil {
		_ = cmd.Wait()
		return nil, scanner.Stats{}, fmt.Errorf("parsing staged diff patch: %w", parseErr)
	}

	// Fail loud on a non-zero git exit (e.g. repoRoot is not a git repo).
	if waitErr := cmd.Wait(); waitErr != nil {
		return nil, scanner.Stats{}, fmt.Errorf("git staged scan failed (is %q a git repository?): %w", repoRoot, waitErr)
	}

	deduped := dedupByFingerprint(findings)

	// Deterministic order: File → Line → Column (mirrors ScanHistory/scanner.Scan).
	sort.Slice(deduped, func(i, j int) bool {
		if deduped[i].File != deduped[j].File {
			return deduped[i].File < deduped[j].File
		}
		if deduped[i].Line != deduped[j].Line {
			return deduped[i].Line < deduped[j].Line
		}
		return deduped[i].Column < deduped[j].Column
	})

	stats := scanner.Stats{
		FilesScanned: len(deduped),
		Suppressed:   suppressed,
	}
	return deduped, stats, nil
}

// dedupByFingerprint collapses occurrences of the same secret (same content
// fingerprint) into a single finding (Pitfall 3 / D-09). A secret added in one
// commit and re-touched in a later commit appears as an added line in both
// patches; the content-based fingerprint makes those one entry.
//
// When duplicates carry commit metadata, the earliest-introducing commit is
// kept (oldest CommitDate, which is RFC3339 and therefore lexicographically
// sortable) so the human one-liner attributes the leak to where it first
// appeared (RESEARCH A3 / D-10). Insertion order is otherwise preserved.
func dedupByFingerprint(findings []finding.Finding) []finding.Finding {
	index := make(map[string]int, len(findings))
	out := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		if pos, seen := index[f.Fingerprint]; seen {
			// Prefer the earlier commit's metadata. Non-empty dates compare
			// lexicographically thanks to RFC3339; an empty incoming date never
			// displaces an existing one.
			if f.CommitDate != "" && (out[pos].CommitDate == "" || f.CommitDate < out[pos].CommitDate) {
				// Carry the earlier commit's LOCATION together with its provenance
				// (WR-01): the printed "file:line @ sha" must take its line number
				// and its SHA from the same commit, or the D-10 jump-link points at
				// an unrelated line. git log -p is newest-first, so the first-seen
				// occurrence's Line/Column belong to a later commit than this one.
				out[pos].Line = f.Line
				out[pos].Column = f.Column
				out[pos].CommitSHA = f.CommitSHA
				out[pos].CommitAuthor = f.CommitAuthor
				out[pos].CommitDate = f.CommitDate
			}
			continue
		}
		index[f.Fingerprint] = len(out)
		out = append(out, f)
	}
	return out
}
