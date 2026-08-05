package gitscan

import (
	"io"
	"strings"
	"time"

	"github.com/gitleaks/go-gitdiff/gitdiff"

	"github.com/MatrixMagician/mimir/internal/detect"
	"github.com/MatrixMagician/mimir/internal/finding"
	"github.com/MatrixMagician/mimir/internal/suppress"
)

// parsePatch streams the unified-diff patch on r through go-gitdiff and scans
// every added (OpAdd) line with the detection engine. It returns the raw (not
// yet deduped or sorted) findings, a per-reason suppression count, the raw
// side-channel map, and the number of FILES the patch touched.
//
// Streaming discipline (criterion 2 / Pitfall 2): gitdiff.Parse returns a
// channel fed by an internal goroutine; ranging it lazily keeps peak memory
// bounded (independent of history length) and the caller drains it fully before
// cmd.Wait(), so the git process never blocks on an unread pipe.
//
// showSuppressed mirrors the scanner: when false an inline-ignored finding is
// dropped (but still counted); when true it is kept and annotated.
func parsePatch(r io.Reader, engine *detect.Engine, showSuppressed bool) ([]finding.Finding, map[string]int, map[string]string, int, error) {
	files, err := gitdiff.Parse(r)
	if err != nil {
		return nil, nil, nil, 0, err
	}

	var out []finding.Finding
	suppressed := map[string]int{}
	// Fingerprint→raw side channel for opt-in live verification. Written only by
	// engine.ScanLine, never stored on a Finding or serialized.
	raw := map[string]string{}
	// Distinct paths touched by the patch. A history scan revisits the same path
	// across commits, so the count is of distinct files, matching the
	// working-tree scanner's "files scanned" semantics.
	seenFiles := map[string]struct{}{}

	for f := range files {
		name := f.NewName
		if name == "" {
			name = f.OldName // pure deletion: attribute to the removed path
		}
		if name != "" {
			seenFiles[name] = struct{}{}
		}
		for _, tf := range f.TextFragments {
			if tf == nil {
				continue
			}
			// Absolute new-file line number. With -U0 there are no context
			// lines, but we still handle OpContext defensively: OpAdd/OpContext
			// advance the new-file counter, OpDelete does not (the deleted line
			// is not present in the new file).
			lineNum := int(tf.NewPosition)
			for _, l := range tf.Lines {
				switch l.Op {
				case gitdiff.OpAdd:
					// Pitfall 1: go-gitdiff preserves the trailing newline in
					// Line.Line; strip it so column math and regex anchors match
					// the working-tree scanner's behavior.
					line := strings.TrimSuffix(l.Line, "\n")
					// The diff-added line IS the source line, so the identical
					// inline-ignore check applies — shared with scanner.scanFile
					// via suppress.FilterInline (SUP-01/D-12).
					kept := suppress.FilterInline(line,
						engine.ScanLine(line, f.NewName, lineNum, raw), suppressed, showSuppressed)
					for i := range kept {
						attachCommitMeta(&kept[i], f.PatchHeader)
					}
					out = append(out, kept...)
					lineNum++
				case gitdiff.OpContext:
					lineNum++
				case gitdiff.OpDelete:
					// deleted lines are absent from the new file — do not advance
				}
			}
		}
	}

	return out, suppressed, raw, len(seenFiles), nil
}

// attachCommitMeta copies D-08 commit provenance from a patch header onto a
// finding. It only does so when the header carries a real commit SHA (Pitfall 5:
// staged diffs have no commit preamble, so their findings keep the omitempty
// fields empty and OUT-02 stays byte-identical for non-history scans). The
// commit SHA is metadata only and never enters the fingerprint (D-09).
func attachCommitMeta(f *finding.Finding, h *gitdiff.PatchHeader) {
	if h == nil || h.SHA == "" {
		return
	}
	f.CommitSHA = h.SHA
	if h.Author != nil {
		f.CommitAuthor = h.Author.Name
	}
	if !h.AuthorDate.IsZero() {
		f.CommitDate = h.AuthorDate.Format(time.RFC3339)
	}
}
