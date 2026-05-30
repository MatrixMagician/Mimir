// Package output formats scan results for human-readable and machine-readable output.
package output

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/fatih/color"

	"github.com/MatrixMagician/mimir/internal/finding"
	"github.com/MatrixMagician/mimir/internal/scanner"
)

// Color styles for human output.
var (
	sigRuleStyle = color.New(color.FgCyan)
	heuStyle     = color.New(color.FgYellow)
	warnStyle    = color.New(color.FgYellow, color.Bold)
	okStyle      = color.New(color.FgGreen, color.Bold)
)

// WriteHuman writes findings and (unless quiet is true) a scan-stats summary to w.
//
// Output format (D-01): path:line:col  rule-id  redacted-snippet
// Summary (D-02, D-14): suppressed when quiet=true.
// ANSI color is disabled when noColor=true or the NO_COLOR env var is set.
func WriteHuman(w io.Writer, findings []finding.Finding, stats scanner.Stats, noColor, quiet, verbose bool) {
	if noColor {
		color.NoColor = true
	}

	// Only NON-suppressed findings are part of the default report. Suppressed
	// findings (e.g. inline-ignore) are dropped at scan time by default; the
	// tagged --show-suppressed row renderer is owned by Plan 04.
	activeCount := 0
	activeFiles := make(map[string]struct{})
	var suppressed []finding.Finding
	for _, f := range findings {
		if f.Suppressed {
			suppressed = append(suppressed, f)
			continue
		}
		activeCount++
		activeFiles[f.File] = struct{}{}

		ruleDisplay := f.RuleID
		if f.IsHeuristic {
			ruleDisplay += " ?"
		}

		var ruleStr string
		if f.IsHeuristic {
			ruleStr = heuStyle.Sprint(ruleDisplay)
		} else {
			ruleStr = sigRuleStyle.Sprint(ruleDisplay)
		}

		// D-10: history findings carry a commit SHA — append a short SHA to the
		// location so the user can jump to the leaking commit. Working-tree and
		// staged findings have an empty CommitSHA, so the no-SHA branch is kept
		// byte-identical to the Phase 1 format (OUT-02 stability).
		if f.CommitSHA != "" {
			fmt.Fprintf(w, "%s:%d:%d @ %s  %s  %s\n",
				sanitizeForTTY(f.File), f.Line, f.Column, sanitizeForTTY(shortSHA(f.CommitSHA)), ruleStr, sanitizeForTTY(f.Secret))
		} else {
			fmt.Fprintf(w, "%s:%d:%d  %s  %s\n",
				sanitizeForTTY(f.File), f.Line, f.Column, ruleStr, sanitizeForTTY(f.Secret))
		}

		// --verbose surfaces the paste-ready suppression hint + fingerprint
		// (D-04, criterion 1) so the user knows exactly what to add. For history
		// findings it additionally surfaces the full commit author and date.
		if verbose {
			if f.CommitSHA != "" && (f.CommitAuthor != "" || f.CommitDate != "") {
				fmt.Fprintf(w, "    ↳ commit %s by %s on %s\n",
					sanitizeForTTY(f.CommitSHA), sanitizeForTTY(f.CommitAuthor), sanitizeForTTY(f.CommitDate))
			}
			fmt.Fprintf(w, "    ↳ suppress: add `// mimir:ignore` on this line · fingerprint: %s\n", sanitizeForTTY(f.Fingerprint))
		}
	}

	// --show-suppressed: render withheld findings in a reason-tagged section.
	// Suppressed findings only reach here when --show-suppressed kept them;
	// otherwise they were dropped upstream (scanner / baseline filter).
	if len(suppressed) > 0 {
		if color.NoColor {
			fmt.Fprintf(w, "\nSuppressed (informational):\n")
		} else {
			color.New(color.FgHiBlack).Fprintf(w, "\nSuppressed (informational):\n")
		}
		for _, f := range suppressed {
			fmt.Fprintf(w, "  ○ %s:%d:%d  [%s] (%s)  %s\n",
				sanitizeForTTY(f.File), f.Line, f.Column, f.RuleID, f.SuppressionReason, sanitizeForTTY(f.Secret))
		}
	}

	// Summary line (D-02): skip when --quiet is set.
	if quiet {
		return
	}

	durationStr := formatDuration(stats.Duration)
	if activeCount > 0 {
		fmt.Fprintf(w, "%s\n", warnStyle.Sprintf("⚠ %d finding(s) in %d file(s) · scanned %d files · %s",
			activeCount, len(activeFiles), stats.FilesScanned, durationStr))
	} else {
		fmt.Fprintf(w, "%s\n", okStyle.Sprintf("✓ no findings · scanned %d files · %s",
			stats.FilesScanned, durationStr))
	}
	// D-11 transparency: always report suppression counts by reason when non-zero.
	for _, reason := range []string{"inline-ignore", "allowlist", "baseline"} {
		if n := stats.Suppressed[reason]; n > 0 {
			fmt.Fprintf(w, "  (%d %s)\n", n, reason)
		}
	}
}

// shortSHA returns the conventional 7-character abbreviation of a git commit
// SHA, or the whole value when it is shorter (length-guarded so a malformed or
// truncated SHA never panics).
func shortSHA(sha string) string {
	if len(sha) <= 7 {
		return sha
	}
	return sha[:7]
}

// sanitizeForTTY strips terminal-control bytes from strings that originate from
// untrusted repository data — git commit metadata (author, SHA, date),
// diff-sourced file paths, and the redacted secret snippet — before they are
// written to a terminal. A crafted commit author name, file path, or matched
// line can embed ANSI escape sequences or carriage returns; emitting them raw
// would let scanned repo content rewrite the user's terminal or forge output
// (terminal-escape / log-injection, T-03-03). ESC, DEL, and C0 control chars
// (except tab) are replaced with the Unicode replacement rune. The result is
// length-capped to bound oversized single-line ANSI payloads. For well-formed
// input (no control bytes, under the cap) the string is returned unchanged, so
// legitimate paths and snippets stay byte-identical (OUT-02 / D-10 stability).
//
// U+2028 (LINE SEPARATOR) and U+2029 (PARAGRAPH SEPARATOR) are stripped too:
// many terminals and log viewers treat them as line breaks, so leaving them in
// would reopen the log-injection vector through a crafted author name or path
// (WR-04).
func sanitizeForTTY(s string) string {
	const maxLen = 256
	isUnsafe := func(r rune) bool {
		return r == 0x1b || r == 0x7f || (r < 0x20 && r != '\t') || r == '\u2028' || r == '\u2029'
	}
	hasControl := false
	for _, r := range s {
		if isUnsafe(r) {
			hasControl = true
			break
		}
	}
	if !hasControl && len(s) <= maxLen {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	n := 0
	for _, r := range s {
		if n >= maxLen {
			b.WriteString("…")
			break
		}
		if isUnsafe(r) {
			b.WriteRune('�')
		} else {
			b.WriteRune(r)
		}
		n++
	}
	return b.String()
}

// formatDuration formats a duration as a human-friendly string like "0.8s" or "1.2s".
func formatDuration(d time.Duration) string {
	secs := d.Seconds()
	if secs < 0.1 {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", secs)
}
