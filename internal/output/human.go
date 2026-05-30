// Package output formats scan results for human-readable and machine-readable output.
package output

import (
	"fmt"
	"io"
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
				f.File, f.Line, f.Column, shortSHA(f.CommitSHA), ruleStr, f.Secret)
		} else {
			fmt.Fprintf(w, "%s:%d:%d  %s  %s\n",
				f.File, f.Line, f.Column, ruleStr, f.Secret)
		}

		// --verbose surfaces the paste-ready suppression hint + fingerprint
		// (D-04, criterion 1) so the user knows exactly what to add. For history
		// findings it additionally surfaces the full commit author and date.
		if verbose {
			if f.CommitSHA != "" && (f.CommitAuthor != "" || f.CommitDate != "") {
				fmt.Fprintf(w, "    ↳ commit %s by %s on %s\n", f.CommitSHA, f.CommitAuthor, f.CommitDate)
			}
			fmt.Fprintf(w, "    ↳ suppress: add `// mimir:ignore` on this line · fingerprint: %s\n", f.Fingerprint)
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
				f.File, f.Line, f.Column, f.RuleID, f.SuppressionReason, f.Secret)
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

// suppressInlineReason mirrors suppress.InlineReason without importing the
// suppress package into the output layer (output stays a pure formatter).
const suppressInlineReason = "inline-ignore"

// uniqueFileCount returns the number of distinct file paths in findings.
func uniqueFileCount(findings []finding.Finding) int {
	seen := make(map[string]struct{}, len(findings))
	for _, f := range findings {
		seen[f.File] = struct{}{}
	}
	return len(seen)
}

// formatDuration formats a duration as a human-friendly string like "0.8s" or "1.2s".
func formatDuration(d time.Duration) string {
	secs := d.Seconds()
	if secs < 0.1 {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", secs)
}
