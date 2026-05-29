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
	for _, f := range findings {
		if f.Suppressed {
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

		fmt.Fprintf(w, "%s:%d:%d  %s  %s\n",
			f.File, f.Line, f.Column, ruleStr, f.Secret)

		// --verbose surfaces the paste-ready suppression hint + fingerprint
		// (D-04, criterion 1) so the user knows exactly what to add.
		if verbose {
			fmt.Fprintf(w, "    ↳ suppress: add `// mimir:ignore` on this line · fingerprint: %s\n", f.Fingerprint)
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
	// D-11 transparency: always report the inline-ignored count when non-zero.
	if n := stats.Suppressed[suppressInlineReason]; n > 0 {
		fmt.Fprintf(w, "  (%d inline-ignored)\n", n)
	}
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
