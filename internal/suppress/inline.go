package suppress

import (
	"regexp"
	"strings"

	"github.com/MatrixMagician/mimir/internal/finding"
)

// InlineReason is the SuppressionReason value set on findings withheld by an
// inline mimir-ignore directive (D-04).
const InlineReason = "inline-ignore"

// inlineDirectiveRE matches a mimir inline-ignore directive anywhere on a line
// (D-01/D-02): the directive token is grepped, not tied to any comment syntax.
//
//   - blanket form: mimir:ignore         → suppresses every rule on the line
//   - scoped form:  mimir:ignore:a,b,c   → suppresses only the listed rule IDs
//
// Matched case-insensitively (D-01/D-05) and compiled once at package scope
// (RE2, no backtracking). The trailing \b after "ignore" prevents a longer word
// such as "ignored" from triggering a blanket match. Captured rule IDs preserve
// their original case for the exact, case-sensitive comparison in D-03.
var inlineDirectiveRE = regexp.MustCompile(`(?i)mimir:ignore\b(:([a-zA-Z0-9_,-]+))?`)

// FilterInline applies the inline-ignore policy to the findings produced from a
// single source line, incrementing counts[InlineReason] for every suppressed
// finding regardless of the branch taken.
//
// When showSuppressed is false a suppressed finding is DROPPED; when true it is
// KEPT and annotated (Suppressed=true, SuppressionReason=InlineReason) so it
// reaches the output stage (D-12). Both scan sources — the working-tree file
// walk and the diff parser — share this one function, since a diff-added line
// IS the source line and the directive check is identical.
//
// The result reuses findings' backing array, so callers must not retain the
// input slice afterwards. Both call sites pass a slice fresh from
// detect.ScanLine, which nobody else holds.
func FilterInline(line string, findings []finding.Finding, counts map[string]int, showSuppressed bool) []finding.Finding {
	kept := findings[:0]
	for i := range findings {
		if InlineSuppresses(line, findings[i].RuleID) {
			counts[InlineReason]++
			if !showSuppressed {
				continue // drop: do not keep
			}
			findings[i].Suppressed = true
			findings[i].SuppressionReason = InlineReason
		}
		kept = append(kept, findings[i])
	}
	return kept
}

// InlineSuppresses reports whether an inline mimir-ignore directive on the given
// source line suppresses the given rule (D-01..D-03). It operates on a single
// physical line — it never scans across lines. A blanket `mimir:ignore`
// suppresses any rule; a scoped `mimir:ignore:<rule-id>[,<rule-id>...]`
// suppresses only the listed rule IDs, compared case-sensitively against ruleID.
func InlineSuppresses(line, ruleID string) bool {
	m := inlineDirectiveRE.FindStringSubmatch(line)
	if m == nil {
		return false
	}
	scope := m[2] // rule list without the leading colon, or "" for blanket
	if scope == "" {
		return true // blanket directive suppresses every rule on the line
	}
	for _, r := range strings.Split(scope, ",") {
		if strings.TrimSpace(r) == ruleID {
			return true
		}
	}
	return false
}
