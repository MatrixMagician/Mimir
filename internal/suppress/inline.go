package suppress

import (
	"regexp"
	"strings"
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

// LineSuppresses reports whether an inline mimir-ignore directive on the given
// source line suppresses the given rule (D-01..D-03). It operates on a single
// physical line — it never scans across lines. A blanket `mimir:ignore`
// suppresses any rule; a scoped `mimir:ignore:<rule-id>[,<rule-id>...]`
// suppresses only the listed rule IDs, compared case-sensitively against ruleID.
func LineSuppresses(line, ruleID string) bool {
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
