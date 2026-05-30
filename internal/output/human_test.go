package output_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/stretchr/testify/assert"

	"github.com/MatrixMagician/mimir/internal/finding"
	"github.com/MatrixMagician/mimir/internal/output"
)

// withVerification returns a copy of f labelled with the given verification
// status/provider (mirrors how verify.Run writes Verification in place).
func withVerification(f finding.Finding, status, provider string) finding.Finding {
	f.Verification = &finding.Verification{Status: status, Provider: provider}
	return f
}

// TestHumanVerificationTag asserts each verification status renders its plain-text
// tag word (ACTIVE/INACTIVE/UNKNOWN) on the finding row, and that a finding with
// nil Verification renders the pre-Phase-4 row unchanged (no tag).
func TestHumanVerificationTag(t *testing.T) {
	color.NoColor = true

	// Bracketed tags are used so distinct substrings can be asserted: a bare
	// "ACTIVE" check would spuriously match "[INACTIVE]".
	cases := []struct {
		name   string
		status string
		tag    string
	}{
		{"active", "active", "[ACTIVE]"},
		{"inactive", "inactive", "[INACTIVE]"},
		{"unknown", "unknown", "[UNKNOWN]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := finding.New("aws-access-token", "src/config.go", 3, 21, "AKIAFAKEKEYABCDE2345", "context", false)
			f := withVerification(base, tc.status, "aws")
			var buf bytes.Buffer
			output.WriteHuman(&buf, []finding.Finding{f}, makeStats(1, time.Millisecond), true, false, false)
			out := buf.String()
			assert.Contains(t, out, tc.tag, "row must carry the %s tag", tc.tag)
			// The other two tags must not appear for this single finding.
			for _, other := range []string{"[ACTIVE]", "[INACTIVE]", "[UNKNOWN]"} {
				if other != tc.tag {
					assert.NotContains(t, out, other, "row must not carry the %s tag for a %s finding", other, tc.status)
				}
			}
		})
	}

	t.Run("nil-verification row unchanged", func(t *testing.T) {
		f := finding.New("aws-access-token", "src/config.go", 3, 21, "AKIAFAKEKEYABCDE2345", "context", false)
		var got bytes.Buffer
		output.WriteHuman(&got, []finding.Finding{f}, makeStats(1, time.Millisecond), true, false, false)
		// No tag word anywhere; the row stays byte-identical to the Phase 1 format.
		assert.NotContains(t, got.String(), "[ACTIVE]")
		assert.NotContains(t, got.String(), "[INACTIVE]")
		assert.NotContains(t, got.String(), "[UNKNOWN]")
		assert.NotContains(t, got.String(), "Verified:")
	})
}

// TestHumanVerifiedTally asserts the one-line `Verified: N active, M inactive,
// K unknown` tally appears with correct counts when any finding is verified, and
// is absent when none are.
func TestHumanVerifiedTally(t *testing.T) {
	color.NoColor = true

	mk := func(file, status string) finding.Finding {
		return withVerification(
			finding.New("aws-access-token", file, 1, 1, "AKIAFAKEKEYABCDE2345", "context", false),
			status, "aws")
	}

	t.Run("mixed counts", func(t *testing.T) {
		findings := []finding.Finding{
			mk("a.txt", "active"),
			mk("b.txt", "active"),
			mk("c.txt", "inactive"),
			mk("d.txt", "unknown"),
		}
		var buf bytes.Buffer
		output.WriteHuman(&buf, findings, makeStats(4, time.Millisecond), true, false, false)
		assert.Contains(t, buf.String(), "Verified: 2 active, 1 inactive, 1 unknown")
	})

	t.Run("absent when none verified", func(t *testing.T) {
		f := finding.New("aws-access-token", "a.txt", 1, 1, "AKIAFAKEKEYABCDE2345", "context", false)
		var buf bytes.Buffer
		output.WriteHuman(&buf, []finding.Finding{f}, makeStats(1, time.Millisecond), true, false, false)
		assert.NotContains(t, buf.String(), "Verified:")
	})
}
