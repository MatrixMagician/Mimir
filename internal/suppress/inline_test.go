package suppress

import (
	"testing"

	"github.com/MatrixMagician/mimir/internal/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInlineSuppresses(t *testing.T) {
	cases := []struct {
		name string
		line string
		rule string
		want bool
	}{
		{"blanket suppresses any rule", `key = "AKIAFAKEKEYABCDE2345" // mimir:ignore`, "aws-access-token", true},
		{"scoped suppresses named rule", `x // mimir:ignore:aws-access-token`, "aws-access-token", true},
		{"scoped does not suppress other rule", `x // mimir:ignore:aws-access-token`, "github-pat", false},
		{"scoped comma list", `x // mimir:ignore:foo,github-pat,bar`, "github-pat", true},
		{"no directive present", `just a normal line with a secret`, "aws-access-token", false},
		{"case-insensitive blanket", `x // MIMIR:IGNORE`, "any-rule", true},
		{"mixed-case scoped keeps rule case", `x // Mimir:Ignore:aws-access-token`, "aws-access-token", true},
		{"longer word does not trigger", `x // mimir:ignored for now`, "aws-access-token", false},
		{"hash comment style works", `secret # mimir:ignore`, "any-rule", true},
		{"semicolon comment style works", `secret ; mimir:ignore:github-pat`, "github-pat", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := InlineSuppresses(tc.line, tc.rule); got != tc.want {
				t.Errorf("InlineSuppresses(%q, %q) = %v, want %v", tc.line, tc.rule, got, tc.want)
			}
		})
	}
}

// TestFilterInline covers the shared inline-ignore policy directly. Both scan
// sources (the working-tree walk and the diff parser) route through it, so its
// two branches — drop vs annotate-and-keep — and its counting contract are
// load-bearing for the summary line and the exit code.
func TestFilterInline(t *testing.T) {
	newFindings := func() []finding.Finding {
		return []finding.Finding{
			{RuleID: "aws-access-token", Fingerprint: "a"},
			{RuleID: "github-pat", Fingerprint: "b"},
		}
	}

	t.Run("no directive keeps everything and counts nothing", func(t *testing.T) {
		counts := map[string]int{}
		got := FilterInline("plain line", newFindings(), counts, false)
		assert.Len(t, got, 2)
		assert.Empty(t, counts)
	})

	t.Run("blanket directive drops all but still counts them", func(t *testing.T) {
		counts := map[string]int{}
		got := FilterInline("x // mimir:ignore", newFindings(), counts, false)
		assert.Empty(t, got, "default branch DROPS suppressed findings")
		assert.Equal(t, 2, counts[InlineReason],
			"suppressed findings must be counted even when dropped, or the summary under-reports")
	})

	t.Run("showSuppressed keeps and annotates instead of dropping", func(t *testing.T) {
		counts := map[string]int{}
		got := FilterInline("x // mimir:ignore", newFindings(), counts, true)
		require.Len(t, got, 2, "--show-suppressed keeps them")
		for _, f := range got {
			assert.True(t, f.Suppressed)
			assert.Equal(t, InlineReason, f.SuppressionReason)
		}
		assert.Equal(t, 2, counts[InlineReason],
			"the count must be identical in both branches")
	})

	t.Run("scoped directive suppresses only the named rule", func(t *testing.T) {
		counts := map[string]int{}
		got := FilterInline("x // mimir:ignore:github-pat", newFindings(), counts, false)
		require.Len(t, got, 1)
		assert.Equal(t, "aws-access-token", got[0].RuleID, "the unnamed rule survives")
		assert.Equal(t, 1, counts[InlineReason])
		assert.False(t, got[0].Suppressed, "a surviving finding must not be marked suppressed")
	})

	t.Run("empty input is safe", func(t *testing.T) {
		counts := map[string]int{}
		assert.Empty(t, FilterInline("x // mimir:ignore", nil, counts, false))
		assert.Empty(t, counts)
	})

	t.Run("counts accumulate across calls", func(t *testing.T) {
		counts := map[string]int{}
		FilterInline("x // mimir:ignore", newFindings(), counts, false)
		FilterInline("y // mimir:ignore", newFindings(), counts, false)
		assert.Equal(t, 4, counts[InlineReason], "counts are per-file totals, not per-line")
	})
}
