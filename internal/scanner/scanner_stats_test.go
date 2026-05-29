package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestStatsTransparencyCounters verifies the D-11/D-13 Stats fields exist and
// that a completed Scan returns a usable (non-nil) Suppressed map with a zero
// PathsExcluded count before any suppression layer populates them (Plans 02–04).
func TestStatsTransparencyCounters(t *testing.T) {
	s := newTestScanner(t)
	dir := t.TempDir()
	writeFile(t, dir, "clean.txt", "nothing to see here\n")

	_, stats := scanPaths(t, s, dir)

	assert.Equal(t, 0, stats.PathsExcluded, "no path exclusion wired yet")
	assert.NotNil(t, stats.Suppressed, "Suppressed map must be initialized by Scan")
	assert.Empty(t, stats.Suppressed, "no suppression wired yet")
}
