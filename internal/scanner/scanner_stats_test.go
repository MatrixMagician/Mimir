package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStatsTransparencyCounters verifies the D-11/D-13 Stats fields exist and
// that a completed Scan returns a usable (non-nil) Suppressed map with a zero
// PathsExcluded count on a clean file (no suppression to record).
func TestStatsTransparencyCounters(t *testing.T) {
	s := newTestScanner(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("nothing to see here\n"), 0600))

	_, stats, err := s.Scan(context.Background(), []string{dir})
	require.NoError(t, err)

	assert.Equal(t, 0, stats.PathsExcluded, "no path exclusion wired yet")
	assert.NotNil(t, stats.Suppressed, "Suppressed map must be initialized by Scan")
	assert.Empty(t, stats.Suppressed, "no suppression on a clean file")
}

// TestInlineIgnoreDropsByDefault verifies that, with ShowSuppressed=false
// (default), an inline mimir:ignore drops the finding from the returned slice
// while still being counted in Stats.Suppressed["inline-ignore"] (D-11/D-12).
func TestInlineIgnoreDropsByDefault(t *testing.T) {
	s := newTestScanner(t)
	dir := t.TempDir()
	content := "aws_key = \"AKIAFAKEKEYABCDE2345\" // mimir:ignore\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "app.go"), []byte(content), 0600))

	findings, stats, err := s.Scan(context.Background(), []string{dir})
	require.NoError(t, err)

	assert.Empty(t, findings, "inline-ignored finding must be dropped by default")
	assert.Equal(t, 1, stats.Suppressed["inline-ignore"], "inline-ignored finding must still be counted")
}

// TestInlineIgnoreAnnotatesWhenShowSuppressed verifies that, with
// ShowSuppressed=true, the inline-ignored finding is KEPT and annotated so it
// reaches the output stage for the D-12 audit guarantee.
func TestInlineIgnoreAnnotatesWhenShowSuppressed(t *testing.T) {
	s := newTestScanner(t)
	s.ShowSuppressed = true
	dir := t.TempDir()
	content := "aws_key = \"AKIAFAKEKEYABCDE2345\" // mimir:ignore\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "app.go"), []byte(content), 0600))

	findings, stats, err := s.Scan(context.Background(), []string{dir})
	require.NoError(t, err)

	require.Len(t, findings, 1, "inline-ignored finding must be kept under ShowSuppressed")
	assert.True(t, findings[0].Suppressed)
	assert.Equal(t, "inline-ignore", findings[0].SuppressionReason)
	assert.Equal(t, 1, stats.Suppressed["inline-ignore"])
}
