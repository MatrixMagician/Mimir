package output_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/stretchr/testify/assert"

	"github.com/MatrixMagician/mimir/internal/finding"
	"github.com/MatrixMagician/mimir/internal/output"
	"github.com/MatrixMagician/mimir/internal/scanner"
)

func makeStats(filesScanned int, dur time.Duration) scanner.Stats {
	return scanner.Stats{FilesScanned: filesScanned, Duration: dur}
}

func TestWriteHumanOneFinding(t *testing.T) {
	color.NoColor = true
	f := finding.New("aws-access-token", "src/config.go", 3, 21, "AKIAFAKEKEYABCDE2345", "context", false)
	var buf bytes.Buffer
	output.WriteHuman(&buf, []finding.Finding{f}, makeStats(1, time.Millisecond), true, false)
	out := buf.String()
	// Should contain path:line:col  rule-id  redacted
	assert.Regexp(t, `src/config\.go:3:21\s+aws-access-token\s+AKIA\*\*\*\*`, out)
}

func TestWriteHumanHeuristicRuleDisplay(t *testing.T) {
	color.NoColor = true
	f := finding.New("generic-secret", "file.go", 1, 1, "AKIAFAKEKEYABCDE2345", "context", true)
	var buf bytes.Buffer
	output.WriteHuman(&buf, []finding.Finding{f}, makeStats(1, time.Millisecond), true, false)
	out := buf.String()
	// Heuristic rules should have " ?" suffix appended
	assert.Contains(t, out, "generic-secret ?")
}

func TestWriteHumanSummaryWithFindings(t *testing.T) {
	color.NoColor = true
	f1 := finding.New("aws-access-token", "file1.go", 1, 1, "AKIAFAKEKEYABCDE2345", "ctx", false)
	f2 := finding.New("aws-access-token", "file2.go", 1, 1, "AKIATESTKEY234567AB", "ctx", false)
	var buf bytes.Buffer
	output.WriteHuman(&buf, []finding.Finding{f1, f2}, makeStats(5, 100*time.Millisecond), true, false)
	out := buf.String()
	assert.Contains(t, out, "2 finding")
	assert.Contains(t, out, "2 file")
	assert.Contains(t, out, "scanned 5 files")
}

func TestWriteHumanSummaryNoFindings(t *testing.T) {
	color.NoColor = true
	var buf bytes.Buffer
	output.WriteHuman(&buf, nil, makeStats(3, 50*time.Millisecond), true, false)
	out := buf.String()
	assert.Contains(t, out, "no findings")
	assert.Contains(t, out, "scanned 3 files")
}

func TestWriteHumanNoColor(t *testing.T) {
	f := finding.New("aws-access-token", "file.go", 1, 1, "AKIAFAKEKEYABCDE2345", "ctx", false)
	var buf bytes.Buffer
	output.WriteHuman(&buf, []finding.Finding{f}, makeStats(1, time.Millisecond), true, false)
	out := buf.String()
	// No ANSI escape codes
	assert.NotContains(t, out, "\x1b[")
}

func TestWriteHumanQuietSuppressesSummary(t *testing.T) {
	color.NoColor = true
	f := finding.New("aws-access-token", "file.go", 1, 1, "AKIAFAKEKEYABCDE2345", "ctx", false)
	var buf bytes.Buffer
	output.WriteHuman(&buf, []finding.Finding{f}, makeStats(1, time.Millisecond), true, true) // quiet=true
	out := buf.String()
	// Findings should still be present
	assert.Contains(t, out, "aws-access-token")
	// Summary should be absent
	assert.NotContains(t, out, "finding(s) in")
	assert.NotContains(t, out, "no findings")
}

func TestWriteHumanQuietFalseIncludesSummary(t *testing.T) {
	color.NoColor = true
	f := finding.New("aws-access-token", "file.go", 1, 1, "AKIAFAKEKEYABCDE2345", "ctx", false)
	var buf bytes.Buffer
	output.WriteHuman(&buf, []finding.Finding{f}, makeStats(1, time.Millisecond), true, false) // quiet=false
	out := buf.String()
	assert.Contains(t, out, "finding(s) in")
}

func TestWriteHumanRedactionInFindingLine(t *testing.T) {
	color.NoColor = true
	rawSecret := "AKIAFAKEKEYABCDE2345"
	f := finding.New("aws-access-token", "file.go", 1, 1, rawSecret, "ctx", false)
	var buf bytes.Buffer
	output.WriteHuman(&buf, []finding.Finding{f}, makeStats(1, time.Millisecond), true, false)
	out := buf.String()
	// Raw secret must never appear in output
	assert.False(t, strings.Contains(out, rawSecret), "raw secret should not appear in output")
}
