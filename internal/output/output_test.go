package output_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mimirconfig "github.com/MatrixMagician/mimir/internal/config"
	"github.com/MatrixMagician/mimir/internal/detect"
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
	output.WriteHuman(&buf, []finding.Finding{f}, makeStats(1, time.Millisecond), true, false, false)
	out := buf.String()
	// Should contain path:line:col  rule-id  redacted
	assert.Regexp(t, `src/config\.go:3:21\s+aws-access-token\s+AKIA\*\*\*\*`, out)
}

func TestWriteHumanHeuristicRuleDisplay(t *testing.T) {
	color.NoColor = true
	f := finding.New("generic-secret", "file.go", 1, 1, "AKIAFAKEKEYABCDE2345", "context", true)
	var buf bytes.Buffer
	output.WriteHuman(&buf, []finding.Finding{f}, makeStats(1, time.Millisecond), true, false, false)
	out := buf.String()
	// Heuristic rules should have " ?" suffix appended
	assert.Contains(t, out, "generic-secret ?")
}

func TestWriteHumanSummaryWithFindings(t *testing.T) {
	color.NoColor = true
	f1 := finding.New("aws-access-token", "file1.go", 1, 1, "AKIAFAKEKEYABCDE2345", "ctx", false)
	f2 := finding.New("aws-access-token", "file2.go", 1, 1, "AKIATESTKEY234567AB", "ctx", false)
	var buf bytes.Buffer
	output.WriteHuman(&buf, []finding.Finding{f1, f2}, makeStats(5, 100*time.Millisecond), true, false, false)
	out := buf.String()
	assert.Contains(t, out, "2 finding")
	assert.Contains(t, out, "2 file")
	assert.Contains(t, out, "scanned 5 files")
}

func TestWriteHumanSummaryNoFindings(t *testing.T) {
	color.NoColor = true
	var buf bytes.Buffer
	output.WriteHuman(&buf, nil, makeStats(3, 50*time.Millisecond), true, false, false)
	out := buf.String()
	assert.Contains(t, out, "no findings")
	assert.Contains(t, out, "scanned 3 files")
}

func TestWriteHumanNoColor(t *testing.T) {
	f := finding.New("aws-access-token", "file.go", 1, 1, "AKIAFAKEKEYABCDE2345", "ctx", false)
	var buf bytes.Buffer
	output.WriteHuman(&buf, []finding.Finding{f}, makeStats(1, time.Millisecond), true, false, false)
	out := buf.String()
	// No ANSI escape codes
	assert.NotContains(t, out, "\x1b[")
}

func TestWriteHumanQuietSuppressesSummary(t *testing.T) {
	color.NoColor = true
	f := finding.New("aws-access-token", "file.go", 1, 1, "AKIAFAKEKEYABCDE2345", "ctx", false)
	var buf bytes.Buffer
	output.WriteHuman(&buf, []finding.Finding{f}, makeStats(1, time.Millisecond), true, true, false) // quiet=true
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
	output.WriteHuman(&buf, []finding.Finding{f}, makeStats(1, time.Millisecond), true, false, false) // quiet=false
	out := buf.String()
	assert.Contains(t, out, "finding(s) in")
}

func TestWriteHumanRedactionInFindingLine(t *testing.T) {
	color.NoColor = true
	rawSecret := "AKIAFAKEKEYABCDE2345"
	f := finding.New("aws-access-token", "file.go", 1, 1, rawSecret, "ctx", false)
	var buf bytes.Buffer
	output.WriteHuman(&buf, []finding.Finding{f}, makeStats(1, time.Millisecond), true, false, false)
	out := buf.String()
	// Raw secret must never appear in output
	assert.False(t, strings.Contains(out, rawSecret), "raw secret should not appear in output")
}

// TestWriteHumanSanitizesUntrustedGitMetadata verifies that attacker-influenced
// git metadata and diff-sourced paths can never inject terminal-control bytes
// (ANSI escapes, carriage returns) into human output (terminal-escape /
// log-injection, T-03-03). A history finding's File, CommitSHA, CommitAuthor,
// and CommitDate all originate from untrusted repo content.
func TestWriteHumanSanitizesUntrustedGitMetadata(t *testing.T) {
	color.NoColor = true
	f := finding.New("aws-access-token", "evil\x1b[31m\rpath.go", 7, 3, "AKIAFAKEKEYABCDE2345", "ctx", false)
	f.CommitSHA = "abc1234\x1b]0;pwned\x07def"
	f.CommitAuthor = "Attacker\x1b[2J\x1b[H\r\u2028\u2029<injected>"
	f.CommitDate = "2026-01-01T00:00:00Z\x1b[5m"
	var buf bytes.Buffer
	output.WriteHuman(&buf, []finding.Finding{f}, makeStats(1, time.Millisecond), true, false, true) // verbose=true
	out := buf.String()
	// No raw ESC, BEL, or CR may survive to the terminal.
	assert.NotContains(t, out, "\x1b", "ESC must be stripped from git metadata")
	assert.NotContains(t, out, "\x07", "BEL must be stripped from git metadata")
	assert.NotContains(t, out, "\r", "CR must be stripped from git metadata")
	assert.NotContains(t, out, "\u2028", "U+2028 line separator must be stripped (WR-04)")
	assert.NotContains(t, out, "\u2029", "U+2029 paragraph separator must be stripped (WR-04)")
	// The benign textual parts still render (sanitization replaces only controls).
	assert.Contains(t, out, "abc1234", "short SHA prefix still shown")
	assert.Contains(t, out, "Attacker", "author name still shown (minus control bytes)")
}

// ---- Plan 01-03 JSON tests ----

// TestWriteJSONSchema verifies that WriteJSON produces valid JSON with the
// expected schema fields (OUT-02 stable schema).
func TestWriteJSONSchema(t *testing.T) {
	f := finding.New("aws-access-token", "src/config.go", 3, 21, "AKIAFAKEKEYABCDE2345", "context", false)
	stats := makeStats(5, 100*time.Millisecond)

	var buf bytes.Buffer
	err := output.WriteJSON(&buf, []finding.Finding{f}, stats)
	require.NoError(t, err)

	// Must be valid JSON
	var result output.ScanResult
	err = json.Unmarshal(buf.Bytes(), &result)
	require.NoError(t, err, "WriteJSON output must be valid JSON")

	// findings array must have 1 item
	require.Len(t, result.Findings, 1)

	// fingerprint field must be non-empty on every finding
	assert.NotEmpty(t, result.Findings[0].Fingerprint,
		"every finding must have a non-empty fingerprint field")

	// summary object must have required fields
	assert.Equal(t, 5, result.Summary.FilesScanned)
	assert.Equal(t, 1, result.Summary.FindingCount)
	assert.GreaterOrEqual(t, result.Summary.DurationMs, int64(0))
}

// TestWriteJSONFingerprint verifies that every finding in JSON output has a
// non-empty fingerprint field (OUT-02 schema stability).
func TestWriteJSONFingerprint(t *testing.T) {
	findings := []finding.Finding{
		finding.New("aws-access-token", "file1.go", 1, 1, "AKIAFAKEKEYABCDE2345", "ctx", false),
		finding.New("github-pat", "file2.go", 2, 5, "ghp_FakeGitHubToken123456789012345678901", "ctx", false),
	}
	stats := makeStats(3, 50*time.Millisecond)

	var buf bytes.Buffer
	err := output.WriteJSON(&buf, findings, stats)
	require.NoError(t, err)

	var result output.ScanResult
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result))

	for i, f := range result.Findings {
		assert.NotEmpty(t, f.Fingerprint, "finding %d must have non-empty fingerprint", i)
	}
}

// TestWriteJSONNoSecretLeak verifies that JSON output does NOT contain raw secret
// values (OUT-03 guarantee in the JSON channel).
func TestWriteJSONNoSecretLeak(t *testing.T) {
	rawSecret := "AKIAFAKEKEYABCDE2345"
	f := finding.New("aws-access-token", "file.go", 1, 1, rawSecret, "ctx", false)
	stats := makeStats(1, time.Millisecond)

	var buf bytes.Buffer
	err := output.WriteJSON(&buf, []finding.Finding{f}, stats)
	require.NoError(t, err)

	jsonOutput := buf.String()
	assert.NotContains(t, jsonOutput, rawSecret,
		"JSON output must not contain the raw secret value (OUT-03)")
}

// TestWriteJSONEmptyFindings verifies WriteJSON handles empty findings slice correctly.
func TestWriteJSONEmptyFindings(t *testing.T) {
	stats := makeStats(10, 200*time.Millisecond)

	var buf bytes.Buffer
	err := output.WriteJSON(&buf, []finding.Finding{}, stats)
	require.NoError(t, err)

	var result output.ScanResult
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result))
	assert.Empty(t, result.Findings)
	assert.Equal(t, 10, result.Summary.FilesScanned)
	assert.Equal(t, 0, result.Summary.FindingCount)
}

// TestWriteJSONSummaryFields verifies the summary object has all required fields.
func TestWriteJSONSummaryFields(t *testing.T) {
	f := finding.New("aws-access-token", "f.go", 1, 1, "AKIAFAKEKEYABCDE2345", "ctx", false)
	stats := makeStats(42, 1500*time.Millisecond)

	var buf bytes.Buffer
	require.NoError(t, output.WriteJSON(&buf, []finding.Finding{f}, stats))

	var result output.ScanResult
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result))

	assert.Equal(t, 42, result.Summary.FilesScanned)
	assert.Equal(t, 1, result.Summary.FindingCount)
	assert.Equal(t, int64(1500), result.Summary.DurationMs)
}

// TestSelfScanOutThree is the OUT-03 self-scan integration test.
// It scans testdata/fixtures/known-secrets.txt, captures JSON output, then
// checks that no known raw fixture secret values appear in the JSON output.
//
// OUT-03 requires that no raw secret value appears in any output channel.
// The redaction boundary in finding.New() must hold: only redacted forms
// (e.g. "AKIA****...****2345") appear in JSON, never the raw value.
//
// NOTE: The scanner may still find pattern matches in the JSON output (e.g.
// redacted URIs like "scheme://user:[REDACTED]@host" still look like URIs).
// OUT-03 does not require zero pattern matches — it requires zero RAW secret
// values. The test therefore checks string presence of known raw secrets.
func TestSelfScanOutThree(t *testing.T) {
	cfg, err := mimirconfig.LoadDefault()
	require.NoError(t, err)

	eng := detect.NewEngine(cfg)
	s := scanner.New(eng, cfg)

	// Step 1: scan testdata/fixtures/known-secrets.txt
	fixturesPath := "../../testdata/fixtures/known-secrets.txt"
	if _, statErr := os.Stat(fixturesPath); os.IsNotExist(statErr) {
		t.Skip("testdata/fixtures/known-secrets.txt not found; skipping self-scan test")
	}

	findings, _, stats, err := s.Scan(context.Background(), []string{fixturesPath})
	require.NoError(t, err)
	require.NotEmpty(t, findings, "expected at least one finding in known-secrets.txt")

	// Step 2: capture JSON output
	var jsonBuf bytes.Buffer
	err = output.WriteJSON(&jsonBuf, findings, stats)
	require.NoError(t, err)

	jsonOutput := jsonBuf.String()

	// Step 3: assert no known raw fixture secret values appear in the JSON output.
	// These are the raw token values from testdata/fixtures/known-secrets.txt.
	// After redaction, only masked forms (AKIA****...****2345) should appear.
	knownRawSecrets := []string{
		"AKIAFAKEKEYABCDE2345",
		"AKIATESTKEY234567AB",
		"AIzaFakeKey1234567890123456789012345678",
		"ghp_FakeGitHubToken123456789012345678901",
		"gho_FakeGitHubOAuth123456789012345678901",
		"ghu_FakeGitHubApp12123456789012345678901",
		"ghr_FakeGitHubRef12123456789012345678901",
		"glpat-FakegitLabTok12345678901234567890",
		"sk_test_FakeStripeKey1234567890",
		"FakeSecretPass123",
	}

	for _, rawSecret := range knownRawSecrets {
		assert.NotContains(t, jsonOutput, rawSecret,
			"OUT-03: raw secret value %q must not appear in JSON output (redact-at-boundary holds)", rawSecret)
	}
}
