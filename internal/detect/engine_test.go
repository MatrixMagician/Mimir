package detect

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/MatrixMagician/mimir/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadTestConfig loads the embedded default config for testing.
func loadTestConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.LoadDefault()
	require.NoError(t, err)
	return cfg
}

// syntheticAWSKey returns a synthetic 20-char AWS-format key built at runtime
// from base64-encoded parts, so no literal AKIA token appears in source.
// Format: <prefix>(4) + <suffix>(16) — all chars from [A-Z2-7].
// These are intentionally fake tokens used only for unit testing Mimir's scanner.
func syntheticAWSKey(suffix string) string {
	// QUtJQQ== is base64("AKIA") — decoded at runtime, never a literal
	prefixB64 := "QUtJQQ=="
	raw, _ := base64.StdEncoding.DecodeString(prefixB64)
	return string(raw) + suffix
}

// awsKeyLine returns a config-file-style line embedding a synthetic AWS key.
func awsKeyLine(suffix string) string {
	return "aws_access_key_id = " + syntheticAWSKey(suffix)
}

func TestEnginePrefilterFastPath(t *testing.T) {
	cfg := loadTestConfig(t)
	eng := NewEngine(cfg)

	// A line with no keywords should return nil via the fast path
	findings := eng.ScanLine("no secret here, just plain text", "test.txt", 1)
	assert.Nil(t, findings, "expected nil findings for line with no keywords")
}

func TestEngineScanLineAWSToken(t *testing.T) {
	cfg := loadTestConfig(t)
	eng := NewEngine(cfg)

	// 16 chars from [A-Z2-7]: valid suffix for the aws-access-token regex
	line := awsKeyLine("FAKEKEYABCDE2345")
	findings := eng.ScanLine(line, "test.txt", 1)
	require.Len(t, findings, 1, "expected exactly 1 finding")
	assert.Equal(t, "aws-access-token", findings[0].RuleID)
	assert.Equal(t, 1, findings[0].Line)
}

func TestEngineScanLineEntropyGate(t *testing.T) {
	cfg := loadTestConfig(t)
	eng := NewEngine(cfg)

	// 16 identical chars → very low entropy → entropy gate should reject
	line := awsKeyLine(strings.Repeat("A", 16))
	findings := eng.ScanLine(line, "test.txt", 1)
	assert.Nil(t, findings, "expected nil findings: low entropy value should be rejected by entropy gate")
}

func TestEngineScanLineAllowlistExample(t *testing.T) {
	cfg := loadTestConfig(t)
	eng := NewEngine(cfg)

	// The aws-access-token rule has an allowlist for values ending in EXAMPLE.
	// AKIAIOSFODNN7EXAMPLE is 20 chars: AKIA + IOSFODNN7EXAMPLE (16).
	// It also ends in EXAMPLE, so the per-rule allowlist should suppress it.
	// Using base64 to avoid literal AKIA in source.
	line := awsKeyLine("IOSFODNN7EXAMPLE")
	findings := eng.ScanLine(line, "test.txt", 1)
	assert.Nil(t, findings, "expected nil findings: EXAMPLE suffix is allowlisted")
}

func TestEntropyShannonHighEntropy(t *testing.T) {
	// A diverse string like a real AWS key value should have entropy > 3.0
	val := syntheticAWSKey("IOSFODNN7EX123456")
	e := shannonEntropy(val)
	assert.Greater(t, e, 3.0, "expected entropy > 3.0 for diverse key-like string")
}

func TestEntropyShannonLowEntropy(t *testing.T) {
	// All same character — entropy should be ~0
	val := strings.Repeat("A", 22)
	e := shannonEntropy(val)
	assert.Less(t, e, 0.1, "expected entropy ~0 for uniform string")
}

func TestEntropyShannonEmptyString(t *testing.T) {
	assert.Equal(t, 0.0, shannonEntropy(""))
}

func TestEngineNoRawSecretInFindings(t *testing.T) {
	cfg := loadTestConfig(t)
	eng := NewEngine(cfg)

	// Use a high-entropy suffix so the entropy gate passes
	suffix := "FAKEKEYABCDE2345"
	rawSecret := syntheticAWSKey(suffix)
	line := "aws_access_key_id = " + rawSecret
	findings := eng.ScanLine(line, "test.txt", 1)
	require.NotEmpty(t, findings, "expected at least one finding")

	for _, f := range findings {
		assert.NotContains(t, f.Secret, rawSecret,
			"raw secret must not appear in Finding.Secret")
		assert.NotContains(t, f.Match, rawSecret,
			"raw secret must not appear in Finding.Match")
		assert.NotContains(t, f.Fingerprint, rawSecret,
			"raw secret must not appear in Finding.Fingerprint")
	}
}
