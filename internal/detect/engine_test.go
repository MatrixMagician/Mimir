package detect

import (
	"bufio"
	"os"
	"path/filepath"
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

// syntheticAWSKey returns a synthetic 20-char AWS-format key built at runtime.
// Format: AKIA + 16 chars from [A-Z2-7].
// These are intentionally fake tokens used only for unit testing Mimir's scanner.
func syntheticAWSKey(suffix string) string {
	return "AKIA" + suffix
}

// awsKeyLine returns a config-file-style line embedding a synthetic AWS key.
func awsKeyLine(suffix string) string {
	return "aws_access_key_id = " + syntheticAWSKey(suffix)
}

func TestEnginePrefilterFastPath(t *testing.T) {
	cfg := loadTestConfig(t)
	eng := NewEngine(cfg)

	// A line with no keywords should return nil via the fast path
	findings := eng.ScanLine("no secret here, just plain text", "test.txt", 1, map[string]string{})
	assert.Nil(t, findings, "expected nil findings for line with no keywords")
}

func TestEngineScanLineAWSToken(t *testing.T) {
	cfg := loadTestConfig(t)
	eng := NewEngine(cfg)

	// 16 chars from [A-Z2-7]: valid suffix for the aws-access-token regex
	line := awsKeyLine("FAKEKEYABCDE2345")
	findings := eng.ScanLine(line, "test.txt", 1, map[string]string{})
	require.Len(t, findings, 1, "expected exactly 1 finding")
	assert.Equal(t, "aws-access-token", findings[0].RuleID)
	assert.Equal(t, 1, findings[0].Line)
}

// TestScanLineEmitsRawIntoSink verifies the off-struct raw-secret side channel:
// ScanLine writes raw[finding.Fingerprint] = rawSecret into the caller-provided
// sink, keyed by the same fingerprint the finding carries. The raw value is the
// exact secret and never appears on the Finding itself.
func TestScanLineEmitsRawIntoSink(t *testing.T) {
	cfg := loadTestConfig(t)
	eng := NewEngine(cfg)

	rawKey := syntheticAWSKey("FAKEKEYABCDE2345")
	line := "aws_access_key_id = " + rawKey
	raw := map[string]string{}
	findings := eng.ScanLine(line, "test.txt", 1, raw)
	require.Len(t, findings, 1, "expected exactly 1 finding")

	fp := findings[0].Fingerprint
	gotRaw, ok := raw[fp]
	require.True(t, ok, "raw sink must contain an entry keyed by the finding's fingerprint")
	assert.Equal(t, rawKey, gotRaw, "raw sink must carry the exact raw secret")
	// The raw value must NOT have leaked onto the redacted Finding.
	assert.NotEqual(t, rawKey, findings[0].Secret)
}

func TestEngineScanLineEntropyGate(t *testing.T) {
	cfg := loadTestConfig(t)
	eng := NewEngine(cfg)

	// 16 identical chars → very low entropy → entropy gate should reject
	line := awsKeyLine(strings.Repeat("A", 16))
	findings := eng.ScanLine(line, "test.txt", 1, map[string]string{})
	assert.Nil(t, findings, "expected nil findings: low entropy value should be rejected by entropy gate")
}

func TestEngineScanLineAllowlistExample(t *testing.T) {
	cfg := loadTestConfig(t)
	eng := NewEngine(cfg)

	// The aws-access-token rule has an allowlist for values ending in EXAMPLE.
	// AKIAIOSFODNN7EXAMPLE is 20 chars: AKIA + IOSFODNN7EXAMPLE (16).
	// It also ends in EXAMPLE, so the per-rule allowlist should suppress it.
	// Additionally, the global allowlist should catch it even for generic-api-key.
	line := awsKeyLine("IOSFODNN7EXAMPLE")
	findings := eng.ScanLine(line, "test.txt", 1, map[string]string{})
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
	findings := eng.ScanLine(line, "test.txt", 1, map[string]string{})
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

// TestConnStr verifies the connection-string rule detects credentials in URIs.
func TestConnStr(t *testing.T) {
	cfg := loadTestConfig(t)
	eng := NewEngine(cfg)

	tests := []struct {
		name      string
		line      string
		wantRule  string
		wantCount int
	}{
		{
			name:      "postgres with user and password",
			line:      "DATABASE_URL = postgres://user:FakeSecretPass123@localhost:5432/mydb",
			wantRule:  "connection-string",
			wantCount: 1,
		},
		{
			name:      "redis password-only form (empty user)",
			line:      "REDIS_URL = redis://:sometoken@redis.host.io:6379",
			wantRule:  "connection-string",
			wantCount: 1,
		},
		{
			name:      "mongodb with credentials",
			line:      "MONGO_URI = mongodb://admin:hunter2@mongo.example.com:27017/db",
			wantRule:  "connection-string",
			wantCount: 1,
		},
		{
			name:      "plain https URL without credentials",
			line:      "https://example.com/page",
			wantRule:  "",
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := eng.ScanLine(tt.line, "test.txt", 1, map[string]string{})
			require.Len(t, findings, tt.wantCount, "unexpected finding count for: %q", tt.line)
			if tt.wantCount > 0 {
				assert.Equal(t, tt.wantRule, findings[0].RuleID)
				// The raw password must not appear in the Finding.Secret field
				// (redact-at-boundary invariant)
				assert.NotContains(t, findings[0].Secret, "FakeSecretPass123",
					"raw password must not appear in Secret field")
				assert.NotContains(t, findings[0].Secret, "sometoken",
					"raw password must not appear in Secret field")
				assert.NotContains(t, findings[0].Secret, "hunter2",
					"raw password must not appear in Secret field")
			}
		})
	}
}

// TestNoEntropy verifies the cfg.NoEntropy flag bypasses entropy thresholds.
func TestNoEntropy(t *testing.T) {
	t.Run("NoEntropy=false rejects low-entropy match", func(t *testing.T) {
		cfg := loadTestConfig(t)
		cfg.NoEntropy = false
		eng := NewEngine(cfg)

		// Low entropy: AKIA + 16 identical chars → entropy well below 3.0
		line := awsKeyLine(strings.Repeat("B", 16))
		findings := eng.ScanLine(line, "test.txt", 1, map[string]string{})
		assert.Nil(t, findings, "low-entropy match should be rejected when NoEntropy=false")
	})

	t.Run("NoEntropy=true passes low-entropy match", func(t *testing.T) {
		cfg := loadTestConfig(t)
		cfg.NoEntropy = true
		eng := NewEngine(cfg)

		// Same low-entropy key — with NoEntropy=true it should produce a finding
		line := awsKeyLine(strings.Repeat("B", 16))
		findings := eng.ScanLine(line, "test.txt", 1, map[string]string{})
		require.NotEmpty(t, findings, "low-entropy match should pass when NoEntropy=true")
		assert.Equal(t, "aws-access-token", findings[0].RuleID)
	})
}

// fixtureLines parses testdata/fixtures/known-secrets.txt and returns a map
// of lines indexed by line number (1-based) for rule detection tests.
func fixtureLines(t *testing.T) []string {
	t.Helper()
	// Find the testdata directory relative to the module root
	path := filepath.Join("..", "..", "testdata", "fixtures", "known-secrets.txt")
	f, err := os.Open(path)
	require.NoError(t, err, "failed to open known-secrets.txt")
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	require.NoError(t, sc.Err())
	return lines
}

// TestAllRules verifies that every rule in the default config produces at least
// one finding when scanning testdata/fixtures/known-secrets.txt.
func TestAllRules(t *testing.T) {
	cfg := loadTestConfig(t)
	eng := NewEngine(cfg)
	lines := fixtureLines(t)

	// Build a set of rule IDs we expect to find
	ruleIDs := make(map[string]bool)
	for _, rule := range cfg.Rules {
		ruleIDs[rule.ID] = false // false = not yet found
	}

	// Scan every line in the fixture file
	for i, line := range lines {
		findings := eng.ScanLine(line, "known-secrets.txt", i+1, map[string]string{})
		for _, f := range findings {
			ruleIDs[f.RuleID] = true
		}
	}

	// Every rule should have been triggered by at least one fixture line
	for ruleID, found := range ruleIDs {
		assert.True(t, found, "rule %q produced no findings on the fixture file — add a fixture token for it", ruleID)
	}
}

// TestCleanNoFP verifies that scanning testdata/clean/no-secrets.go with
// the full ruleset produces zero findings (false-positive regression test).
func TestCleanNoFP(t *testing.T) {
	cfg := loadTestConfig(t)
	eng := NewEngine(cfg)

	path := filepath.Join("..", "..", "testdata", "clean", "no-secrets.go")
	f, err := os.Open(path)
	require.NoError(t, err, "failed to open no-secrets.go")
	defer f.Close()

	var allFindings []string
	sc := bufio.NewScanner(f)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := sc.Text()
		findings := eng.ScanLine(line, "no-secrets.go", lineNum, map[string]string{})
		for _, finding := range findings {
			allFindings = append(allFindings, "line "+string(rune('0'+lineNum))+" rule "+finding.RuleID)
		}
	}
	require.NoError(t, sc.Err())

	assert.Empty(t, allFindings,
		"expected zero findings on clean file, got: %v", allFindings)
}
