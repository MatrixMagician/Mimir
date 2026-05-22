package finding_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/MatrixMagician/mimir/internal/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRedactSecret verifies redaction behavior per D-04 and D-05.
func TestRedactSecret(t *testing.T) {
	t.Run("long secret shows prefix and last-4", func(t *testing.T) {
		result := finding.RedactSecret("AKIAIOSFODNN7EXAMPLE")
		// 20 chars >= 16 minVisibleLen: first 4 + ****...****  + last 4
		assert.Equal(t, "AKIA****...****MPLE", result)
		assert.NotContains(t, result, "AKIAIOSFODNN7EXAMPLE", "raw secret must not appear in output")
	})

	t.Run("exact 16 char secret shows prefix and last-4", func(t *testing.T) {
		result := finding.RedactSecret("1234567890abcdef")
		assert.Equal(t, "1234****...****cdef", result)
		assert.NotContains(t, result, "1234567890abcdef")
	})

	t.Run("short secret below threshold returns REDACTED", func(t *testing.T) {
		result := finding.RedactSecret("hunter2")
		assert.Equal(t, "[REDACTED]", result)
	})

	t.Run("15 char secret returns REDACTED (below minVisibleLen)", func(t *testing.T) {
		result := finding.RedactSecret("short15charssec")
		assert.Equal(t, "[REDACTED]", result)
	})

	t.Run("empty string returns REDACTED", func(t *testing.T) {
		result := finding.RedactSecret("")
		assert.Equal(t, "[REDACTED]", result)
	})
}

// TestFindingNew verifies Finding construction and redact-at-boundary invariant.
func TestFindingNew(t *testing.T) {
	const rawSecret = "AKIAIOSFODNN7EXAMPLE123"
	const ruleID = "aws-access-token"
	const filePath = "src/config.go"

	f := finding.New(ruleID, filePath, 5, 10, rawSecret, "context line with "+rawSecret+" in it", false)

	t.Run("Secret field is redacted not raw", func(t *testing.T) {
		assert.NotEqual(t, rawSecret, f.Secret, "Secret must not be the raw value")
		assert.Contains(t, f.Secret, "****", "Secret must contain redaction marker")
	})

	t.Run("Match field does not contain raw secret", func(t *testing.T) {
		assert.NotContains(t, f.Match, rawSecret, "Match must not contain raw secret")
	})

	t.Run("RuleID is preserved", func(t *testing.T) {
		assert.Equal(t, ruleID, f.RuleID)
	})

	t.Run("File is preserved", func(t *testing.T) {
		assert.Equal(t, filePath, f.File)
	})

	t.Run("Line and Column are preserved", func(t *testing.T) {
		assert.Equal(t, 5, f.Line)
		assert.Equal(t, 10, f.Column)
	})

	t.Run("Fingerprint is non-empty", func(t *testing.T) {
		assert.NotEmpty(t, f.Fingerprint)
	})

	t.Run("IsHeuristic is false", func(t *testing.T) {
		assert.False(t, f.IsHeuristic)
	})
}

// TestFindingNewShortSecret verifies fallback redaction for short secrets.
func TestFindingNewShortSecret(t *testing.T) {
	f := finding.New("test-rule", "file.txt", 1, 1, "hunter2", "context", false)
	assert.Equal(t, "[REDACTED]", f.Secret)
	assert.NotContains(t, f.Match, "hunter2")
}

// TestFingerprint verifies fingerprint stability and format.
func TestFingerprint(t *testing.T) {
	const rawSecret = "AKIAIOSFODNN7EXAMPLE123"

	f1 := finding.New("aws-access-token", "src/config.go", 5, 10, rawSecret, "ctx", false)
	f2 := finding.New("aws-access-token", "src/config.go", 5, 10, rawSecret, "ctx", false)

	t.Run("fingerprint is stable across calls", func(t *testing.T) {
		assert.Equal(t, f1.Fingerprint, f2.Fingerprint, "fingerprint must be deterministic")
	})

	t.Run("fingerprint format is path:rule_id:16hex", func(t *testing.T) {
		// Must be: src/config.go:aws-access-token:<16 hex chars>
		parts := strings.Split(f1.Fingerprint, ":")
		require.Len(t, parts, 3, "fingerprint must have 3 colon-separated parts")
		assert.Equal(t, "src/config.go", parts[0])
		assert.Equal(t, "aws-access-token", parts[1])
		assert.Regexp(t, `^[0-9a-f]{16}$`, parts[2], "third part must be 16 lowercase hex chars")
	})

	t.Run("different secrets produce different fingerprints", func(t *testing.T) {
		f3 := finding.New("aws-access-token", "src/config.go", 5, 10, "DIFFERENTVALUE0001234", "ctx", false)
		assert.NotEqual(t, f1.Fingerprint, f3.Fingerprint)
	})

	t.Run("fingerprint normalizes Windows path separators", func(t *testing.T) {
		// Windows-style path with backslashes should be normalized to forward slashes
		f := finding.New("aws-access-token", `src\config.go`, 5, 10, rawSecret, "ctx", false)
		assert.True(t, strings.HasPrefix(f.Fingerprint, "src/config.go:"), "path must use forward slash in fingerprint, got: %s", f.Fingerprint)
	})
}

// TestNoRawSecretInAnyField is the security regression test: reflect-inspect
// all exported string fields of Finding to assert no raw secret value escaped.
func TestNoRawSecretInAnyField(t *testing.T) {
	const rawSecret = "AKIAFAKEKEY12345678"
	f := finding.New("aws-access-token", "src/config.go", 1, 1, rawSecret, "some context "+rawSecret, false)

	v := reflect.ValueOf(f)
	typ := v.Type()

	for i := range v.NumField() {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}
		fv := v.Field(i)
		if fv.Kind() == reflect.String {
			fieldVal := fv.String()
			assert.NotContains(t, fieldVal, rawSecret,
				"field %s must not contain the raw secret value", field.Name)
		}
	}
}
