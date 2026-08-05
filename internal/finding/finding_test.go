package finding_test

import (
	"encoding/json"
	"reflect"
	"slices"
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

	// D-09: commit metadata must NOT enter computeFingerprint. The same secret at
	// the same path/rule must hash identically whether or not CommitSHA is set —
	// this is what makes cross-mode baseline/dedup work (history + working-tree
	// occurrences of one leaked secret share a single fingerprint).
	t.Run("commit metadata does not change the fingerprint (D-09)", func(t *testing.T) {
		base := finding.New("aws-access-token", "src/config.go", 5, 10, rawSecret, "ctx", false)
		withCommit := finding.New("aws-access-token", "src/config.go", 5, 10, rawSecret, "ctx", false)
		withCommit.CommitSHA = "abc1234def5678901234567890abcdef12345678"
		withCommit.CommitAuthor = "Alice Example"
		withCommit.CommitDate = "2026-05-30T12:00:00Z"
		assert.Equal(t, base.Fingerprint, withCommit.Fingerprint,
			"setting commit metadata must not alter the content-based fingerprint")
	})
}

// TestCommitMetaOmitempty verifies the D-08 commit fields are omitempty: a
// default (working-tree/staged) finding's JSON omits commit_sha entirely, while
// a history finding with CommitSHA set serializes it. This preserves OUT-02
// byte-identical output for non-history scans.
func TestCommitMetaOmitempty(t *testing.T) {
	const rawSecret = "AKIAFAKEKEYABCDE2345"

	t.Run("default finding omits commit fields", func(t *testing.T) {
		f := finding.New("aws-access-token", "src/config.go", 5, 10, rawSecret, "ctx", false)
		b, err := json.Marshal(f)
		require.NoError(t, err)
		js := string(b)
		assert.NotContains(t, js, "commit_sha", "default-scan JSON must omit commit_sha")
		assert.NotContains(t, js, "commit_author", "default-scan JSON must omit commit_author")
		assert.NotContains(t, js, "commit_date", "default-scan JSON must omit commit_date")
	})

	t.Run("history finding includes commit fields when set", func(t *testing.T) {
		f := finding.New("aws-access-token", "src/config.go", 5, 10, rawSecret, "ctx", false)
		f.CommitSHA = "abc1234def5678901234567890abcdef12345678"
		f.CommitAuthor = "Alice Example"
		f.CommitDate = "2026-05-30T12:00:00Z"
		b, err := json.Marshal(f)
		require.NoError(t, err)
		js := string(b)
		assert.Contains(t, js, "commit_sha", "history JSON must include commit_sha when set")
		assert.Contains(t, js, "abc1234def5678901234567890abcdef12345678")
		assert.Contains(t, js, "commit_author")
		assert.Contains(t, js, "commit_date")
	})
}

// TestVerificationOmittedByDefault verifies the pointer + omitempty discipline on
// the new Verification field (mirrors TestCommitMetaOmitempty): a default finding's
// JSON omits "verification" entirely, while a finding with Verification set
// serializes the nested object. This preserves OUT-02 byte-identical output for
// non-verify scans.
func TestVerificationOmittedByDefault(t *testing.T) {
	const rawSecret = "AKIAFAKEKEYABCDE2345"

	t.Run("default finding omits verification field", func(t *testing.T) {
		f := finding.New("aws-access-token", "src/config.go", 5, 10, rawSecret, "ctx", false)
		b, err := json.Marshal(f)
		require.NoError(t, err)
		js := string(b)
		assert.NotContains(t, js, "verification", "default-scan JSON must omit verification")
	})

	t.Run("finding includes verification when set", func(t *testing.T) {
		f := finding.New("aws-access-token", "src/config.go", 5, 10, rawSecret, "ctx", false)
		f.Verification = &finding.Verification{Status: "active", Provider: "aws"}
		b, err := json.Marshal(f)
		require.NoError(t, err)
		js := string(b)
		assert.Contains(t, js, "verification", "verify JSON must include verification when set")
		assert.Contains(t, js, "active", "verification status must serialize")
		assert.Contains(t, js, "aws", "verification provider must serialize")
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

// TestSortIsTotalOrder is the determinism regression test. Two rules can match
// the same secret at the same file:line:column (e.g. a `token: gho_...` line
// matches both github-oauth and the generic-api-key heuristic). Before Sort
// carried RuleID/Fingerprint tiebreakers, such findings compared EQUAL, and the
// unstable sort emitted them in whichever order the concurrent walk happened to
// append them — so two scans of an unchanged tree produced different JSON and
// therefore different baselines. Sorting several distinct permutations of the
// same set must now converge on one identical order.
func TestSortIsTotalOrder(t *testing.T) {
	tied := []finding.Finding{
		{RuleID: "github-oauth", File: "a.go", Line: 3, Column: 8, Fingerprint: "a.go:github-oauth:1111"},
		{RuleID: "generic-api-key", File: "a.go", Line: 3, Column: 8, Fingerprint: "a.go:generic-api-key:1111"},
		{RuleID: "aws-access-token", File: "a.go", Line: 3, Column: 8, Fingerprint: "a.go:aws-access-token:2222"},
		{RuleID: "generic-api-key", File: "a.go", Line: 1, Column: 1, Fingerprint: "a.go:generic-api-key:3333"},
		{RuleID: "generic-api-key", File: "b.go", Line: 3, Column: 8, Fingerprint: "b.go:generic-api-key:4444"},
	}

	fingerprintsOf := func(fs []finding.Finding) []string {
		out := make([]string, len(fs))
		for i, f := range fs {
			out[i] = f.Fingerprint
		}
		return out
	}

	base := slices.Clone(tied)
	finding.Sort(base)
	want := fingerprintsOf(base)

	// Every permutation of the same set must sort to the same sequence.
	perm := slices.Clone(tied)
	for i := range perm {
		shuffled := slices.Clone(tied)
		// Rotate by i to get a different input order each round.
		shuffled = append(shuffled[i:], shuffled[:i]...)
		finding.Sort(shuffled)
		assert.Equal(t, want, fingerprintsOf(shuffled),
			"Sort must be a total order: rotation %d produced a different sequence", i)
	}

	// And the order itself must be the documented File → Line → Column → RuleID.
	assert.Equal(t, []string{
		"a.go:generic-api-key:3333",
		"a.go:aws-access-token:2222",
		"a.go:generic-api-key:1111",
		"a.go:github-oauth:1111",
		"b.go:generic-api-key:4444",
	}, want)
}

// TestNewAt covers the positional redaction constructor, including the fallback
// that protects against a caller passing an offset that does not describe the
// secret. NewAt exists because search-based replacement rewrote every occurrence
// of the secret's bytes, which mangled unrelated context and could splice
// adjacent redactions back into the raw value.
func TestNewAt(t *testing.T) {
	const secret = "S3cretPassw0rdLong12"
	redacted := finding.RedactSecret(secret)

	t.Run("redacts only the span at the given offset", func(t *testing.T) {
		ctx := "db://user:" + secret + "@host"
		f := finding.NewAt("connection-string", "a.go", 1, 11, secret, ctx, len("db://user:"), false)
		assert.Equal(t, "db://user:"+redacted+"@host", f.Match)
		assert.Equal(t, redacted, f.Secret)
		assert.NotContains(t, f.Match, secret, "the raw secret must not survive")
	})

	t.Run("leaves an identical byte run elsewhere untouched", func(t *testing.T) {
		// The host repeats the password verbatim. Search-based replacement
		// rewrote BOTH, so the operator could not tell which host leaked.
		ctx := "db://u:" + secret + "@" + secret
		f := finding.NewAt("connection-string", "a.go", 1, 8, secret, ctx, len("db://u:"), false)
		assert.Equal(t, "db://u:"+redacted+"@"+secret, f.Match,
			"only the matched span is redacted; the repeat in the host stays intact")
		assert.Equal(t, 1, strings.Count(f.Match, redacted), "exactly one substitution")
	})

	t.Run("falls back to search when the offset is wrong", func(t *testing.T) {
		ctx := "prefix " + secret + " suffix"
		for name, offset := range map[string]int{
			"negative":    -1,
			"past end":    len(ctx) + 10,
			"mismatched":  0,
			"overlapping": len(ctx) - 2,
		} {
			t.Run(name, func(t *testing.T) {
				f := finding.NewAt("r", "a.go", 1, 1, secret, ctx, offset, false)
				assert.NotContains(t, f.Match, secret,
					"a bad offset must still redact, never emit the raw secret")
				assert.Equal(t, redacted, f.Secret)
			})
		}
	})

	t.Run("agrees with New on fingerprint and redaction", func(t *testing.T) {
		ctx := "k = " + secret
		viaNew := finding.New("r", "a.go", 2, 5, secret, ctx, true)
		viaAt := finding.NewAt("r", "a.go", 2, 5, secret, ctx, len("k = "), true)
		assert.Equal(t, viaNew.Fingerprint, viaAt.Fingerprint, "fingerprint is content-based")
		assert.Equal(t, viaNew.Secret, viaAt.Secret)
		assert.Equal(t, viaNew.Match, viaAt.Match, "single occurrence: both paths agree")
		assert.Equal(t, viaNew.IsHeuristic, viaAt.IsHeuristic)
	})
}
