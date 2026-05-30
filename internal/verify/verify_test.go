package verify

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegistry asserts the rule-ID → verifier provider mappings: the AWS
// access-key rule maps to an "aws" verifier, the five GitHub rule IDs map to a
// "github" verifier, and rule IDs for other providers are absent (those
// findings are left unlabeled).
func TestRegistry(t *testing.T) {
	t.Run("aws rule maps to aws verifier", func(t *testing.T) {
		v, ok := registry["aws-access-token"]
		require.True(t, ok, "aws-access-token must be registered")
		assert.Equal(t, "aws", v.Provider())
	})

	githubIDs := []string{
		"github-pat",
		"github-oauth",
		"github-app-token",
		"github-refresh-token",
		"github-fine-grained-pat",
	}
	for _, id := range githubIDs {
		id := id
		t.Run("github rule "+id+" maps to github verifier", func(t *testing.T) {
			v, ok := registry[id]
			require.True(t, ok, "%s must be registered", id)
			assert.Equal(t, "github", v.Provider())
		})
	}

	absent := []string{"gcp-api-key", "stripe-access-token", "gitlab-pat", "slack-token"}
	for _, id := range absent {
		id := id
		t.Run("non-verifiable rule "+id+" is absent", func(t *testing.T) {
			_, ok := registry[id]
			assert.False(t, ok, "%s must NOT be registered (left unlabeled)", id)
		})
	}
}

// TestSanitizedErrorNoSecret asserts the sanitizedError surfaces only the
// provider and a reason enum — never a secret. It is the type all verifiers use
// on their error paths so no SDK/HTTP error (which may embed the token) leaks.
func TestSanitizedErrorNoSecret(t *testing.T) {
	const secret = "AKIAFAKEKEYABCDE2345"
	err := sanitizedError{provider: "aws", reason: reasonAPIError}
	msg := err.Error()
	assert.NotContains(t, msg, secret)
	assert.Contains(t, msg, "aws")
	assert.Contains(t, msg, string(reasonAPIError))
}

// TestStatusValues pins the three-state enum string values, which are written
// verbatim into finding.Verification.Status and the JSON schema.
func TestStatusValues(t *testing.T) {
	assert.Equal(t, "active", string(Active))
	assert.Equal(t, "inactive", string(Inactive))
	assert.Equal(t, "unknown", string(Unknown))
}
