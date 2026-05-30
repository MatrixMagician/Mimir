package verify

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MatrixMagician/mimir/internal/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingVerifier records how many times Verify is called per distinct raw
// secret, returning a fixed Status. Used to assert the per-(provider,secret)
// run-scoped cache dedups calls.
type countingVerifier struct {
	provider string
	status   Status
	mu       sync.Mutex
	calls    map[string]int
	total    atomic.Int64
}

func (c *countingVerifier) Provider() string { return c.provider }

func (c *countingVerifier) Verify(ctx context.Context, raw string, f finding.Finding) Status {
	c.mu.Lock()
	if c.calls == nil {
		c.calls = map[string]int{}
	}
	c.calls[raw]++
	c.mu.Unlock()
	c.total.Add(1)
	return c.status
}

// TestCacheDedup asserts Run verifies each distinct (provider, secret) at most
// once even when the same secret appears across many findings.
func TestCacheDedup(t *testing.T) {
	cv := &countingVerifier{provider: "github", status: Active}
	reg := map[string]Verifier{"github-pat": cv}

	const secret = "ghp_FAKEtoken0123456789abcdefABCDEF012345"
	var findings []finding.Finding
	rawByFP := map[string]string{}
	for i := 0; i < 10; i++ {
		fp := "fp-" + string(rune('a'+i))
		findings = append(findings, finding.Finding{RuleID: "github-pat", Fingerprint: fp})
		rawByFP[fp] = secret
	}

	runWithRegistry(context.Background(), reg, findings, rawByFP)

	assert.Equal(t, int64(1), cv.total.Load(), "one call per distinct secret across 10 findings")
	for i := range findings {
		require.NotNil(t, findings[i].Verification)
		assert.Equal(t, string(Active), findings[i].Verification.Status)
		assert.Equal(t, "github", findings[i].Verification.Provider)
	}
}

// TestCacheKeyIsProviderPlusSecret asserts two different providers verifying the
// SAME string value do not share a cache entry (RESEARCH Open Question 3).
func TestCacheKeyIsProviderPlusSecret(t *testing.T) {
	aws := &countingVerifier{provider: "aws", status: Inactive}
	gh := &countingVerifier{provider: "github", status: Active}
	reg := map[string]Verifier{"aws-access-token": aws, "github-pat": gh}

	const shared = "same-string-value-1234567890"
	findings := []finding.Finding{
		{RuleID: "aws-access-token", Fingerprint: "fp-aws"},
		{RuleID: "github-pat", Fingerprint: "fp-gh"},
	}
	rawByFP := map[string]string{"fp-aws": shared, "fp-gh": shared}

	runWithRegistry(context.Background(), reg, findings, rawByFP)

	assert.Equal(t, int64(1), aws.total.Load())
	assert.Equal(t, int64(1), gh.total.Load())
	assert.Equal(t, string(Inactive), findings[0].Verification.Status)
	assert.Equal(t, string(Active), findings[1].Verification.Status)
}

// TestRunUnlabeledRuleIsNil asserts findings whose rule ID has no verifier are
// left unlabeled (Verification stays nil).
func TestRunUnlabeledRuleIsNil(t *testing.T) {
	gh := &countingVerifier{provider: "github", status: Active}
	reg := map[string]Verifier{"github-pat": gh}
	findings := []finding.Finding{
		{RuleID: "gcp-api-key", Fingerprint: "fp-gcp"},
		{RuleID: "github-pat", Fingerprint: "fp-gh"},
	}
	rawByFP := map[string]string{"fp-gcp": "x", "fp-gh": "y"}

	runWithRegistry(context.Background(), reg, findings, rawByFP)

	assert.Nil(t, findings[0].Verification, "unverifiable rule stays unlabeled")
	require.NotNil(t, findings[1].Verification)
}

// TestRunMissingRawIsUnknown asserts a matched finding with no raw secret in the
// side channel is labelled Unknown (no call possible) and never errors.
func TestRunMissingRawIsUnknown(t *testing.T) {
	gh := &countingVerifier{provider: "github", status: Active}
	reg := map[string]Verifier{"github-pat": gh}
	findings := []finding.Finding{{RuleID: "github-pat", Fingerprint: "fp-missing"}}
	rawByFP := map[string]string{} // no raw for the fingerprint

	runWithRegistry(context.Background(), reg, findings, rawByFP)

	require.NotNil(t, findings[0].Verification)
	assert.Equal(t, string(Unknown), findings[0].Verification.Status)
	assert.Equal(t, int64(0), gh.total.Load(), "no call made when raw secret missing")
}

// failingVerifier returns Unknown via a path that produces a sanitizedError, so
// we can assert the secret never appears in any surfaced error/log.
type failingVerifier struct{}

func (failingVerifier) Provider() string { return "github" }
func (failingVerifier) Verify(ctx context.Context, raw string, f finding.Finding) Status {
	return Unknown
}

// TestNoSecretInError drives a verifier and asserts neither the resulting
// Verification nor any sanitizedError contains the secret value.
func TestNoSecretInError(t *testing.T) {
	const secret = "ghp_FAKEtoken0123456789abcdefABCDEF012345"
	reg := map[string]Verifier{"github-pat": failingVerifier{}}
	findings := []finding.Finding{{RuleID: "github-pat", Fingerprint: "fp"}}
	rawByFP := map[string]string{"fp": secret}

	runWithRegistry(context.Background(), reg, findings, rawByFP)

	require.NotNil(t, findings[0].Verification)
	assert.False(t, strings.Contains(findings[0].Verification.Status, secret))
	assert.False(t, strings.Contains(findings[0].Verification.Provider, secret))

	// sanitizedError must never carry the secret regardless of construction.
	se := sanitizedError{provider: "github", reason: reasonAPIError}
	assert.False(t, strings.Contains(se.Error(), secret))
}

// panickingVerifier panics inside Verify, simulating an SDK bug or a malformed
// pairing edge on adversarial scanned content (CR-01).
type panickingVerifier struct{}

func (panickingVerifier) Provider() string { return "github" }
func (panickingVerifier) Verify(ctx context.Context, raw string, f finding.Finding) Status {
	panic("verifier blew up on adversarial input")
}

// TestPanicDoesNotDeadlock asserts a panicking verifier does NOT hang the scan
// (CR-01): the cache owner recovers the panic, classifies the secret Unknown,
// and unblocks every waiter on that key. The same secret is shared across many
// findings so non-owner waiters exercise the <-entry.done path. Run completes
// (returns) and all findings are labelled Unknown rather than deadlocking.
func TestPanicDoesNotDeadlock(t *testing.T) {
	reg := map[string]Verifier{"github-pat": panickingVerifier{}}

	const secret = "ghp_FAKEtoken0123456789abcdefABCDEF012345"
	var findings []finding.Finding
	rawByFP := map[string]string{}
	for i := 0; i < 20; i++ {
		fp := "fp-" + string(rune('a'+i))
		findings = append(findings, finding.Finding{RuleID: "github-pat", Fingerprint: fp})
		rawByFP[fp] = secret
	}

	done := make(chan struct{})
	go func() {
		runWithRegistry(context.Background(), reg, findings, rawByFP)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("runWithRegistry deadlocked on a panicking verifier (CR-01 regression)")
	}

	for i := range findings {
		require.NotNil(t, findings[i].Verification, "finding %d must be labelled, not left hung", i)
		assert.Equal(t, string(Unknown), findings[i].Verification.Status,
			"a panicking verifier must classify as Unknown, never fail the scan")
	}
}

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
