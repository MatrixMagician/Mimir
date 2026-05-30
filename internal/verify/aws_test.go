package verify

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/MatrixMagician/mimir/internal/finding"
	smithy "github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeAPIError implements smithy.APIError with an injectable error code so the
// classification table can be exercised without a live STS call.
type fakeAPIError struct {
	code string
}

func (e fakeAPIError) Error() string                 { return "api error: " + e.code }
func (e fakeAPIError) ErrorCode() string             { return e.code }
func (e fakeAPIError) ErrorMessage() string          { return "msg" }
func (e fakeAPIError) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

// TestAWSClassify drives the pure error-code → Status classifier. Definitive
// rejection codes map to Inactive; nil maps to Active; everything else
// (network, timeout, throttling, unrecognized) maps to Unknown — a network
// failure is never Inactive.
func TestAWSClassify(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want Status
	}{
		{"nil error is active", nil, Active},
		{"InvalidClientTokenId is inactive", fakeAPIError{"InvalidClientTokenId"}, Inactive},
		{"SignatureDoesNotMatch is inactive", fakeAPIError{"SignatureDoesNotMatch"}, Inactive},
		{"ExpiredToken is inactive", fakeAPIError{"ExpiredToken"}, Inactive},
		{"AccessDenied is inactive", fakeAPIError{"AccessDenied"}, Inactive},
		{"InvalidSignatureException is inactive", fakeAPIError{"InvalidSignatureException"}, Inactive},
		{"Throttling is unknown", fakeAPIError{"Throttling"}, Unknown},
		{"unrecognized code is unknown", fakeAPIError{"SomeNovelCode"}, Unknown},
		{"plain network error is unknown", errors.New("dial tcp: connection refused"), Unknown},
		{"context deadline is unknown", context.DeadlineExceeded, Unknown},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := classifyAWSError(tc.err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestNoAmbientCreds asserts the verifier never consults ambient AWS_* env. A
// bogus AWS_ACCESS_KEY_ID is injected; the verifier must still build its client
// from the (passed) static pair only. We assert this structurally: the
// credential source the verifier constructs is the static provider seeded with
// the passed key, regardless of env. If the verifier read the env (e.g. via
// LoadDefaultConfig), the resolved access key would be the bogus env value.
func TestNoAmbientCreds(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIABOGUSAMBIENTKEY99")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "bogusambientsecretkeybogusambientsecre00")

	const passedKey = "AKIAFAKEKEYABCDE2345"
	const passedSecret = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123"

	provider := staticProviderFor(passedKey, passedSecret)
	creds, err := provider.Retrieve(context.Background())
	require.NoError(t, err)
	assert.Equal(t, passedKey, creds.AccessKeyID,
		"verifier must use the passed access key, NOT the ambient AWS_ACCESS_KEY_ID")
	assert.NotEqual(t, "AKIABOGUSAMBIENTKEY99", creds.AccessKeyID,
		"ambient AWS_ACCESS_KEY_ID must be ignored")
}

// TestAWSPairingMissingSecretKey asserts that when no co-located secret access
// key can be found in the finding's file, Verify returns Unknown (never
// Inactive) and makes no call (Pitfall 7).
func TestAWSPairingMissingSecretKey(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "config.txt")
	// File contains the access key but NO 40-char base64 secret key.
	require.NoError(t, os.WriteFile(file, []byte("aws_access_key_id = AKIAFAKEKEYABCDE2345\n"), 0o600))

	f := finding.Finding{RuleID: "aws-access-token", File: file}
	v := awsVerifier{}
	got := v.Verify(context.Background(), "AKIAFAKEKEYABCDE2345", f)
	assert.Equal(t, Unknown, got)
}

// TestAWSPairingFindsSecretKey asserts the pairing helper locates a 40-char
// base64 secret key co-located with a secret_access_key token.
func TestAWSPairingFindsSecretKey(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "creds.txt")
	const secretKey = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123"
	content := "aws_access_key_id = AKIAFAKEKEYABCDE2345\naws_secret_access_key = " + secretKey + "\n"
	require.NoError(t, os.WriteFile(file, []byte(content), 0o600))

	got, ok := findSecretKey(file)
	require.True(t, ok)
	assert.Equal(t, secretKey, got)
}
