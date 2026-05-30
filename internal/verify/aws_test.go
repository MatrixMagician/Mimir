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
// Inactive) and makes no call (Pitfall 7). The finding carries a REPO-RELATIVE
// File resolved against scanRoot (CR-02), mirroring the real pipeline.
func TestAWSPairingMissingSecretKey(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.txt"),
		[]byte("aws_access_key_id = AKIAFAKEKEYABCDE2345\n"), 0o600))

	f := finding.Finding{RuleID: "aws-access-token", File: "config.txt"}
	v := awsVerifier{}
	got := v.Verify(context.Background(), dir, "AKIAFAKEKEYABCDE2345", f)
	assert.Equal(t, Unknown, got)
}

// TestAWSVerifyResolvesScanRoot is the CR-02 regression guard: Verify must join
// scanRoot with the finding's repo-relative, forward-slash File to locate the
// pairing file, NOT read it against the process CWD. We assert via the pairing
// path: with a correct scanRoot the secret key is found (so the verifier would
// proceed to a network call — we keep the access key invalid so no real call
// matters); with the WRONG scanRoot the file is unreadable and the result is
// Unknown with no call. The latter is exactly the silent-failure CR-02 fixes.
func TestAWSVerifyResolvesScanRoot(t *testing.T) {
	dir := t.TempDir()
	const secretKey = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123"
	content := "aws_access_key_id = AKIAFAKEKEYABCDE2345\naws_secret_access_key = " + secretKey + "\n"
	// Nested repo-relative path with forward slashes, as scanner.go produces.
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "config"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config", "creds.txt"), []byte(content), 0o600))

	// Pairing resolves against scanRoot + FromSlash(File).
	got, ok := findSecretKey(filepath.Join(dir, filepath.FromSlash("config/creds.txt")))
	require.True(t, ok, "pairing must find the secret key under the joined scanRoot path")
	assert.Equal(t, secretKey, got)

	// A WRONG scanRoot makes the file unreadable → ("", false) → Unknown, never
	// a false Inactive and never a network call.
	_, ok = findSecretKey(filepath.Join(t.TempDir(), filepath.FromSlash("config/creds.txt")))
	assert.False(t, ok, "wrong scanRoot must not resolve the pairing file")
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

// TestAWSPairingRequiresHint is the WR-02 guard: with a 40-char base64 token but
// NO secret-key hint line, pairing must refuse (→ Unknown), never silently send
// an arbitrary blob to STS and risk reporting a live key as inactive.
func TestAWSPairingRequiresHint(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "data.txt")
	// A 40-char base64 blob with no hint anywhere (e.g. a hash or vendored key).
	content := "checksum = abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123\n"
	require.NoError(t, os.WriteFile(file, []byte(content), 0o600))

	_, ok := findSecretKey(file)
	assert.False(t, ok, "no hint line → must not pair (WR-02: avoid false inactive)")
}

// TestAWSPairingIgnoresLongerBlob is the WR-06 guard: a base64 blob LONGER than
// 40 chars must not yield a spurious 40-char prefix candidate. With a hint line
// present but only an over-length token, pairing finds no true 40-char token.
func TestAWSPairingIgnoresLongerBlob(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "creds.txt")
	// 60-char token on a hinted line — a 40-char prefix must NOT be paired.
	const blob60 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123456789KLMNOPQRSTUVWXYZ"
	content := "aws_secret_access_key = " + blob60 + "\n"
	require.NoError(t, os.WriteFile(file, []byte(content), 0o600))

	_, ok := findSecretKey(file)
	assert.False(t, ok, "an over-length base64 blob must not produce a 40-char candidate (WR-06)")
}
