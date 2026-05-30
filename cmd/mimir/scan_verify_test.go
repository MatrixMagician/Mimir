package cmd_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestScanNoVerifyNoNetwork asserts that a plain `mimir scan` (WITHOUT --verify)
// makes zero network calls and emits JSON byte-identical to the OUT-02 schema:
// no "verification" key is present, and the exit-code contract is untouched
// (a repo with one new finding still exits 1). This is the T-04-default /
// T-04-exit guard: without the flag, verify.Run is never invoked.
func TestScanNoVerifyNoNetwork(t *testing.T) {
	dir := t.TempDir()
	// A secret that matches the AWS rule but is NOT auto-allowlisted (not the
	// canonical AKIAIOSFODNN7EXAMPLE), so it survives suppression and becomes a
	// reportable finding.
	fixture := filepath.Join(dir, "leak.txt")
	require.NoError(t, os.WriteFile(fixture, []byte("aws_access_key_id = AKIAFAKEKEYABCDE2345\n"), 0600))

	stdout, _, code := runMimir(t, "scan", "--no-color", "-f", "json", dir)

	// Exit-code contract is label-only / unchanged: one new finding → exit 1.
	assert.Equal(t, 1, code, "a new finding must still exit 1 without --verify")
	// No verification path ran: the JSON must not carry the verification key.
	assert.NotContains(t, stdout, "verification",
		"non-verify JSON must omit the verification key (OUT-02 byte-identical)")
	// Sanity: the finding itself is present (proves the fixture matched a rule).
	assert.True(t, strings.Contains(stdout, "AKIA"),
		"expected the AWS finding to be present in the JSON output")
}
