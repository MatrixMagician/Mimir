package finding_test

import (
	"encoding/json"
	"testing"

	"github.com/MatrixMagician/mimir/internal/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSuppressionFieldsOmitemptyWhenUnset verifies the D-12 fields do not appear
// in the JSON when unset, preserving the Phase 1 OUT-02 schema byte-for-byte for
// findings that are not suppressed.
func TestSuppressionFieldsOmitemptyWhenUnset(t *testing.T) {
	f := finding.New("aws-access-token", "src/config.go", 5, 10,
		"AKIAFAKEKEYABCDE2345", "ctx", false)

	data, err := json.Marshal(f)
	require.NoError(t, err)

	s := string(data)
	assert.NotContains(t, s, "suppressed", "omitempty must drop the suppressed key when false")
	assert.NotContains(t, s, "suppression_reason", "omitempty must drop the reason key when empty")
}

// TestSuppressionFieldsPresentWhenSet verifies both D-12 fields marshal with
// their values once a suppression layer annotates the finding.
func TestSuppressionFieldsPresentWhenSet(t *testing.T) {
	f := finding.New("aws-access-token", "src/config.go", 5, 10,
		"AKIAFAKEKEYABCDE2345", "ctx", false)
	f.Suppressed = true
	f.SuppressionReason = "baseline"

	data, err := json.Marshal(f)
	require.NoError(t, err)

	s := string(data)
	assert.Contains(t, s, `"suppressed":true`)
	assert.Contains(t, s, `"suppression_reason":"baseline"`)
}
