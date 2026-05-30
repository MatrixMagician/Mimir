package output_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/MatrixMagician/mimir/internal/finding"
	"github.com/MatrixMagician/mimir/internal/output"
)

// TestVerifyOmittedByDefault proves the omitempty pointer behavior end-to-end
// through WriteJSON: a finding with nil Verification omits the "verification"
// key (OUT-02 byte-identical), while a finding with Verification set emits the
// nested {"status","provider"} object.
func TestVerifyOmittedByDefault(t *testing.T) {
	t.Run("nil verification omits key", func(t *testing.T) {
		f := finding.New("aws-access-token", "src/config.go", 3, 21, "AKIAFAKEKEYABCDE2345", "context", false)
		var buf bytes.Buffer
		require.NoError(t, output.WriteJSON(&buf, []finding.Finding{f}, makeStats(1, time.Millisecond)))
		assert.NotContains(t, buf.String(), "verification",
			"nil Verification must drop the verification key (omitempty)")
	})

	t.Run("set verification emits nested object", func(t *testing.T) {
		f := finding.New("aws-access-token", "src/config.go", 3, 21, "AKIAFAKEKEYABCDE2345", "context", false)
		f.Verification = &finding.Verification{Status: "active", Provider: "aws"}
		var buf bytes.Buffer
		require.NoError(t, output.WriteJSON(&buf, []finding.Finding{f}, makeStats(1, time.Millisecond)))
		out := buf.String()
		assert.Contains(t, out, `"verification"`)
		assert.Contains(t, out, `"status": "active"`)
		assert.Contains(t, out, `"provider": "aws"`)
	})
}
