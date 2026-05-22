package output

import (
	"encoding/json"
	"io"

	"github.com/MatrixMagician/mimir/internal/finding"
	"github.com/MatrixMagician/mimir/internal/scanner"
)

// ScanResult is the top-level JSON envelope for scan output (OUT-02 stable schema).
// Field names are frozen after v1 ships — downstream tooling depends on them.
type ScanResult struct {
	Findings []finding.Finding `json:"findings"`
	Summary  ScanSummary       `json:"summary"`
}

// ScanSummary holds aggregate stats about the scan run.
type ScanSummary struct {
	FilesScanned int   `json:"files_scanned"`
	FindingCount int   `json:"finding_count"`
	DurationMs   int64 `json:"duration_ms"`
}

// WriteJSON encodes findings and stats as a JSON ScanResult to w.
// findings already have redacted Secret fields — no raw value is present (OUT-03).
// Output is indented for human readability and machine parseability.
func WriteJSON(w io.Writer, findings []finding.Finding, stats scanner.Stats) error {
	// Ensure findings is never null in JSON (use empty slice, not nil)
	if findings == nil {
		findings = []finding.Finding{}
	}

	result := ScanResult{
		Findings: findings,
		Summary: ScanSummary{
			FilesScanned: stats.FilesScanned,
			FindingCount: len(findings),
			DurationMs:   stats.Duration.Milliseconds(),
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
