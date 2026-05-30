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

// ScanSummary holds aggregate stats about the scan run. The first three fields
// are frozen (OUT-02); the Phase 2 fields are additive and omitempty so the
// default schema is byte-identical to Phase 1 when nothing was suppressed.
type ScanSummary struct {
	FilesScanned  int            `json:"files_scanned"`
	FindingCount  int            `json:"finding_count"`
	DurationMs    int64          `json:"duration_ms"`
	PathsExcluded int            `json:"paths_excluded,omitempty"` // D-13
	Suppressed    map[string]int `json:"suppressed,omitempty"`     // D-11: reason -> count
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
			FilesScanned:  stats.FilesScanned,
			FindingCount:  len(findings),
			DurationMs:    stats.Duration.Milliseconds(),
			PathsExcluded: stats.PathsExcluded,
			Suppressed:    emptyToNil(stats.Suppressed),
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// emptyToNil returns nil for an empty map so the omitempty Suppressed field is
// dropped entirely (preserving the OUT-02 byte-identical schema when nothing was
// suppressed) rather than serializing as "suppressed":{}.
func emptyToNil(m map[string]int) map[string]int {
	if len(m) == 0 {
		return nil
	}
	return m
}
