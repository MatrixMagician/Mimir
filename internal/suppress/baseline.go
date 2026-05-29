package suppress

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/MatrixMagician/mimir/internal/finding"
)

// BaselineReason is the SuppressionReason value set on findings withheld because
// they match a baseline snapshot (D-08..D-10).
const BaselineReason = "baseline"

// baselineEnvelope is the on-disk baseline schema. The version field is for
// forward-compatibility with future merge tooling (A2); findings reuse the
// redacted Finding JSON schema so the baseline never stores a raw secret.
type baselineEnvelope struct {
	Version     int               `json:"version"`
	GeneratedAt string            `json:"generated_at,omitempty"`
	Findings    []finding.Finding `json:"findings"`
}

// Baseline holds the suppression keys derived from a finding snapshot: the full
// fingerprints AND the path-independent content keys (rule-id:hash16) so a
// baselined finding survives a file move (D-10 OR-match, Pitfall 4).
type Baseline struct {
	fingerprints map[string]struct{}
	contentKeys  map[string]struct{}
}

// contentKey returns the path-independent key (rule-id:hash16): the LAST TWO
// colon-segments of a fingerprint (path:rule-id:hash16). Taking the last two
// segments tolerates a path that itself contains colons.
func contentKey(fingerprint string) string {
	parts := strings.Split(fingerprint, ":")
	if len(parts) < 2 {
		return fingerprint
	}
	return parts[len(parts)-2] + ":" + parts[len(parts)-1]
}

// newBaseline builds the fingerprint and content-key sets from a snapshot.
func newBaseline(findings []finding.Finding) *Baseline {
	b := &Baseline{
		fingerprints: make(map[string]struct{}, len(findings)),
		contentKeys:  make(map[string]struct{}, len(findings)),
	}
	for _, f := range findings {
		if f.Fingerprint == "" {
			continue
		}
		b.fingerprints[f.Fingerprint] = struct{}{}
		b.contentKeys[contentKey(f.Fingerprint)] = struct{}{}
	}
	return b
}

// LoadBaseline reads a baseline JSON file. A missing file returns an empty
// (non-nil) Baseline and a nil error — the first-run case (D-08).
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return newBaseline(nil), nil
		}
		return nil, err
	}
	var env baselineEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parsing baseline %q: %w", path, err)
	}
	return newBaseline(env.Findings), nil
}

// WriteBaseline writes findings as a baseline JSON envelope to path. The full
// finding set is written as the snapshot (A5); secrets are already redacted in
// the Finding schema.
func WriteBaseline(path string, findings []finding.Finding) error {
	env := baselineEnvelope{Version: 1, Findings: findings}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0600)
}

// IsSuppressed reports whether a finding matches the baseline by full
// fingerprint OR by path-independent content key (D-10 OR-match). The content-key
// arm is what makes a baselined finding survive a file move.
func (b *Baseline) IsSuppressed(f finding.Finding) bool {
	if b == nil || f.Fingerprint == "" {
		return false
	}
	if _, ok := b.fingerprints[f.Fingerprint]; ok {
		return true
	}
	_, ok := b.contentKeys[contentKey(f.Fingerprint)]
	return ok
}
