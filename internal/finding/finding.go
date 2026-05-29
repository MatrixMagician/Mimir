// Package finding defines the Finding data model for Mimir secret scanner.
//
// SECURITY INVARIANT: This package enforces redact-at-boundary.
// The raw secret value is used only to compute the fingerprint and the
// redacted snippet inside New(). It is never stored in any exported field.
// The reflect-inspection test in finding_test.go is the regression guard.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
)

// toSlash converts path separators to forward slashes unconditionally.
// filepath.ToSlash is a no-op on non-Windows; this function normalizes
// backslashes on all platforms for cross-platform fingerprint stability.
func toSlash(path string) string {
	return filepath.ToSlash(strings.ReplaceAll(path, `\`, "/"))
}

// Finding represents a single detected secret. All secret values are redacted —
// the raw value never appears in any exported field.
type Finding struct {
	RuleID      string  `json:"rule_id"`
	Description string  `json:"description,omitempty"`
	File        string  `json:"file"`        // repo-relative, forward-slash
	Line        int     `json:"line"`        // 1-indexed
	Column      int     `json:"column"`      // 1-indexed
	Match       string  `json:"match"`       // surrounding context, redacted
	Secret      string  `json:"secret"`      // token, redacted; NEVER raw value
	Fingerprint string  `json:"fingerprint"` // path:rule_id:sha256[:16]
	Entropy     float32 `json:"entropy,omitempty"`
	IsHeuristic bool    `json:"is_heuristic,omitempty"`

	// Suppressed and SuppressionReason (D-12) are populated by the suppression
	// layers when a finding is withheld but still surfaced via --show-suppressed.
	// Both are omitempty so the Phase 1 OUT-02 schema is byte-identical for
	// findings that are not suppressed. They carry only a bool and an enum-like
	// reason string ("baseline" | "inline-ignore" | "allowlist") — never a raw
	// secret, preserving the redact-at-boundary invariant above.
	Suppressed        bool   `json:"suppressed,omitempty"`
	SuppressionReason string `json:"suppression_reason,omitempty"`
}

// minVisibleLen is the D-05 guardrail threshold: secrets shorter than this
// are fully masked (to avoid revealing too high a percentage of the value).
const minVisibleLen = 16

// RedactSecret applies structural-prefix + last-4-peek redaction (D-04).
// If the secret is shorter than minVisibleLen (16), returns "[REDACTED]" (D-05).
//
// Examples:
//
//	AKIAIOSFODNN7EXAMPLE → AKIA****...****MPLE
//	ghp_abc123def456GHI789jkl012 → ghp_****...****l012
//	hunter2 (7 chars) → [REDACTED]
func RedactSecret(secret string) string {
	if len(secret) < minVisibleLen {
		return "[REDACTED]"
	}
	// Show first 4 chars (structural prefix) + last 4 chars
	return secret[:4] + "****...****" + secret[len(secret)-4:]
}

// computeFingerprint returns a stable content-hash fingerprint for a finding.
// Format: <repo-relative-path>:<rule-id>:<sha256[:16](raw_secret)>
//
// The path is normalized to forward slashes for cross-platform stability.
// The hash prefix encodes the raw secret value so the fingerprint survives
// line-number changes (unlike gitleaks' line-number fingerprint).
func computeFingerprint(repoRelPath, ruleID, rawSecret string) string {
	// Normalize path separator for Windows compatibility (always, not just on Windows)
	normalizedPath := toSlash(repoRelPath)
	// Hash the raw secret value
	h := sha256.Sum256([]byte(rawSecret))
	hashPrefix := hex.EncodeToString(h[:])[:16] // first 8 bytes = 16 hex chars
	return normalizedPath + ":" + ruleID + ":" + hashPrefix
}

// New constructs a Finding with redaction applied at the boundary.
//
// The rawSecret parameter is used only to compute the fingerprint and the
// redacted representation. It is not stored in any field of the returned
// Finding. After this function returns, rawSecret goes out of scope.
//
// Parameters:
//   - ruleID: the rule that matched (e.g. "aws-access-token")
//   - file: repo-relative file path (forward-slash normalized)
//   - line: 1-indexed line number
//   - col: 1-indexed column where the secret starts
//   - rawSecret: the matched secret value (NEVER stored in any field)
//   - matchContext: surrounding line context (raw secret will be redacted here)
//   - isHeuristic: true for generic-* entropy-based rules
func New(ruleID, file string, line, col int, rawSecret, matchContext string, isHeuristic bool) Finding {
	// Compute fingerprint from raw secret BEFORE redacting
	fp := computeFingerprint(file, ruleID, rawSecret)

	// Redact the secret in the match context string
	redactedMatch := strings.ReplaceAll(matchContext, rawSecret, RedactSecret(rawSecret))

	return Finding{
		RuleID:      ruleID,
		File:        file,
		Line:        line,
		Column:      col,
		Match:       redactedMatch,
		Secret:      RedactSecret(rawSecret),
		Fingerprint: fp,
		IsHeuristic: isHeuristic,
	}
	// rawSecret goes out of scope here — not stored in any field
}
