// Package finding defines the Finding data model for Mimir secret scanner.
//
// SECURITY INVARIANT: This package enforces redact-at-boundary.
// The raw secret value is used only to compute the fingerprint and the
// redacted snippet inside New(). It is never stored in any exported field.
// The reflect-inspection test in finding_test.go is the regression guard.
package finding

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
)

// toSlash converts path separators to forward slashes unconditionally.
// filepath.ToSlash is a no-op on non-Windows, so the ReplaceAll is what actually
// normalizes backslashes on every platform — which is what fingerprint stability
// across platforms requires.
func toSlash(path string) string {
	return strings.ReplaceAll(path, `\`, "/")
}

// Finding represents a single detected secret. All secret values are redacted —
// the raw value never appears in any exported field.
type Finding struct {
	RuleID      string `json:"rule_id"`
	File        string `json:"file"`        // repo-relative, forward-slash
	Line        int    `json:"line"`        // 1-indexed
	Column      int    `json:"column"`      // 1-indexed
	Match       string `json:"match"`       // surrounding context, redacted
	Secret      string `json:"secret"`      // token, redacted; NEVER raw value
	Fingerprint string `json:"fingerprint"` // path:rule_id:sha256[:16]
	IsHeuristic bool   `json:"is_heuristic,omitempty"`

	// Suppressed and SuppressionReason (D-12) are populated by the suppression
	// layers when a finding is withheld but still surfaced via --show-suppressed.
	// Both are omitempty so the Phase 1 OUT-02 schema is byte-identical for
	// findings that are not suppressed. They carry only a bool and an enum-like
	// reason string ("baseline" | "inline-ignore" | "allowlist") — never a raw
	// secret, preserving the redact-at-boundary invariant above.
	Suppressed        bool   `json:"suppressed,omitempty"`
	SuppressionReason string `json:"suppression_reason,omitempty"`

	// CommitSHA, CommitAuthor, and CommitDate (D-08) carry git provenance for
	// findings sourced from history scans (mimir scan --git). They are populated
	// by internal/gitscan AFTER New() returns — never inside New() and never by
	// computeFingerprint (D-09), so the fingerprint stays content-based and
	// commit-independent (the same secret across many commits shares one
	// fingerprint). All three are omitempty: working-tree and staged findings
	// leave them empty, keeping the Phase 1 OUT-02 JSON schema byte-identical for
	// non-history scans. They carry only non-secret git metadata (a commit hash,
	// an author name, and an RFC3339 date) — never a raw secret, preserving the
	// redact-at-boundary invariant above.
	CommitSHA    string `json:"commit_sha,omitempty"`
	CommitAuthor string `json:"commit_author,omitempty"`
	CommitDate   string `json:"commit_date,omitempty"` // RFC3339 from PatchHeader.AuthorDate

	// Verification (Phase 4) carries the result of opt-in live verification
	// (mimir scan --verify). Like CommitSHA above, it is populated AFTER New()
	// returns — by internal/verify in a later wave — never inside New() and never
	// by computeFingerprint, so the fingerprint stays content-based. It is a
	// pointer with omitempty so non-verify scans leave it nil and the marshalled
	// JSON is byte-identical to the frozen Phase 1 OUT-02 schema (a non-pointer
	// struct would serialize "verification":{...} on every finding). It carries
	// ONLY two non-secret enum strings (a three-state status and a provider name)
	// — never a raw secret, preserving the redact-at-boundary invariant above.
	Verification *Verification `json:"verification,omitempty"`
}

// Verification holds the result of an opt-in live verification check for a
// finding (mimir scan --verify). It carries ONLY non-secret enum values and is
// never part of computeFingerprint.
//
// SECURITY: This struct must NOT gain a secret-bearing field. The raw secret is
// carried entirely off-struct (see internal/detect and internal/verify); only
// the resulting status/provider enums are recorded here.
type Verification struct {
	// Status is the three-state verification outcome: "active" | "inactive" | "unknown".
	Status string `json:"status"`
	// Provider identifies which verifier produced the result: "aws" | "github".
	Provider string `json:"provider"`
}

// Sort orders findings deterministically, in place. Every scan source (working
// tree, git history, staged diff) sorts through this one function so output and
// baselines stay diff-stable across modes.
//
// The order is File → Line → Column → RuleID → Fingerprint. The first three are
// the reported location; the last two are tiebreakers, and they are load-bearing
// rather than decorative. Two rules can match the SAME secret at the SAME
// file:line:column (e.g. a `token: gho_...` line matches both github-oauth and
// the generic-api-key heuristic). On a File/Line/Column-only comparator those
// two compare equal, and since the concurrent walk appends findings in
// goroutine-completion order, an unstable sort was free to emit them in either
// order — so consecutive scans of an unchanged tree produced different output
// and therefore different baselines. Extending the comparator to a total order
// makes the result independent of both goroutine timing and sort stability.
func Sort(findings []Finding) {
	slices.SortFunc(findings, func(a, b Finding) int {
		if c := strings.Compare(a.File, b.File); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Line, b.Line); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Column, b.Column); c != 0 {
			return c
		}
		if c := strings.Compare(a.RuleID, b.RuleID); c != 0 {
			return c
		}
		return strings.Compare(a.Fingerprint, b.Fingerprint)
	})
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
