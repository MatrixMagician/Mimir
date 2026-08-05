package detect_test

import (
	"github.com/MatrixMagician/mimir/internal/config"
	"github.com/MatrixMagician/mimir/internal/detect"
	"github.com/MatrixMagician/mimir/internal/finding"
	"strings"
	"testing"
)

// FuzzScanLine drives the detection engine with arbitrary line content. Mimir
// scans untrusted repository data — including files an attacker may control —
// so ScanLine must never panic, and it must never leak the raw secret into a
// Finding's exported fields.
//
// The invariants asserted here are the ones a crash or a leak would violate:
//
//  1. no panic on any input (the engine slices lines by regex submatch index,
//     which is where an off-by-one would show up);
//  2. the redact-at-boundary contract — no exported string field may contain the
//     raw matched secret;
//  3. reported columns stay inside the line, so downstream renderers and editor
//     jump-links cannot be pointed out of bounds;
//  4. every finding is fingerprinted, since the fingerprint keys both the
//     baseline and the raw side channel.
func FuzzScanLine(f *testing.F) {
	cfg, err := config.LoadDefault()
	if err != nil {
		f.Fatalf("loading default config: %v", err)
	}
	engine := detect.NewEngine(cfg)

	seeds := []string{
		"",
		"aws_access_key_id = AKIAFAKEKEYABCDE2345",
		`token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"`,
		"password = ",
		"key=",
		"secret: ${VAR}",
		"url = postgres://user:hunter2@host:5432/db",
		"-----BEGIN RSA PRIVATE KEY-----",
		"api_key = \"x\" // mimir:ignore",
		// Degenerate shapes that stress the submatch-index arithmetic.
		"key=" + strings.Repeat("A", 4096),
		strings.Repeat("secret=", 512),
		"token\x00= AKIAFAKEKEYABCDE2345",
		"token = \xff\xfe\xfd",
		"密钥 = AKIAFAKEKEYABCDE2345",
		"key\u2028= AKIAFAKEKEYABCDE2345",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, line string) {
		raw := map[string]string{}
		findings := engine.ScanLine(line, "fuzz/input.go", 1, raw)

		for _, fd := range findings {
			if fd.Fingerprint == "" {
				t.Fatalf("finding with empty fingerprint for rule %q; the baseline and the raw side channel are both keyed by it", fd.RuleID)
			}
			// Column is 1-indexed and must address a byte within the line.
			if fd.Column < 1 || fd.Column > len(line)+1 {
				t.Fatalf("column %d out of range for a %d-byte line (rule %q)", fd.Column, len(line), fd.RuleID)
			}
			// Redact-at-boundary: the raw secret reached the side channel, so it
			// must NOT also appear in any exported string field of the finding.
			secret, ok := raw[fd.Fingerprint]
			if !ok {
				t.Fatalf("no raw side-channel entry for fingerprint %q (rule %q)", fd.Fingerprint, fd.RuleID)
			}
			if secret == "" {
				continue
			}

			// The exact contract: Secret is the redaction of the raw value, never
			// the value itself. Comparing against RedactSecret rather than doing a
			// substring check keeps this precise — a 1-char secret like "A"
			// redacts to "[REDACTED]", which trivially *contains* "A" without
			// disclosing anything.
			redacted := finding.RedactSecret(secret)
			if fd.Secret != redacted {
				t.Fatalf("Finding.Secret = %q, want the redaction %q (rule %q)", fd.Secret, redacted, fd.RuleID)
			}

			// Match is the surrounding context with the secret redacted at its own
			// offset. A blunt "Match must not contain these bytes" check is wrong:
			// the context legitimately includes other spans (a hostname, a
			// neighbouring field) that may repeat the same byte run, and the
			// redaction placeholder itself can contain them for short secrets.
			//
			// The precise invariants, using only what a Finding exposes:
			//
			//  a) the redaction is present exactly once — the matched span was
			//     rewritten, and no OTHER span was rewritten along with it; and
			//  b) undoing that one substitution reproduces a literal substring of
			//     the original line. That round-trip is what fails if the
			//     redaction rewrote extra occurrences or spliced the raw value
			//     back together, and it holds regardless of what else the context
			//     happens to contain.
			if n := strings.Count(fd.Match, redacted); n != 1 {
				t.Fatalf("Match contains the redaction %d times, want exactly 1 (rule %q): %q",
					n, fd.RuleID, fd.Match)
			}
			if restored := strings.Replace(fd.Match, redacted, secret, 1); !strings.Contains(line, restored) {
				t.Fatalf("Match does not round-trip to a substring of the input line (rule %q): got %q from %q",
					fd.RuleID, restored, line)
			}

			// The disclosure bound: for a secret long enough to be partially shown,
			// only a 4-byte head and 4-byte tail may appear. The MIDDLE — the part
			// that actually makes the credential usable — must never survive into
			// the redaction. (Length is not a useful proxy here: the mask itself is
			// 11 bytes, so a 19-byte redaction of a 16-byte secret still discloses
			// only 8 bytes.)
			if len(secret) >= 16 {
				if middle := secret[4 : len(secret)-4]; strings.Contains(redacted, middle) {
					t.Fatalf("redaction disclosed the middle of a %d-byte secret (rule %q)", len(secret), fd.RuleID)
				}
			}
		}
	})
}
