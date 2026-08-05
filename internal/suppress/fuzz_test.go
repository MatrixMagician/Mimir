package suppress

import (
	"strings"
	"testing"
)

// FuzzInlineSuppresses drives the inline-directive matcher with arbitrary line
// content. Every scanned line of every repository reaches this function, so it
// must never panic and must never over-suppress: a directive that wrongly
// matches silently hides a real secret, which is the worst failure this tool
// has.
func FuzzInlineSuppresses(f *testing.F) {
	seeds := []string{
		"",
		"// mimir:ignore",
		"# mimir:ignore:aws-access-token",
		"mimir:ignore:a,b,c",
		"mimir:ignored",
		"MIMIR:IGNORE",
		"mimir:ignore:",
		"mimir:ignore::",
		"mimir:ignore:,,,",
		"mimir:ignore:" + strings.Repeat("a,", 1000),
		"\x00mimir:ignore",
		"mimir:ignore\u2028",
		strings.Repeat("mimir:ignore:", 500),
	}
	for _, s := range seeds {
		f.Add(s, "aws-access-token")
	}

	f.Fuzz(func(t *testing.T, line, ruleID string) {
		got := InlineSuppresses(line, ruleID)

		// The load-bearing direction: suppression may only happen when the
		// directive token is actually present. Anything else is a silent
		// false-negative on a real secret.
		if got && indexFold(line, "mimir:ignore") < 0 {
			t.Fatalf("suppressed without a directive on the line: %q (rule %q)", line, ruleID)
		}

		// A scoped directive must only suppress rules it actually names. Checking
		// this on the ORIGINAL line (never on a lowercased copy — ToLower can
		// change the byte length on invalid UTF-8, so offsets do not carry across)
		// via a case-insensitive search for the directive token.
		if got && ruleID != "" {
			i := indexFold(line, "mimir:ignore")
			if i < 0 {
				t.Fatalf("suppressed without a directive token: %q", line)
			}
			rest := line[i+len("mimir:ignore"):]
			if strings.HasPrefix(rest, ":") && len(rest) > 1 {
				scope := rest[1:]
				// Trailing text after the rule list is not part of the scope; the
				// grammar stops at the first byte outside [A-Za-z0-9_,-].
				if cut := strings.IndexFunc(scope, func(r rune) bool {
					return !(r == ',' || r == '-' || r == '_' ||
						(r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'))
				}); cut >= 0 {
					scope = scope[:cut]
				}
				if scope != "" {
					named := false
					for _, name := range strings.Split(scope, ",") {
						if strings.TrimSpace(name) == ruleID {
							named = true
							break
						}
					}
					if !named {
						t.Fatalf("scoped directive %q suppressed unnamed rule %q", line, ruleID)
					}
				}
			}
		}
	})
}

// indexFold is a byte-offset-preserving, case-insensitive Index for ASCII
// needles. strings.ToLower cannot be used for this: on invalid UTF-8 it
// substitutes the replacement rune, changing the byte length, so an offset found
// in the lowered copy does not address the same byte in the original.
func indexFold(haystack, needleLower string) int {
	for i := 0; i+len(needleLower) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needleLower); j++ {
			c := haystack[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != needleLower[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// FuzzPathMatcher drives the .mimirignore glob compiler and matcher with
// arbitrary patterns and paths. Patterns come from a file in the scanned repo,
// so they are untrusted input: a panic here is a crash on someone else's
// checkout, and an over-broad match silently skips files that should be scanned.
func FuzzPathMatcher(f *testing.F) {
	seeds := []struct{ pattern, path string }{
		{"vendor/**", "vendor/lib.go"},
		{"!docs/**", "docs/a.md"},
		{"**/*.min.js", "a/b/c.min.js"},
		{"[", "a"},
		{"a/[b", "a/b"},
		{"**", ""},
		{"", "a"},
		{"\\", "a"},
		{"**/**/**", "a/b/c"},
		{strings.Repeat("*/", 200), strings.Repeat("a/", 200)},
		{"a/**", "a\\b\\c"},
	}
	for _, s := range seeds {
		f.Add(s.pattern, s.path, false)
	}

	f.Fuzz(func(t *testing.T, pattern, path string, isDir bool) {
		// A malformed USER pattern must fail loud rather than panic or be
		// silently dropped (Security V5).
		m, err := NewPathMatcher([]string{pattern}, false)
		if err != nil {
			if m != nil {
				t.Fatalf("NewPathMatcher returned both an error and a matcher for %q", pattern)
			}
			return
		}

		// Matching must not panic on any path, and must be deterministic.
		first := m.Excluded(path, isDir)
		if second := m.Excluded(path, isDir); first != second {
			t.Fatalf("Excluded is not deterministic for pattern %q path %q", pattern, path)
		}

		// A nil matcher never excludes — the "no .mimirignore" path.
		var nilMatcher *PathMatcher
		if nilMatcher.Excluded(path, isDir) {
			t.Fatalf("a nil PathMatcher must never exclude (path %q)", path)
		}
	})
}
