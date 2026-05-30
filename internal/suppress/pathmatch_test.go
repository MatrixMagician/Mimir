package suppress

import "testing"

func mustMatcher(t *testing.T, lines []string, useDefaults bool) *PathMatcher {
	t.Helper()
	m, err := NewPathMatcher(lines, useDefaults)
	if err != nil {
		t.Fatalf("NewPathMatcher: %v", err)
	}
	return m
}

func TestPathMatchDoublestar(t *testing.T) {
	m := mustMatcher(t, []string{"**/*.min.js"}, false)
	if !m.Excluded("app/static/x.min.js", false) {
		t.Error("** glob should exclude nested *.min.js")
	}
	if m.Excluded("app/static/x.js", false) {
		t.Error("non-min .js must not be excluded")
	}
}

func TestPathMatchNegationLastMatchWins(t *testing.T) {
	// Defaults exclude **/*.min.js; a !keep.min.js re-includes it (Pitfall 2).
	m := mustMatcher(t, []string{"!keep.min.js"}, true)
	if !m.Excluded("app.min.js", false) {
		t.Error("default **/*.min.js should exclude app.min.js")
	}
	if m.Excluded("keep.min.js", false) {
		t.Error("!keep.min.js should re-include (defaults-first, last-match-wins)")
	}
}

func TestPathMatchDefaultGlobs(t *testing.T) {
	m := mustMatcher(t, nil, true)
	cases := []struct {
		path  string
		isDir bool
	}{
		{"vendor", true},
		{"vendor/lib.go", false},
		{"node_modules", true},
		{"node_modules/pkg/index.js", false},
		{"app.min.js", false},
		{"sub/app.min.js", false},
		{"package-lock.json", false},
		{"yarn.lock", false},
	}
	for _, tc := range cases {
		if !m.Excluded(tc.path, tc.isDir) {
			t.Errorf("default globs should exclude %q (isDir=%v)", tc.path, tc.isDir)
		}
	}
}

func TestPathMatchDefaultsOff(t *testing.T) {
	m := mustMatcher(t, []string{"build/**"}, false)
	if m.Excluded("vendor/lib.go", false) {
		t.Error("with defaults off, vendor/ must NOT be excluded")
	}
	if !m.Excluded("build/out.js", false) {
		t.Error("explicit build/** must still exclude")
	}
}

func TestPathMatchForwardSlashNormalization(t *testing.T) {
	m := mustMatcher(t, []string{"vendor/**"}, false)
	if !m.Excluded(`vendor\lib.go`, false) {
		t.Error("backslash path must normalize to forward slash and match (Pitfall 1)")
	}
}

func TestPathMatchRejectsMalformedPattern(t *testing.T) {
	if _, err := NewPathMatcher([]string{"a/[b"}, false); err == nil {
		t.Error("a malformed glob must be rejected at construction (Security V5)")
	}
}

func TestPathMatchNilSafe(t *testing.T) {
	var m *PathMatcher
	if m.Excluded("anything", false) {
		t.Error("nil matcher must never exclude")
	}
}
