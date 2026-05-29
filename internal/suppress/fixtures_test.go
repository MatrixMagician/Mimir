package suppress

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// dirtyAWSSecret is the fake AWS access key reused verbatim from
// testdata/fixtures/known-secrets.txt and embedded in the dirty fixture's
// secret-bearing source file (and its moved/shifted criterion-4 variants).
const dirtyAWSSecret = "AKIAFAKEKEYABCDE2345"

// TestDirtyFixturesWired is a sanity check proving the Phase 2 fixture repos are
// in place before later plans consume them. It does NOT assert scanner behavior
// (that belongs to Plans 02–04) — only that the three fixture dirs exist, carry
// the expected secret substring, and that the path-prune fixtures are present.
func TestDirtyFixturesWired(t *testing.T) {
	root := filepath.Join("..", "..", "testdata")

	secretFiles := map[string]string{
		"dirty":         filepath.Join(root, "dirty", "src", "app.go"),
		"dirty-moved":   filepath.Join(root, "dirty-moved", "lib", "app.go"),
		"dirty-shifted": filepath.Join(root, "dirty-shifted", "src", "app.go"),
	}
	for name, file := range secretFiles {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("fixture file missing: %s: %v", file, err)
			}
			if !strings.Contains(string(data), dirtyAWSSecret) {
				t.Errorf("fixture %s missing expected secret substring %q", file, dirtyAWSSecret)
			}
		})
	}

	// Path-prune + inline-ignore + .mimirignore fixtures must exist in dirty/.
	mustExist := []string{
		filepath.Join(root, "dirty", ".mimirignore"),
		filepath.Join(root, "dirty", "vendor", "lib.go"),
		filepath.Join(root, "dirty", "node_modules", "pkg", "index.js"),
		filepath.Join(root, "dirty", "app.min.js"),
		filepath.Join(root, "dirty", "package-lock.json"),
		filepath.Join(root, "dirty", "ignored.go"),
		filepath.Join(root, "dirty", "scoped.go"),
	}
	for _, p := range mustExist {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected dirty fixture path missing: %s: %v", p, err)
		}
	}

	// vendor/ must be a directory (default path-prune target).
	if fi, err := os.Stat(filepath.Join(root, "dirty", "vendor")); err != nil || !fi.IsDir() {
		t.Errorf("testdata/dirty/vendor must exist as a directory")
	}
}
