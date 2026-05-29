package suppress

import (
	"path/filepath"
	"testing"

	"github.com/MatrixMagician/mimir/internal/finding"
)

func TestBaselineFingerprintMatch(t *testing.T) {
	f := finding.New("aws-access-token", "src/app.go", 5, 1, "AKIAFAKEKEYABCDE2345", "ctx", false)
	b := newBaseline([]finding.Finding{f})
	if !b.IsSuppressed(f) {
		t.Error("a finding whose full fingerprint is in the baseline must be suppressed")
	}
}

func TestBaselineFileMoveContentKey(t *testing.T) {
	orig := finding.New("aws-access-token", "src/app.go", 5, 1, "AKIAFAKEKEYABCDE2345", "ctx", false)
	moved := finding.New("aws-access-token", "lib/app.go", 99, 7, "AKIAFAKEKEYABCDE2345", "ctx", false)
	b := newBaseline([]finding.Finding{orig})
	if orig.Fingerprint == moved.Fingerprint {
		t.Fatal("precondition: a file move must change the full fingerprint")
	}
	if !b.IsSuppressed(moved) {
		t.Error("same secret at a new path must be suppressed via content-key OR-match (file move)")
	}
}

func TestBaselineNewFindingNotSuppressed(t *testing.T) {
	base := finding.New("aws-access-token", "src/app.go", 5, 1, "AKIAFAKEKEYABCDE2345", "ctx", false)
	other := finding.New("aws-access-token", "src/app.go", 5, 1, "AKIADIFFERENTVAL9999", "ctx", false)
	b := newBaseline([]finding.Finding{base})
	if b.IsSuppressed(other) {
		t.Error("a genuinely new secret must not be suppressed")
	}
}

func TestLoadBaselineMissingFile(t *testing.T) {
	b, err := LoadBaseline(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("missing baseline file must not error: %v", err)
	}
	f := finding.New("aws-access-token", "src/app.go", 5, 1, "AKIAFAKEKEYABCDE2345", "ctx", false)
	if b.IsSuppressed(f) {
		t.Error("empty baseline must suppress nothing")
	}
}

func TestBaselineRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	f := finding.New("aws-access-token", "src/app.go", 5, 1, "AKIAFAKEKEYABCDE2345", "ctx", false)
	if err := WriteBaseline(path, []finding.Finding{f}); err != nil {
		t.Fatalf("WriteBaseline: %v", err)
	}
	b, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if !b.IsSuppressed(f) {
		t.Error("a written baseline must suppress the finding it recorded after reload")
	}
}
