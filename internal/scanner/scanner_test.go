package scanner

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/MatrixMagician/mimir/internal/config"
	"github.com/MatrixMagician/mimir/internal/detect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestScanner creates a scanner with the embedded default config.
func newTestScanner(t *testing.T) *Scanner {
	t.Helper()
	cfg, err := config.LoadDefault()
	require.NoError(t, err)
	eng := detect.NewEngine(cfg)
	return New(eng, cfg)
}

// repoRoot returns the module root directory (two levels up from this package).
func repoRoot(t *testing.T) string {
	t.Helper()
	// internal/scanner → internal → repo root
	dir, err := filepath.Abs("../..")
	require.NoError(t, err)
	return dir
}

func TestScannerNonexistentPathIsFatal(t *testing.T) {
	s := newTestScanner(t)

	// A path the user named that does not exist must be a fatal error (→ exit 2),
	// never a silent "clean" scan (→ exit 0) that would hide a typo'd path in CI.
	_, _, _, err := s.Scan(context.Background(), []string{filepath.Join(t.TempDir(), "does-not-exist")})
	require.Error(t, err)
}

func TestScannerBinarySkip(t *testing.T) {
	s := newTestScanner(t)

	// Create a temp file with a NUL byte
	tmp := t.TempDir()
	binFile := filepath.Join(tmp, "binary.bin")
	err := os.WriteFile(binFile, []byte("AKIA\x00FAKEKEY12345678"), 0600)
	require.NoError(t, err)

	findings, _, stats, err := s.Scan(context.Background(), []string{tmp})
	require.NoError(t, err)
	assert.Empty(t, findings, "expected 0 findings for binary file")
	// The binary file should be walked but not scanned (not counted as FilesScanned)
	_ = stats
}

func TestScannerGitDirSkip(t *testing.T) {
	s := newTestScanner(t)

	tmp := t.TempDir()

	// Create a .git directory with a secret file inside
	gitDir := filepath.Join(tmp, ".git")
	require.NoError(t, os.Mkdir(gitDir, 0750))
	secretFile := filepath.Join(gitDir, "config")
	err := os.WriteFile(secretFile, []byte("aws_access_key_id = AKIAFAKEKEY12345678\n"), 0600)
	require.NoError(t, err)

	// Create a clean file outside .git
	cleanFile := filepath.Join(tmp, "clean.txt")
	err = os.WriteFile(cleanFile, []byte("hello world\n"), 0600)
	require.NoError(t, err)

	findings, _, _, err := s.Scan(context.Background(), []string{tmp})
	require.NoError(t, err)
	assert.Empty(t, findings, "expected 0 findings: .git directory should be skipped")
}

func TestScannerFixturesDetected(t *testing.T) {
	s := newTestScanner(t)
	root := repoRoot(t)
	fixturesPath := filepath.Join(root, "testdata", "fixtures")

	findings, _, _, err := s.Scan(context.Background(), []string{fixturesPath})
	require.NoError(t, err)
	require.NotEmpty(t, findings, "expected at least 1 finding in testdata/fixtures")

	// At least one finding should be aws-access-token
	found := false
	for _, f := range findings {
		if f.RuleID == "aws-access-token" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected at least 1 aws-access-token finding in fixtures")
}

func TestScannerCleanFileNoFindings(t *testing.T) {
	s := newTestScanner(t)
	root := repoRoot(t)
	cleanPath := filepath.Join(root, "testdata", "clean", "no-secrets.go")

	findings, _, _, err := s.Scan(context.Background(), []string{cleanPath})
	require.NoError(t, err)
	assert.Empty(t, findings, "expected 0 findings in testdata/clean/no-secrets.go")
}

func TestCleanNoKeywords(t *testing.T) {
	s := newTestScanner(t)
	root := repoRoot(t)
	cleanDir := filepath.Join(root, "testdata", "clean")

	findings, _, _, err := s.Scan(context.Background(), []string{cleanDir})
	require.NoError(t, err)
	assert.Empty(t, findings, "expected 0 findings in testdata/clean/")
}

func TestScannerRedactAtBoundary(t *testing.T) {
	s := newTestScanner(t)
	root := repoRoot(t)
	fixturesPath := filepath.Join(root, "testdata", "fixtures")

	findings, _, _, err := s.Scan(context.Background(), []string{fixturesPath})
	require.NoError(t, err)
	require.NotEmpty(t, findings, "expected findings for redaction check")

	rawSecret := "AKIAFAKEKEY12345678"
	for _, f := range findings {
		assert.NotContains(t, f.Secret, rawSecret,
			"raw secret must not appear in Finding.Secret (redact-at-boundary)")
		assert.NotContains(t, f.Match, rawSecret,
			"raw secret must not appear in Finding.Match (redact-at-boundary)")
	}
}

func TestIsBinary(t *testing.T) {
	assert.True(t, isBinary([]byte{'A', 'K', 'I', 'A', 0x00, 'F', 'A', 'K', 'E'}))
	assert.False(t, isBinary([]byte("aws_access_key_id = AKIAFAKEKEY12345678")))
	assert.False(t, isBinary([]byte{}))
}

// TestLongLineIsNotSilentlySkipped is the regression test for the worst failure
// class this tool has: reporting "clean" without having looked.
//
// scanFile capped bufio's buffer at 64 KiB, so ANY file containing a longer line
// failed with "token too long" and was skipped — silently, unless --verbose. A
// minified bundle or single-line JSON blob with a key in it therefore scanned as
// clean and exited 0. The git-aware sources never had the limit, so the same
// repo reported differently depending on the flag.
func TestLongLineIsNotSilentlySkipped(t *testing.T) {
	dir := t.TempDir()
	// One line well past the old 64 KiB ceiling, with the secret in the middle.
	pad := strings.Repeat("var x=1;", 9000) // ~72 KiB either side
	content := pad + "aws_access_key_id = AKIAFAKEKEYABCDE2345" + pad + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "big.js"), []byte(content), 0o600))

	s := newTestScanner(t)
	findings, _, stats, err := s.Scan(context.Background(), []string{dir})
	require.NoError(t, err)

	assert.Equal(t, 0, stats.FilesUnreadable,
		"a long line must not make the file unreadable")
	assert.Equal(t, 1, stats.FilesScanned, "the file must be counted as scanned")
	require.NotEmpty(t, findings,
		"the secret on a >64KiB line must be found, not silently skipped")
}

// TestUnreadableFileIsCountedAndReported asserts that a file we cannot read is
// surfaced rather than swallowed. Without the count, "no findings" is
// indistinguishable from "I never looked at the file your key was in" — and the
// scan exits 0, so a pre-commit hook waves the commit through.
func TestUnreadableFileIsCountedAndReported(t *testing.T) {
	// chmod 000 is the portable way to make a file unreadable, but it does not
	// work for root (which bypasses permission checks) or on Windows (where
	// Go's FileMode does not map to NTFS ACLs, so the file stays readable).
	if runtime.GOOS == "windows" {
		t.Skip("chmod does not restrict reads on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod 000 does not prevent reads")
	}
	dir := t.TempDir()
	unreadable := filepath.Join(dir, "secret.go")
	require.NoError(t, os.WriteFile(unreadable, []byte("k = \"AKIAFAKEKEYABCDE2345\"\n"), 0o600))
	require.NoError(t, os.Chmod(unreadable, 0o000))
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o600) })

	s := newTestScanner(t)
	findings, _, stats, err := s.Scan(context.Background(), []string{dir})
	require.NoError(t, err, "an unreadable file must not abort the whole scan")

	assert.Empty(t, findings, "the secret is in the file we could not read")
	assert.Equal(t, 1, stats.FilesUnreadable,
		"an unscanned file must be counted, or a clean-looking scan hides it")
}

// TestMaxLineBytes pins the buffer ceiling's derivation. It tracks the
// file-size limit because a line cannot exceed its file, and it must never fall
// below bufio's starting buffer or grow unbounded when the limit is disabled.
func TestMaxLineBytes(t *testing.T) {
	assert.Equal(t, 10*1024*1024, maxLineBytes(10), "follows the configured MB limit")
	assert.Equal(t, 64*1024, maxLineBytes(0)/(4*1024), "0 (unlimited) uses the absolute cap")
	assert.GreaterOrEqual(t, maxLineBytes(0), 64*1024, "unlimited still has a ceiling")
	assert.Equal(t, 64*1024, maxLineBytes(-1)/(4*1024), "negative is treated as unlimited")
	assert.GreaterOrEqual(t, maxLineBytes(1), 64*1024, "never below bufio's starting buffer")
}

// TestOverlappingPathsScanEachFileOnce is the regression test for duplicate
// reporting across targets. `mimir scan . src` and `mimir scan a a` are both
// things users type, and every file covered by more than one target was scanned
// once per target. That reported each secret multiple times, inflated
// files_scanned, and — because each finding's path is relative to ITS OWN scan
// root — produced different fingerprints for one on-disk secret, so a baseline
// recorded under one invocation did not match the other by fingerprint.
func TestOverlappingPathsScanEachFileOnce(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "a")
	require.NoError(t, os.Mkdir(sub, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "x.go"),
		[]byte("k = \"AKIAFAKEKEYABCDE2347\"\n"), 0o600))

	s := newTestScanner(t)

	t.Run("parent and child", func(t *testing.T) {
		findings, _, stats, err := s.Scan(context.Background(), []string{dir, sub})
		require.NoError(t, err)
		assert.Len(t, findings, 1, "the file is covered twice but must be reported once")
		assert.Equal(t, 1, stats.FilesScanned, "files_scanned must count files, not visits")
	})

	t.Run("the same path twice", func(t *testing.T) {
		findings, _, stats, err := s.Scan(context.Background(), []string{sub, sub})
		require.NoError(t, err)
		assert.Len(t, findings, 1)
		assert.Equal(t, 1, stats.FilesScanned)
	})

	t.Run("distinct paths are both still scanned", func(t *testing.T) {
		other := filepath.Join(dir, "b")
		require.NoError(t, os.Mkdir(other, 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(other, "y.go"),
			[]byte("k = \"AKIAFAKEKEYABCDE2352\"\n"), 0o600))

		findings, _, _, err := s.Scan(context.Background(), []string{sub, other})
		require.NoError(t, err)
		assert.Len(t, findings, 2, "dedup must not drop genuinely different files")
	})
}

// TestSymlinkLoopTerminates guards the walk against a symlink cycle in a scanned
// repository. filepath.WalkDir does not follow symlinks, so a loop must not
// recurse forever; this pins that behaviour rather than trusting it, since a
// hang on a hostile checkout is a denial of service on anyone's CI.
func TestSymlinkLoopTerminates(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	require.NoError(t, os.Mkdir(sub, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "s.go"),
		[]byte("k = \"AKIAFAKEKEYABCDE2347\"\n"), 0o600))
	if err := os.Symlink(dir, filepath.Join(sub, "loop")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s := newTestScanner(t)
	findings, _, _, err := s.Scan(ctx, []string{dir})
	require.NoError(t, err)
	require.NoError(t, ctx.Err(), "the walk must terminate, not spin until the deadline")
	assert.Len(t, findings, 1, "the real file is reported once; the loop adds nothing")
}

// TestFileAsDirectTargetKeepsItsName pins the path reported when the scan target
// IS a file rather than a directory (`mimir scan src/config.go`). scanFile
// derives the reported path with filepath.Rel(root, file); with root == file
// that returns ".", so the finding was reported at path "." and — because the
// path is part of the fingerprint — the SAME secret got a different fingerprint
// depending on whether the user named the file or its directory, so a baseline
// recorded one way did not match the other.
func TestFileAsDirectTargetKeepsItsName(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "config.go")
	require.NoError(t, os.WriteFile(file, []byte("k = \"AKIAFAKEKEYABCDE2347\"\n"), 0o600))

	s := newTestScanner(t)

	viaFile, _, _, err := s.Scan(context.Background(), []string{file})
	require.NoError(t, err)
	require.Len(t, viaFile, 1)
	assert.Equal(t, "config.go", viaFile[0].File,
		"a file named directly must report its own name, not \".\"")

	viaDir, _, _, err := s.Scan(context.Background(), []string{dir})
	require.NoError(t, err)
	require.Len(t, viaDir, 1)

	assert.Equal(t, viaDir[0].Fingerprint, viaFile[0].Fingerprint,
		"the same secret must fingerprint identically however the scan was invoked, "+
			"or a baseline recorded one way silently fails to match the other")
}
