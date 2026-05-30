package cmd_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const mimirTestBin = "/tmp/mimir-cmd-test"

// TestMain builds the mimir binary once for all tests in this package.
func TestMain(m *testing.M) {
	// Determine repo root from this file's location.
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("could not determine source file path")
	}
	repoRoot := filepath.Join(filepath.Dir(file), "..", "..")

	// Build from the repo root (main package is at root, not ./cmd/mimir which is package cmd)
	buildCmd := exec.Command("go", "build", "-o", mimirTestBin, ".") //nolint:gosec
	buildCmd.Dir = repoRoot
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		panic("failed to build mimir binary: " + err.Error())
	}

	code := m.Run()
	os.Remove(mimirTestBin)
	os.Exit(code)
}

// repoRoot returns the absolute path to the repository root.
func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// runMimir runs the compiled mimir binary with the given arguments from the repo root.
// It returns stdout, stderr, and the exit code.
func runMimir(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	//#nosec G204 -- mimirTestBin is a compile-time constant path to the test binary
	cmd := exec.Command(mimirTestBin, args...) //nolint:gosec
	cmd.Dir = repoRoot()
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	stdout = outBuf.String()
	stderr = errBuf.String()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return stdout, stderr, exitCode
}

// TestExitCodeClean verifies that scanning a directory with no secrets exits 0.
func TestExitCodeClean(t *testing.T) {
	_, _, code := runMimir(t, "scan", "--no-color", "testdata/clean/")
	if code != 0 {
		t.Fatalf("expected exit code 0 for clean scan, got %d", code)
	}
}

// TestExitCodeFindings verifies that scanning a directory with secrets exits 1.
func TestExitCodeFindings(t *testing.T) {
	_, _, code := runMimir(t, "scan", "--no-color", "testdata/fixtures/")
	if code != 1 {
		t.Fatalf("expected exit code 1 for scan with findings, got %d", code)
	}
}

// TestExitZero verifies that --exit-zero suppresses the non-zero exit when findings are present.
func TestExitZero(t *testing.T) {
	_, _, code := runMimir(t, "scan", "--no-color", "--exit-zero", "testdata/fixtures/")
	if code != 0 {
		t.Fatalf("expected exit code 0 with --exit-zero, got %d", code)
	}
}

// TestQuietFlag verifies --quiet behavior: findings are printed, summary is suppressed, exit=1.
func TestQuietFlag(t *testing.T) {
	stdout, _, code := runMimir(t, "scan", "--no-color", "--quiet", "testdata/fixtures/")
	if code != 1 {
		t.Fatalf("expected exit code 1 with --quiet (findings present), got %d", code)
	}
	// At least one finding line should be present (path:line:col pattern)
	if !strings.Contains(stdout, ":") {
		t.Errorf("expected finding line in stdout with --quiet, got: %q", stdout)
	}
	// Summary line must be absent
	if strings.Contains(stdout, "finding(s) in") {
		t.Errorf("expected no summary line in stdout with --quiet, but found it: %q", stdout)
	}
	if strings.Contains(stdout, "no findings") {
		t.Errorf("expected no summary line in stdout with --quiet, but found it: %q", stdout)
	}
}

// TestNoSecretsInOutput verifies that raw secret values never appear in stdout.
func TestNoSecretsInOutput(t *testing.T) {
	rawSecrets := []string{
		"AKIAFAKEKEYABCDE2345",
		"AKIATESTKEY234567AB",
	}
	stdout, _, _ := runMimir(t, "scan", "--no-color", "testdata/fixtures/")
	for _, raw := range rawSecrets {
		if strings.Contains(stdout, raw) {
			t.Errorf("raw secret %q found in stdout output — redaction-at-boundary violated", raw)
		}
	}
}

// TestSummaryLineCleanScan verifies the "no findings" summary appears on a clean scan.
func TestSummaryLineCleanScan(t *testing.T) {
	stdout, _, code := runMimir(t, "scan", "--no-color", "testdata/clean/")
	if code != 0 {
		t.Fatalf("expected exit 0 for clean scan, got %d", code)
	}
	if !strings.Contains(stdout, "no findings") {
		t.Errorf("expected 'no findings' in stdout, got: %q", stdout)
	}
}

// TestSummaryLineFindingsScan verifies the findings summary appears when secrets are found.
func TestSummaryLineFindingsScan(t *testing.T) {
	stdout, _, _ := runMimir(t, "scan", "--no-color", "testdata/fixtures/")
	if !strings.Contains(stdout, "finding(s) in") {
		t.Errorf("expected summary line in stdout, got: %q", stdout)
	}
}

// TestVersionCommand verifies the version subcommand works.
func TestVersionCommand(t *testing.T) {
	_, _, code := runMimir(t, "version")
	if code != 0 {
		t.Fatalf("expected exit 0 for version command, got %d", code)
	}
}

// TestDefaultExcludes verifies first-run defaults keep vendor/, node_modules/,
// *.min.js and lockfiles quiet while the top-level secret is still reported
// (SUP-04, criterion 2).
func TestDefaultExcludes(t *testing.T) {
	stdout, _, code := runMimir(t, "scan", "--no-color", "testdata/dirty")
	if code != 1 {
		t.Fatalf("expected exit 1 (top-level secret present), got %d", code)
	}
	assert.Contains(t, stdout, "src/app.go", "the non-excluded secret must be reported")
	assert.NotContains(t, stdout, "vendor/", "vendor/ must be excluded by default")
	assert.NotContains(t, stdout, "node_modules/", "node_modules/ must be excluded by default")
	assert.NotContains(t, stdout, ".min.js", "*.min.js must be excluded by default")
	assert.NotContains(t, stdout, "package-lock.json", "lockfiles must be excluded by default")
}

// TestMimirignoreNegation verifies a `!negation` re-includes a default-excluded
// path so its secret is reported (SUP-02, D-07). It uses build/ — excluded by the
// default glob **/build/** but NOT covered by the embedded content-allowlist
// paths (test/, vendor/, node_modules/, …), so re-inclusion is observable.
func TestMimirignoreNegation(t *testing.T) {
	dir := t.TempDir()
	secret := "\tAccessKey: \"AKIAFAKEKEYABCDE2345\"\n" // identical to testdata/dirty/src/app.go (proven detected)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "build"), 0750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "build", "leak.txt"), []byte(secret), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".mimirignore"), []byte("!**/build/**\n"), 0600))

	stdout, _, code := runMimir(t, "scan", "--no-color", dir)
	if code != 1 {
		t.Fatalf("expected exit 1 (re-included secret present), got %d", code)
	}
	assert.Contains(t, stdout, "build/leak.txt", "!**/build/** must re-include the default-excluded path")
}

// TestDefaultsToggleOff verifies use_default_allowlists=false disables the shipped
// default path-prune globs so a build/ secret is reported (D-07 master toggle).
// build/ is excluded only by a default glob, not by the content-allowlist, so the
// toggle's effect is observable.
func TestDefaultsToggleOff(t *testing.T) {
	dir := t.TempDir()
	secret := "\tAccessKey: \"AKIAFAKEKEYABCDE2345\"\n" // identical to testdata/dirty/src/app.go (proven detected)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "build"), 0750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "build", "leak.txt"), []byte(secret), 0600))
	cfg := "[extend]\nuse_default = true\nuse_default_allowlists = false\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".mimir.toml"), []byte(cfg), 0600))

	stdout, _, code := runMimir(t, "scan", "--no-color", dir)
	if code != 1 {
		t.Fatalf("expected exit 1 (build secret reported with defaults off), got %d", code)
	}
	assert.Contains(t, stdout, "build/leak.txt", "defaults-off must scan build/")
}

// TestMalformedMimirignoreFailsLoud verifies a malformed .mimirignore glob exits
// 2 (fail loud, Security V14).
func TestMalformedMimirignoreFailsLoud(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".mimirignore"), []byte("a/[b\n"), 0600))
	_, _, code := runMimir(t, "scan", "--no-color", dir)
	assert.Equal(t, 2, code, "a malformed .mimirignore glob must exit 2")
}

// TestBaselineNewOnly verifies --baseline-out then --baseline reports 0 NEW
// findings on an unchanged repo (SUP-03).
func TestBaselineNewOnly(t *testing.T) {
	bl := filepath.Join(t.TempDir(), "bl.json")
	runMimir(t, "scan", "--no-color", "--baseline-out", bl, "testdata/dirty")
	stdout, _, code := runMimir(t, "scan", "--no-color", "--baseline", bl, "testdata/dirty")
	assert.Equal(t, 0, code, "re-scan against its own baseline must report 0 NEW findings")
	assert.Contains(t, stdout, "no findings")
}

// TestBaselineFileMove verifies the OR-match keeps a finding suppressed after a
// file move (criterion 4, end-to-end).
func TestBaselineFileMove(t *testing.T) {
	bl := filepath.Join(t.TempDir(), "bl.json")
	runMimir(t, "scan", "--no-color", "--baseline-out", bl, "testdata/dirty")
	_, _, code := runMimir(t, "scan", "--no-color", "--baseline", bl, "testdata/dirty-moved")
	assert.Equal(t, 0, code, "moved-file secret must stay suppressed via content-key")
}

// TestBaselineBlankLineShift verifies a blank-line insert above a secret does
// not change suppression (criterion 4, end-to-end).
func TestBaselineBlankLineShift(t *testing.T) {
	bl := filepath.Join(t.TempDir(), "bl.json")
	runMimir(t, "scan", "--no-color", "--baseline-out", bl, "testdata/dirty")
	_, _, code := runMimir(t, "scan", "--no-color", "--baseline", bl, "testdata/dirty-shifted")
	assert.Equal(t, 0, code, "blank-line shift must not change suppression")
}

// TestSuppressedExitCode verifies an all-baselined scan exits 0 and that
// --show-suppressed does not flip the exit code (IFACE-02, Pitfall 5).
func TestSuppressedExitCode(t *testing.T) {
	bl := filepath.Join(t.TempDir(), "bl.json")
	runMimir(t, "scan", "--no-color", "--baseline-out", bl, "testdata/dirty")
	_, _, c1 := runMimir(t, "scan", "--no-color", "--baseline", bl, "testdata/dirty")
	assert.Equal(t, 0, c1, "all-baselined scan exits 0")
	_, _, c2 := runMimir(t, "scan", "--no-color", "--show-suppressed", "--baseline", bl, "testdata/dirty")
	assert.Equal(t, 0, c2, "--show-suppressed must not flip the exit code")
}

// TestBaselineOutNoRawSecret verifies the written baseline contains no raw
// secret (criterion 3, end-to-end).
func TestBaselineOutNoRawSecret(t *testing.T) {
	bl := filepath.Join(t.TempDir(), "bl.json")
	runMimir(t, "scan", "--no-color", "--baseline-out", bl, "testdata/dirty")
	data, err := os.ReadFile(bl)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "AKIAFAKEKEYABCDE2345", "baseline must never store a raw secret")
}

// TestShowSuppressed verifies --show-suppressed re-includes baselined findings
// tagged "baseline" in JSON, while the default JSON omits the D-12 fields (OUT-02).
func TestShowSuppressed(t *testing.T) {
	bl := filepath.Join(t.TempDir(), "bl.json")
	runMimir(t, "scan", "--no-color", "--baseline-out", bl, "testdata/dirty")

	stdout, _, _ := runMimir(t, "scan", "--no-color", "--show-suppressed", "--baseline", bl, "--format", "json", "testdata/dirty")
	var res struct {
		Findings []struct {
			Suppressed        bool   `json:"suppressed"`
			SuppressionReason string `json:"suppression_reason"`
		} `json:"findings"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &res))
	foundBaseline := false
	for _, f := range res.Findings {
		if f.Suppressed && f.SuppressionReason == "baseline" {
			foundBaseline = true
		}
	}
	assert.True(t, foundBaseline, "--show-suppressed must re-include baselined findings tagged baseline")

	// Default JSON on a repo with active, non-suppressed findings must omit the
	// D-12 fields entirely (OUT-02 byte-identical schema).
	def, _, _ := runMimir(t, "scan", "--no-color", "--format", "json", "testdata/fixtures/")
	assert.NotContains(t, def, "suppression_reason", "default JSON must omit suppression_reason")
}

// gitCmd runs a git command in dir and fails the test on error.
func gitCmd(t *testing.T, dir string, args ...string) {
	t.Helper()
	full := append([]string{"-C", dir}, args...)
	out, err := exec.Command("git", full...).CombinedOutput()
	require.NoErrorf(t, err, "git %v failed: %s", args, string(out))
}

// newGitFixtureRepo builds a temp git repo where a secret is added in commit 1
// and the file is deleted in commit 2 (the added-then-deleted history case).
func newGitFixtureRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gitCmd(t, dir, "init", "-q", "-b", "main")
	gitCmd(t, dir, "config", "user.email", "test@mimir.example")
	gitCmd(t, dir, "config", "user.name", "Mimir Test")
	gitCmd(t, dir, "config", "commit.gpgsign", "false")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "leak.txt"),
		[]byte("aws_access_key_id = AKIAFAKEKEYABCDE2345\n"), 0600))
	gitCmd(t, dir, "add", "leak.txt")
	gitCmd(t, dir, "commit", "-q", "-m", "add secret")
	gitCmd(t, dir, "rm", "-q", "leak.txt")
	gitCmd(t, dir, "commit", "-q", "-m", "remove secret file")
	return dir
}

// TestGitModeFindsHistorySecret verifies `mimir scan --git` finds a secret added
// in a past commit and later deleted, exits 1, and prints the rule plus a short
// SHA marker (SCAN-03 criterion 1, end-to-end).
func TestGitModeFindsHistorySecret(t *testing.T) {
	dir := newGitFixtureRepo(t)
	stdout, _, code := runMimir(t, "scan", "--no-color", "--git", dir)
	assert.Equal(t, 1, code, "history secret must flip exit to 1")
	assert.Contains(t, stdout, "aws-access-token", "the matched rule must be reported")
	assert.Contains(t, stdout, "leak.txt", "the leaking file must be reported")
	assert.Contains(t, stdout, " @ ", "history output must append a short commit SHA marker (D-10)")
	assert.NotContains(t, stdout, "AKIAFAKEKEYABCDE2345", "raw secret must never appear in output")
}

// TestGitModeNonRepoFailsLoud verifies `--git` against a non-git directory exits
// 2 (fail-loud, Pitfall 4) rather than silently reporting clean.
func TestGitModeNonRepoFailsLoud(t *testing.T) {
	dir := t.TempDir() // no git init
	_, _, code := runMimir(t, "scan", "--no-color", "--git", dir)
	assert.Equal(t, 2, code, "--git on a non-git directory must exit 2")
}

// newStagedFixtureRepo builds a temp git repo with an initial commit, then stages
// `name` containing `content` (staged but not committed) so `git diff --staged`
// has a HEAD to diff against and the staged line is reported.
func newStagedFixtureRepo(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	gitCmd(t, dir, "init", "-q", "-b", "main")
	gitCmd(t, dir, "config", "user.email", "test@mimir.example")
	gitCmd(t, dir, "config", "user.name", "Mimir Test")
	gitCmd(t, dir, "config", "commit.gpgsign", "false")
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".keep"), []byte("init\n"), 0600))
	gitCmd(t, dir, "add", ".keep")
	gitCmd(t, dir, "commit", "-q", "-m", "init")
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0600))
	gitCmd(t, dir, "add", name)
	return dir
}

// TestStagedModeFindsSecret verifies `mimir scan --staged` finds a staged secret,
// exits 1 (so the hook blocks the commit, IFACE-02), reports the file, and emits
// NO commit-SHA marker (staged findings carry no commit metadata, Pitfall 5).
func TestStagedModeFindsSecret(t *testing.T) {
	dir := newStagedFixtureRepo(t, "leak.txt", "aws_access_key_id = AKIAFAKEKEYABCDE2345\n")
	stdout, _, code := runMimir(t, "scan", "--no-color", "--staged", dir)
	assert.Equal(t, 1, code, "a staged secret must flip exit to 1")
	assert.Contains(t, stdout, "aws-access-token", "the matched rule must be reported")
	assert.Contains(t, stdout, "leak.txt", "the leaking file must be reported")
	assert.NotContains(t, stdout, " @ ", "staged output must NOT carry a commit SHA marker (Pitfall 5)")
	assert.NotContains(t, stdout, "AKIAFAKEKEYABCDE2345", "raw secret must never appear in output")
}

// TestStagedModeNoCommitJSON verifies staged JSON output has no commit_sha key
// (OUT-02 byte-identical schema for non-history scans).
func TestStagedModeNoCommitJSON(t *testing.T) {
	dir := newStagedFixtureRepo(t, "leak.txt", "aws_access_key_id = AKIAFAKEKEYABCDE2345\n")
	stdout, _, _ := runMimir(t, "scan", "--no-color", "--staged", "--format", "json", dir)
	assert.Contains(t, stdout, "aws-access-token", "staged JSON must report the finding")
	assert.NotContains(t, stdout, "commit_sha", "staged JSON must omit commit_sha (OUT-02, Pitfall 5)")
}

// TestStagedInlineIgnoreCmd verifies a staged secret on a `// mimir:ignore` line
// yields exit 0 — the inline-ignore directive is honored end-to-end (criterion 3).
func TestStagedInlineIgnoreCmd(t *testing.T) {
	dir := newStagedFixtureRepo(t, "leak.go",
		"key := \"AKIAFAKEKEYABCDE2345\" // mimir:ignore\n")
	_, _, code := runMimir(t, "scan", "--no-color", "--staged", dir)
	assert.Equal(t, 0, code, "an inline-ignored staged secret must exit 0")
}

// TestGitStagedMutuallyExclusive verifies `scan --git --staged` exits 2 (misuse,
// Pitfall 6 / RESEARCH A2).
func TestGitStagedMutuallyExclusive(t *testing.T) {
	dir := newStagedFixtureRepo(t, "leak.txt", "aws_access_key_id = AKIAFAKEKEYABCDE2345\n")
	_, stderr, code := runMimir(t, "scan", "--no-color", "--git", "--staged", dir)
	assert.Equal(t, 2, code, "--git and --staged together must exit 2")
	assert.Contains(t, stderr, "mutually exclusive", "the error must explain the misuse")
}
