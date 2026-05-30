package gitscan_test

import (
	"context"
	"os"
	"os/exec"
	"testing"

	"github.com/MatrixMagician/mimir/internal/config"
	"github.com/MatrixMagician/mimir/internal/detect"
	"github.com/MatrixMagician/mimir/internal/gitscan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixtureSecret is an AWS access-key token that matches the aws-access-token
// rule but is NOT suppressed by the global '.+EXAMPLE$' allowlist (Phase 1
// 01-02 decision). It mirrors the fixture in testdata/fixtures.
const fixtureSecret = "AKIAFAKEKEYABCDE2345"

// newTestEngine builds a real detection engine from the embedded default
// config, mirroring scanner_test.go's newTestScanner pattern.
func newTestEngine(t *testing.T) *detect.Engine {
	t.Helper()
	cfg, err := config.LoadDefault()
	require.NoError(t, err)
	return detect.NewEngine(cfg)
}

// git runs a git command in dir and fails the test on error.
func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	full := append([]string{"-C", dir}, args...)
	cmd := exec.Command("git", full...)
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "git %v failed: %s", args, string(out))
}

// initRepo creates a temp git repo with deterministic identity/config so commit
// metadata is stable and no global git config interferes.
func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	git(t, dir, "config", "user.email", "test@mimir.example")
	git(t, dir, "config", "user.name", "Mimir Test")
	git(t, dir, "config", "commit.gpgsign", "false")
	return dir
}

// writeFile writes content to name within dir.
func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := dir + "/" + name
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

// newHistoryFixture builds a repo where a secret is added in commit 1 and the
// file is deleted in commit 2 — the criterion-1 added-then-deleted case.
func newHistoryFixture(t *testing.T) string {
	t.Helper()
	dir := initRepo(t)
	writeFile(t, dir, "leak.txt", "aws_access_key_id = "+fixtureSecret+"\n")
	git(t, dir, "add", "leak.txt")
	git(t, dir, "commit", "-q", "-m", "add secret")
	git(t, dir, "rm", "-q", "leak.txt")
	git(t, dir, "commit", "-q", "-m", "remove secret file")
	return dir
}

// TestHistoryDeletedSecret asserts ScanHistory finds a secret that was added in
// a past commit and later deleted (SCAN-03 criterion 1), with file/line/rule and
// a non-empty CommitSHA.
func TestHistoryDeletedSecret(t *testing.T) {
	dir := newHistoryFixture(t)
	eng := newTestEngine(t)

	findings, stats, err := gitscan.ScanHistory(context.Background(), eng, dir, false)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "expected the added-then-deleted secret to be found")

	var hit bool
	for _, f := range findings {
		if f.RuleID == "aws-access-token" {
			hit = true
			assert.Equal(t, "leak.txt", f.File)
			assert.Equal(t, 1, f.Line)
			assert.NotEmpty(t, f.CommitSHA, "history finding must carry a commit SHA")
			assert.NotContains(t, f.Secret, fixtureSecret, "raw secret must be redacted")
		}
	}
	assert.True(t, hit, "expected an aws-access-token finding")
	_ = stats
}

// TestHistoryDedup asserts the same secret touched across two commits collapses
// to ONE finding by fingerprint (D-09), even though it appears as an added line
// in two commits.
func TestHistoryDedup(t *testing.T) {
	dir := initRepo(t)
	// Commit 1: add the secret.
	writeFile(t, dir, "leak.txt", "key = "+fixtureSecret+"\n")
	git(t, dir, "add", "leak.txt")
	git(t, dir, "commit", "-q", "-m", "add secret")
	// Commit 2: modify the surrounding line (same secret value, re-added line).
	writeFile(t, dir, "leak.txt", "export key = "+fixtureSecret+"  # prod\n")
	git(t, dir, "add", "leak.txt")
	git(t, dir, "commit", "-q", "-m", "reword secret line")

	eng := newTestEngine(t)
	findings, _, err := gitscan.ScanHistory(context.Background(), eng, dir, false)
	require.NoError(t, err)

	fps := map[string]int{}
	for _, f := range findings {
		if f.RuleID == "aws-access-token" {
			fps[f.Fingerprint]++
		}
	}
	require.Len(t, fps, 1, "the same secret across commits must collapse to one fingerprint")
	for fp, n := range fps {
		assert.Equalf(t, 1, n, "fingerprint %s should appear exactly once after dedup", fp)
	}
}

// TestHistoryNonRepoFailsLoud asserts ScanHistory returns an error (→ exit 2)
// when run against a directory that is not a git repository (Pitfall 4).
func TestHistoryNonRepoFailsLoud(t *testing.T) {
	dir := t.TempDir() // plain dir, no git init
	eng := newTestEngine(t)
	_, _, err := gitscan.ScanHistory(context.Background(), eng, dir, false)
	require.Error(t, err, "scanning a non-git directory must fail loud, not exit clean")
}

// newStagedFixture builds a repo with an initial commit, then writes `name` with
// `content` and `git add`s it (staged but NOT committed). The staged diff
// (index vs HEAD) therefore contains the freshly staged line, which is what
// ScanStaged scans (criterion 3). The first commit gives `git diff --staged` a
// HEAD to diff against.
func newStagedFixture(t *testing.T, name, content string) string {
	t.Helper()
	dir := initRepo(t)
	// An initial commit so --staged diffs against HEAD rather than the empty tree.
	writeFile(t, dir, ".keep", "init\n")
	git(t, dir, "add", ".keep")
	git(t, dir, "commit", "-q", "-m", "init")
	// Stage the secret-bearing file without committing it.
	writeFile(t, dir, name, content)
	git(t, dir, "add", name)
	return dir
}

// TestStagedSecret asserts ScanStaged finds a secret in the staged diff at the
// correct file:line with rule aws-access-token and — crucially — an EMPTY
// CommitSHA, since staged diffs carry no commit metadata (Pitfall 5, OUT-02).
func TestStagedSecret(t *testing.T) {
	dir := newStagedFixture(t, "leak.txt", "aws_access_key_id = "+fixtureSecret+"\n")
	eng := newTestEngine(t)

	findings, _, err := gitscan.ScanStaged(context.Background(), eng, dir, false)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "expected the staged secret to be found")

	var hit bool
	for _, f := range findings {
		if f.RuleID == "aws-access-token" {
			hit = true
			assert.Equal(t, "leak.txt", f.File)
			assert.Equal(t, 1, f.Line)
			assert.Empty(t, f.CommitSHA, "staged finding must NOT carry a commit SHA (Pitfall 5)")
			assert.NotContains(t, f.Secret, fixtureSecret, "raw secret must be redacted")
		}
	}
	assert.True(t, hit, "expected an aws-access-token finding in the staged diff")
}

// TestStagedInlineIgnore asserts a staged secret whose line carries
// `// mimir:ignore` yields ZERO findings — the inline-ignore directive is honored
// on staged diff lines exactly as in the working-tree scanner (criterion 3,
// reuses SUP-01).
func TestStagedInlineIgnore(t *testing.T) {
	dir := newStagedFixture(t, "leak.go",
		"key := \""+fixtureSecret+"\" // mimir:ignore\n")
	eng := newTestEngine(t)

	findings, _, err := gitscan.ScanStaged(context.Background(), eng, dir, false)
	require.NoError(t, err)
	assert.Empty(t, findings, "an inline-ignored staged secret must yield zero findings")
}

// TestStagedNonRepoFailsLoud asserts ScanStaged returns an error (→ exit 2) when
// run against a non-git directory (Pitfall 4), mirroring the history path.
func TestStagedNonRepoFailsLoud(t *testing.T) {
	dir := t.TempDir() // plain dir, no git init
	eng := newTestEngine(t)
	_, _, err := gitscan.ScanStaged(context.Background(), eng, dir, false)
	require.Error(t, err, "scanning a non-git directory must fail loud, not exit clean")
}
