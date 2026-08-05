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
// config, mirroring scanner_test.go's newTestScanner pattern. It accepts
// testing.TB so both tests and benchmarks can use it.
func newTestEngine(tb testing.TB) *detect.Engine {
	tb.Helper()
	cfg, err := config.LoadDefault()
	require.NoError(tb, err)
	return detect.NewEngine(cfg)
}

// git runs a git command in dir and fails the test/benchmark on error.
func git(tb testing.TB, dir string, args ...string) {
	tb.Helper()
	full := append([]string{"-C", dir}, args...)
	cmd := exec.Command("git", full...)
	out, err := cmd.CombinedOutput()
	require.NoErrorf(tb, err, "git %v failed: %s", args, string(out))
}

// initRepo creates a temp git repo with deterministic identity/config so commit
// metadata is stable and no global git config interferes.
func initRepo(tb testing.TB) string {
	tb.Helper()
	dir := tb.TempDir()
	git(tb, dir, "init", "-q", "-b", "main")
	git(tb, dir, "config", "user.email", "test@mimir.example")
	git(tb, dir, "config", "user.name", "Mimir Test")
	git(tb, dir, "config", "commit.gpgsign", "false")
	return dir
}

// writeFile writes content to name within dir.
func writeFile(tb testing.TB, dir, name, content string) {
	tb.Helper()
	path := dir + "/" + name
	require.NoError(tb, os.WriteFile(path, []byte(content), 0o600))
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

	findings, _, stats, err := gitscan.ScanHistory(context.Background(), eng, dir, false)
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
	findings, _, _, err := gitscan.ScanHistory(context.Background(), eng, dir, false)
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
	_, _, _, err := gitscan.ScanHistory(context.Background(), eng, dir, false)
	require.Error(t, err, "scanning a non-git directory must fail loud, not exit clean")
}

// newStagedFixture builds a repo with an initial commit, then writes `name` with
// `content` and `git add`s it (staged but NOT committed). The staged diff
// (index vs HEAD) therefore contains the freshly staged line, which is what
// ScanStaged scans (criterion 3). The first commit gives `git diff --staged` a
// HEAD to diff against.
func newStagedFixture(tb testing.TB, name, content string) string {
	tb.Helper()
	dir := initRepo(tb)
	// An initial commit so --staged diffs against HEAD rather than the empty tree.
	writeFile(tb, dir, ".keep", "init\n")
	git(tb, dir, "add", ".keep")
	git(tb, dir, "commit", "-q", "-m", "init")
	// Stage the secret-bearing file without committing it.
	writeFile(tb, dir, name, content)
	git(tb, dir, "add", name)
	return dir
}

// TestStagedSecret asserts ScanStaged finds a secret in the staged diff at the
// correct file:line with rule aws-access-token and — crucially — an EMPTY
// CommitSHA, since staged diffs carry no commit metadata (Pitfall 5, OUT-02).
func TestStagedSecret(t *testing.T) {
	dir := newStagedFixture(t, "leak.txt", "aws_access_key_id = "+fixtureSecret+"\n")
	eng := newTestEngine(t)

	findings, _, _, err := gitscan.ScanStaged(context.Background(), eng, dir, false)
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

// TestHistoryRawSideChannel asserts ScanHistory threads the fingerprint→raw
// side channel out: a secret added then deleted in history is still resolvable
// to its exact raw value, keyed by the surviving finding's fingerprint, while
// the raw value never appears on the redacted Finding.
func TestHistoryRawSideChannel(t *testing.T) {
	dir := newHistoryFixture(t)
	eng := newTestEngine(t)

	findings, raw, _, err := gitscan.ScanHistory(context.Background(), eng, dir, false)
	require.NoError(t, err)
	require.NotEmpty(t, findings)
	require.NotNil(t, raw, "raw side channel must be non-nil")

	var hit bool
	for _, f := range findings {
		if f.RuleID == "aws-access-token" {
			hit = true
			gotRaw, ok := raw[f.Fingerprint]
			require.Truef(t, ok, "raw map must resolve fingerprint %s", f.Fingerprint)
			assert.Equal(t, fixtureSecret, gotRaw, "raw map must carry the exact deleted secret")
			assert.NotContains(t, f.Secret, fixtureSecret, "raw secret must be redacted on Finding")
		}
	}
	assert.True(t, hit)
}

// TestStagedRawSideChannel asserts ScanStaged threads the fingerprint→raw side
// channel out for a staged secret, keyed by the staged finding's fingerprint.
func TestStagedRawSideChannel(t *testing.T) {
	dir := newStagedFixture(t, "leak.txt", "aws_access_key_id = "+fixtureSecret+"\n")
	eng := newTestEngine(t)

	findings, raw, _, err := gitscan.ScanStaged(context.Background(), eng, dir, false)
	require.NoError(t, err)
	require.NotEmpty(t, findings)
	require.NotNil(t, raw, "raw side channel must be non-nil")

	var hit bool
	for _, f := range findings {
		if f.RuleID == "aws-access-token" {
			hit = true
			gotRaw, ok := raw[f.Fingerprint]
			require.Truef(t, ok, "raw map must resolve fingerprint %s", f.Fingerprint)
			assert.Equal(t, fixtureSecret, gotRaw, "raw map must carry the exact staged secret")
		}
	}
	assert.True(t, hit)
}

// TestStagedInlineIgnore asserts a staged secret whose line carries
// `// mimir:ignore` yields ZERO findings — the inline-ignore directive is honored
// on staged diff lines exactly as in the working-tree scanner (criterion 3,
// reuses SUP-01).
func TestStagedInlineIgnore(t *testing.T) {
	dir := newStagedFixture(t, "leak.go",
		"key := \""+fixtureSecret+"\" // mimir:ignore\n")
	eng := newTestEngine(t)

	findings, _, _, err := gitscan.ScanStaged(context.Background(), eng, dir, false)
	require.NoError(t, err)
	assert.Empty(t, findings, "an inline-ignored staged secret must yield zero findings")
}

// TestStagedNonRepoFailsLoud asserts ScanStaged returns an error (→ exit 2) when
// run against a non-git directory (Pitfall 4), mirroring the history path.
func TestStagedNonRepoFailsLoud(t *testing.T) {
	dir := t.TempDir() // plain dir, no git init
	eng := newTestEngine(t)
	_, _, _, err := gitscan.ScanStaged(context.Background(), eng, dir, false)
	require.Error(t, err, "scanning a non-git directory must fail loud, not exit clean")
}

// TestStatsCountFilesNotFindings is a regression test for the summary line.
// Stats.FilesScanned was set to len(deduped) — the FINDING count — so the
// "scanned N files" summary lied in both git modes: a clean staged commit of
// four files reported "scanned 0 files", and a history scan reported its finding
// count instead of the number of files the patch touched. FilesScanned must mean
// the same thing in every mode.
func TestStatsCountFilesNotFindings(t *testing.T) {
	dir := initRepo(t)
	// Three files, only one of which carries a secret.
	writeFile(t, dir, "clean1.txt", "nothing to see here\n")
	writeFile(t, dir, "clean2.txt", "also benign\n")
	writeFile(t, dir, "leak.txt", "aws_access_key_id = "+fixtureSecret+"\n")
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-q", "-m", "three files, one secret")

	findings, _, stats, err := gitscan.ScanHistory(context.Background(), newTestEngine(t), dir, false)
	require.NoError(t, err)
	require.NotEmpty(t, findings, "the seeded secret must be found")

	assert.Equal(t, 3, stats.FilesScanned,
		"FilesScanned must count the files the patch touched, not the findings")
	assert.NotEqual(t, len(findings), stats.FilesScanned,
		"FilesScanned must not be an alias for the finding count")
}

// TestStagedStatsCountCleanFiles pins the most visible symptom: a staged commit
// with NO secrets reported "scanned 0 files", which reads as though the hook
// checked nothing at all.
func TestStagedStatsCountCleanFiles(t *testing.T) {
	dir := initRepo(t)
	writeFile(t, dir, ".keep", "init\n")
	git(t, dir, "add", ".keep")
	git(t, dir, "commit", "-q", "-m", "init")

	for _, name := range []string{"a.txt", "b.txt", "c.txt", "d.txt"} {
		writeFile(t, dir, name, "benign line\n")
	}
	git(t, dir, "add", ".")

	findings, _, stats, err := gitscan.ScanStaged(context.Background(), newTestEngine(t), dir, false)
	require.NoError(t, err)
	assert.Empty(t, findings, "no secrets were staged")
	assert.Equal(t, 4, stats.FilesScanned,
		"a clean staged scan must still report the files it examined")
}
