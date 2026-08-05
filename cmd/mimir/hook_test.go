package cmd_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hookPath resolves the installed pre-commit hook path for a repo using the same
// `git rev-parse --git-path hooks` mechanism the installer uses, so the test does
// not hardcode `.git/hooks` either.
func hookPath(t *testing.T, dir string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--git-path", "hooks").Output()
	require.NoError(t, err)
	hooksDir := strings.TrimSpace(string(out))
	if !filepath.IsAbs(hooksDir) {
		hooksDir = filepath.Join(dir, hooksDir)
	}
	return filepath.Join(hooksDir, "pre-commit")
}

// TestHookInstall installs the managed hook and asserts it exists, is executable,
// and carries the managed marker, the hooks.mimir off-switch, and `scan --staged`.
func TestHookInstall(t *testing.T) {
	dir := initGitRepoWithHEAD(t)
	_, stderr, code := runMimir(t, "hook", "install", dir)
	require.Equalf(t, 0, code, "install must succeed, stderr=%s", stderr)

	hp := hookPath(t, dir)
	info, err := os.Stat(hp)
	require.NoError(t, err, "pre-commit hook file must exist")
	// Owner execute bit must be set (0755 expected).
	assert.NotZero(t, info.Mode().Perm()&0100, "hook must be executable")

	body, err := os.ReadFile(hp) //nolint:gosec
	require.NoError(t, err)
	s := string(body)
	assert.Contains(t, s, "mimir-managed-hook", "hook must carry a managed marker line")
	assert.Contains(t, s, "hooks.mimir", "hook must honor the git config off-switch (D-06)")
	assert.Contains(t, s, "scan --staged", "hook must invoke mimir scan --staged")
	assert.NotContains(t, s, "--verify", "hook must be offline — never --verify (VERIFY-01)")
}

// TestHookInstallRefusesOverwrite refuses to clobber a foreign pre-commit hook
// without --force, and overwrites it with --force (D-05).
func TestHookInstallRefusesOverwrite(t *testing.T) {
	dir := initGitRepoWithHEAD(t)
	hp := hookPath(t, dir)
	require.NoError(t, os.MkdirAll(filepath.Dir(hp), 0755))
	foreign := "#!/bin/sh\necho foreign hook\n"
	require.NoError(t, os.WriteFile(hp, []byte(foreign), 0755))

	// Without --force: refuse, exit non-zero, leave the foreign hook intact.
	_, _, code := runMimir(t, "hook", "install", dir)
	assert.NotEqual(t, 0, code, "install must refuse to clobber a foreign hook")
	got, err := os.ReadFile(hp) //nolint:gosec
	require.NoError(t, err)
	assert.Equal(t, foreign, string(got), "foreign hook must be untouched without --force")

	// With --force: overwrite succeeds and the hook is now managed.
	_, stderr, code := runMimir(t, "hook", "install", "--force", dir)
	require.Equalf(t, 0, code, "install --force must overwrite, stderr=%s", stderr)
	got2, err := os.ReadFile(hp) //nolint:gosec
	require.NoError(t, err)
	assert.Contains(t, string(got2), "mimir-managed-hook", "--force must install the managed hook")
}

// TestHookInstallRefusesSymlink hardens against symlink-follow / TOCTOU
// (T-03-12): a pre-commit that is a symlink must be refused without --force and
// must NEVER have the 0755 hook script written through it to the link target.
// With --force the symlink is replaced by a regular managed file and the target
// is left untouched.
func TestHookInstallRefusesSymlink(t *testing.T) {
	dir := initGitRepoWithHEAD(t)
	hp := hookPath(t, dir)
	require.NoError(t, os.MkdirAll(filepath.Dir(hp), 0755))

	// A sensitive file outside the hooks dir that a symlink-follow write would clobber.
	target := filepath.Join(dir, "sensitive.txt")
	const sentinel = "do-not-overwrite\n"
	require.NoError(t, os.WriteFile(target, []byte(sentinel), 0600))
	require.NoError(t, os.Symlink(target, hp))

	// Without --force: refuse, and the link target must be byte-for-byte intact.
	_, _, code := runMimir(t, "hook", "install", dir)
	assert.NotEqual(t, 0, code, "install must refuse a symlinked pre-commit without --force")
	got, err := os.ReadFile(target) //nolint:gosec
	require.NoError(t, err)
	assert.Equal(t, sentinel, string(got), "symlink target must not be written through")

	// With --force: the symlink is replaced by a regular managed file; target intact.
	_, stderr, code := runMimir(t, "hook", "install", "--force", dir)
	require.Equalf(t, 0, code, "install --force must replace a symlinked hook, stderr=%s", stderr)
	fi, err := os.Lstat(hp)
	require.NoError(t, err)
	assert.Zero(t, fi.Mode()&os.ModeSymlink, "hook must now be a regular file, not a symlink")
	got2, err := os.ReadFile(target) //nolint:gosec
	require.NoError(t, err)
	assert.Equal(t, sentinel, string(got2), "symlink target must remain untouched after --force")
	body, err := os.ReadFile(hp) //nolint:gosec
	require.NoError(t, err)
	assert.Contains(t, string(body), "mimir-managed-hook", "--force must install the managed hook in place")
}

// TestHookUninstallManagedOnly removes a managed hook but refuses to delete a
// foreign one (marker-line check).
func TestHookUninstallManagedOnly(t *testing.T) {
	// Managed: install then uninstall removes it.
	dir := initGitRepoWithHEAD(t)
	_, _, code := runMimir(t, "hook", "install", dir)
	require.Equal(t, 0, code)
	hp := hookPath(t, dir)
	require.FileExists(t, hp)
	_, stderr, code := runMimir(t, "hook", "uninstall", dir)
	require.Equalf(t, 0, code, "uninstall of managed hook must succeed, stderr=%s", stderr)
	assert.NoFileExists(t, hp, "managed hook must be removed")

	// Foreign: uninstall refuses and leaves it intact.
	dir2 := initGitRepoWithHEAD(t)
	hp2 := hookPath(t, dir2)
	require.NoError(t, os.MkdirAll(filepath.Dir(hp2), 0755))
	foreign := "#!/bin/sh\necho foreign\n"
	require.NoError(t, os.WriteFile(hp2, []byte(foreign), 0755))
	_, _, code2 := runMimir(t, "hook", "uninstall", dir2)
	assert.NotEqual(t, 0, code2, "uninstall must refuse to delete a foreign hook")
	got, err := os.ReadFile(hp2) //nolint:gosec
	require.NoError(t, err)
	assert.Equal(t, foreign, string(got), "foreign hook must be untouched by uninstall")
}

// TestHookStatus reports installed/not-installed accurately before and after install.
func TestHookStatus(t *testing.T) {
	dir := initGitRepoWithHEAD(t)
	out, _, _ := runMimir(t, "hook", "status", dir)
	assert.Contains(t, strings.ToLower(out), "not installed", "status before install must say not installed")

	_, _, code := runMimir(t, "hook", "install", dir)
	require.Equal(t, 0, code)
	out2, _, _ := runMimir(t, "hook", "status", dir)
	low := strings.ToLower(out2)
	assert.Contains(t, low, "installed", "status after install must say installed")
	assert.NotContains(t, low, "not installed", "status after install must not say not installed")
}

// TestHookNonRepoFailsLoud verifies install in a non-git directory exits 2 (Pitfall 4).
func TestHookNonRepoFailsLoud(t *testing.T) {
	dir := t.TempDir() // no git init
	_, _, code := runMimir(t, "hook", "install", dir)
	assert.Equal(t, 2, code, "install in a non-git directory must exit 2")
}

// mimirBinDir installs a copy of the built test binary named exactly `mimir` into
// a temp dir and returns that dir. The installed hook execs `mimir`, so prepending
// this dir to PATH makes the hook resolve to the just-built binary (never a
// globally-installed mimir, and never THIS project's repo).
func mimirBinDir(t *testing.T) string {
	t.Helper()
	binDir := t.TempDir()
	src, err := os.ReadFile(mimirTestBin) //nolint:gosec
	require.NoError(t, err, "test binary must exist (built in TestMain)")
	// The installed hook execs bare `mimir`, so the copy must carry the
	// platform's executable extension for PATH resolution to find it.
	dst := filepath.Join(binDir, "mimir"+exeSuffix())
	require.NoError(t, os.WriteFile(dst, src, 0755)) //nolint:gosec
	return binDir
}

// commitInRepo drives a real `git commit` inside dir with the mimir test binary's
// dir prepended to PATH (so the installed hook's `exec mimir scan --staged`
// resolves to the built binary). Returns combined output and exit code.
func commitInRepo(t *testing.T, dir string, extraArgs ...string) (string, int) {
	t.Helper()
	binDir := mimirBinDir(t)
	args := append([]string{"-C", dir, "commit", "-m", "add staged change"}, extraArgs...)
	cmd := exec.Command("git", args...) //nolint:gosec
	cmd.Env = append(os.Environ(), "PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		} else {
			code = -1
		}
	}
	return string(out), code
}

// stageSecret writes name with content and stages it.
func stageSecret(t *testing.T, dir, name, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0600))
	gitCmd(t, dir, "add", name)
}

// hookSecret is an AWS access-key token that matches the aws-access-token rule and
// is NOT suppressed by the global '.+EXAMPLE$' allowlist.
const hookSecret = "AKIAFAKEKEYABCDE2345"

// TestHookBlocksCommit installs the hook, stages a secret, and asserts a real
// `git commit` is blocked (non-zero), with the finding named and NO raw secret in
// the hook output (criterion 3, redact-at-boundary).
func TestHookBlocksCommit(t *testing.T) {
	dir := initGitRepoWithHEAD(t)
	_, _, code := runMimir(t, "hook", "install", dir)
	require.Equal(t, 0, code)

	stageSecret(t, dir, "leak.txt", "aws_access_key_id = "+hookSecret+"\n")
	out, ccode := commitInRepo(t, dir)
	assert.NotEqual(t, 0, ccode, "commit with a staged secret must be blocked")
	assert.Contains(t, out, "aws-access-token", "hook output must name the finding")
	assert.NotContains(t, out, hookSecret, "raw secret must never appear in hook output (Security V7)")
}

// TestHookRespectsInlineIgnore stages a secret on a `// mimir:ignore` line and
// asserts the commit SUCCEEDS — inline-ignore honored end-to-end (criterion 3).
func TestHookRespectsInlineIgnore(t *testing.T) {
	dir := initGitRepoWithHEAD(t)
	_, _, code := runMimir(t, "hook", "install", dir)
	require.Equal(t, 0, code)

	stageSecret(t, dir, "leak.go", "key := \""+hookSecret+"\" // mimir:ignore\n")
	out, ccode := commitInRepo(t, dir)
	assert.Equalf(t, 0, ccode, "an inline-ignored staged secret must commit cleanly, out=%s", out)
}

// TestHookBypass asserts both honest bypasses: `git commit --no-verify` and the
// persistent `git config hooks.mimir false` toggle; unsetting restores blocking (D-06).
func TestHookBypass(t *testing.T) {
	dir := initGitRepoWithHEAD(t)
	_, _, code := runMimir(t, "hook", "install", dir)
	require.Equal(t, 0, code)
	stageSecret(t, dir, "leak.txt", "aws_access_key_id = "+hookSecret+"\n")

	// (a) --no-verify bypasses the hook entirely.
	out, ccode := commitInRepo(t, dir, "--no-verify")
	assert.Equalf(t, 0, ccode, "--no-verify must allow the commit, out=%s", out)

	// Re-stage another secret for the config-toggle path (previous commit consumed the first).
	stageSecret(t, dir, "leak2.txt", "aws_access_key_id = "+hookSecret+"\n")

	// (b) hooks.mimir false bypasses; commit succeeds.
	gitCmd(t, dir, "config", "hooks.mimir", "false")
	out2, ccode2 := commitInRepo(t, dir)
	assert.Equalf(t, 0, ccode2, "hooks.mimir false must allow the commit, out=%s", out2)

	// (c) unsetting restores blocking.
	gitCmd(t, dir, "config", "--unset", "hooks.mimir")
	stageSecret(t, dir, "leak3.txt", "aws_access_key_id = "+hookSecret+"\n")
	_, ccode3 := commitInRepo(t, dir)
	assert.NotEqual(t, 0, ccode3, "after --unset, the hook must block again (D-06)")
}

// TestHookOffline asserts the installed hook body is offline: it contains no
// `--verify` and scans `--staged` only (static guarantee, VERIFY-01).
func TestHookOffline(t *testing.T) {
	dir := initGitRepoWithHEAD(t)
	_, _, code := runMimir(t, "hook", "install", dir)
	require.Equal(t, 0, code)
	body, err := os.ReadFile(hookPath(t, dir)) //nolint:gosec
	require.NoError(t, err)
	s := string(body)
	assert.NotContains(t, s, "--verify", "hook must never run live verification (offline, VERIFY-01)")
	assert.Contains(t, s, "scan --staged", "hook must scan staged changes only")
}
