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

// hookRepo creates a temp git repo with deterministic identity and an initial
// commit so it has a HEAD to diff staged changes against.
func hookRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gitCmd(t, dir, "init", "-q", "-b", "main")
	gitCmd(t, dir, "config", "user.email", "test@mimir.example")
	gitCmd(t, dir, "config", "user.name", "Mimir Test")
	gitCmd(t, dir, "config", "commit.gpgsign", "false")
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".keep"), []byte("init\n"), 0600))
	gitCmd(t, dir, "add", ".keep")
	gitCmd(t, dir, "commit", "-q", "-m", "init")
	return dir
}

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
	dir := hookRepo(t)
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
	dir := hookRepo(t)
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

// TestHookUninstallManagedOnly removes a managed hook but refuses to delete a
// foreign one (marker-line check).
func TestHookUninstallManagedOnly(t *testing.T) {
	// Managed: install then uninstall removes it.
	dir := hookRepo(t)
	_, _, code := runMimir(t, "hook", "install", dir)
	require.Equal(t, 0, code)
	hp := hookPath(t, dir)
	require.FileExists(t, hp)
	_, stderr, code := runMimir(t, "hook", "uninstall", dir)
	require.Equalf(t, 0, code, "uninstall of managed hook must succeed, stderr=%s", stderr)
	assert.NoFileExists(t, hp, "managed hook must be removed")

	// Foreign: uninstall refuses and leaves it intact.
	dir2 := hookRepo(t)
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
	dir := hookRepo(t)
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
