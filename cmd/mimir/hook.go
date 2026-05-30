package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// hookMarker is the unique comment line written into Mimir's managed pre-commit
// hook. uninstall/status key off this marker so a foreign hook is never touched.
const hookMarker = "# mimir-managed-hook"

// managedHookScript is the body of the managed pre-commit hook. It is staged-only
// and fully offline (NEVER --verify, VERIFY-01). Bypass: `git commit --no-verify`
// or the persistent `git config hooks.mimir false` off-switch (D-06).
const managedHookScript = `#!/bin/sh
` + hookMarker + `
# Managed by 'mimir hook install'. Staged-only, offline secret scan.
# Bypass once: git commit --no-verify
# Bypass persistently: git config hooks.mimir false   (re-enable: git config hooks.mimir true)
if [ "$(git config --type=bool --get hooks.mimir)" = "false" ]; then
	exit 0
fi
exec mimir scan --staged
`

var hookCmd = &cobra.Command{
	Use:   "hook",
	Short: "Manage the mimir pre-commit hook",
	Long:  "Install, uninstall, or check the status of the mimir managed pre-commit hook (mimir scan --staged).",
}

var hookInstallCmd = &cobra.Command{
	Use:   "install [path]",
	Short: "Install the managed pre-commit hook into a git repository",
	Long: "Write a managed pre-commit hook that runs `mimir scan --staged`. " +
		"Refuses to overwrite an existing non-Mimir hook unless --force is given (D-05). " +
		"The hook is staged-only and fully offline.",
	Args: cobra.MaximumNArgs(1),
	RunE: runHookInstall,
}

var hookUninstallCmd = &cobra.Command{
	Use:   "uninstall [path]",
	Short: "Remove the managed pre-commit hook (only if managed by mimir)",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runHookUninstall,
}

var hookStatusCmd = &cobra.Command{
	Use:   "status [path]",
	Short: "Report whether the mimir managed pre-commit hook is installed",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runHookStatus,
}

func init() {
	hookInstallCmd.Flags().Bool("force", false, "Overwrite an existing non-Mimir pre-commit hook")
	hookCmd.AddCommand(hookInstallCmd, hookUninstallCmd, hookStatusCmd)
	rootCmd.AddCommand(hookCmd)
}

// repoArg returns the target repository path from args, defaulting to ".".
func repoArg(args []string) string {
	if len(args) == 0 {
		return "."
	}
	return args[0]
}

// resolveHookPath resolves the pre-commit hook file path via
// `git rev-parse --git-path hooks` (worktree/submodule/core.hooksPath safe — D-05),
// never a hardcoded ".git/hooks". It fails loud (os.Exit(2)) if git is absent or
// the directory is not a git repository (Pitfall 4). The hooks dir is created if
// missing. The returned path is guaranteed to live under the resolved hooks dir.
func resolveHookPath(repoRoot string) string {
	if _, err := exec.LookPath("git"); err != nil {
		fmt.Fprintln(os.Stderr, "error: git not found on PATH (required for the pre-commit hook)")
		os.Exit(2)
	}
	// Explicit arg slice (never sh -c) — no command injection from repoRoot (T-03-10, Security V12).
	out, err := exec.Command("git", "-C", repoRoot, "rev-parse", "--git-path", "hooks").Output() //nolint:gosec
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s is not a git repository (or git failed)\n", repoRoot)
		os.Exit(2)
	}
	hooksDir := strings.TrimSpace(string(out))
	// rev-parse returns a path relative to repoRoot (or absolute); normalize.
	if !filepath.IsAbs(hooksDir) {
		hooksDir = filepath.Join(repoRoot, hooksDir)
	}
	if err := os.MkdirAll(hooksDir, 0o755); err != nil { //nolint:gosec
		fmt.Fprintln(os.Stderr, "error: could not create hooks directory:", err)
		os.Exit(2)
	}
	return filepath.Join(hooksDir, "pre-commit")
}

// isManaged reports whether the file at path is a Mimir-managed hook (carries the
// marker line). A read error (e.g. file absent) reports false.
func isManaged(path string) bool {
	body, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return false
	}
	return strings.Contains(string(body), hookMarker)
}

func runHookInstall(cmd *cobra.Command, args []string) error {
	repoRoot := repoArg(args)
	force, _ := cmd.Flags().GetBool("force")
	hookPath := resolveHookPath(repoRoot)

	// D-05: never silently clobber a foreign pre-commit hook.
	if _, err := os.Stat(hookPath); err == nil {
		if !isManaged(hookPath) && !force {
			return fmt.Errorf("a pre-commit hook already exists at %s — refusing to overwrite a non-mimir hook; re-run with --force to replace it", hookPath)
		}
	}

	if err := os.WriteFile(hookPath, []byte(managedHookScript), 0o755); err != nil { //nolint:gosec
		return fmt.Errorf("writing pre-commit hook: %w", err)
	}
	// Ensure the exec bit survives an existing-file umask (WriteFile only applies
	// perms when creating).
	if err := os.Chmod(hookPath, 0o755); err != nil { //nolint:gosec
		return fmt.Errorf("setting hook executable: %w", err)
	}
	fmt.Printf("mimir: installed managed pre-commit hook at %s\n", hookPath)
	fmt.Println("mimir: bypass once with `git commit --no-verify`, or persistently with `git config hooks.mimir false`")
	return nil
}

func runHookUninstall(cmd *cobra.Command, args []string) error {
	repoRoot := repoArg(args)
	hookPath := resolveHookPath(repoRoot)

	if _, err := os.Stat(hookPath); err != nil {
		fmt.Println("mimir: no pre-commit hook to remove")
		return nil
	}
	// Only remove Mimir's managed hook — never a user's foreign hook.
	if !isManaged(hookPath) {
		return fmt.Errorf("the pre-commit hook at %s is not managed by mimir — refusing to remove it", hookPath)
	}
	if err := os.Remove(hookPath); err != nil {
		return fmt.Errorf("removing pre-commit hook: %w", err)
	}
	fmt.Printf("mimir: removed managed pre-commit hook at %s\n", hookPath)
	return nil
}

func runHookStatus(cmd *cobra.Command, args []string) error {
	repoRoot := repoArg(args)
	hookPath := resolveHookPath(repoRoot)

	if isManaged(hookPath) {
		fmt.Printf("mimir: pre-commit hook installed (managed) at %s\n", hookPath)
		return nil
	}
	if _, err := os.Stat(hookPath); err == nil {
		fmt.Printf("mimir: a non-mimir pre-commit hook is present at %s — mimir hook not installed\n", hookPath)
		return nil
	}
	fmt.Println("mimir: pre-commit hook not installed")
	return nil
}
