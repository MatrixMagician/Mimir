package gitscan

import (
	"context"
	"fmt"
	"io"
	"os/exec"
)

// historyArgs builds the argument slice for the current-branch history command.
//
//   - `-C repoRoot` runs git in the target repo without changing our cwd.
//   - `log -p` emits each commit's patch; `-U0` gives zero context lines so only
//     added/deleted lines appear (smaller, faster, exact line attribution).
//   - `--full-history` follows renames so a moved-then-leaked file is covered.
//   - NO `--all` (D-03): scope is HEAD-reachable history only, not every ref.
//   - `--no-color` keeps the patch stream free of ANSI escapes for the parser.
//
// The args are a fixed slice with repoRoot passed as a distinct argument (never
// interpolated into a shell string), which is the command-injection mitigation
// for T-03-01 (Security V12): repo paths and branch names cannot break out into
// a shell.
func historyArgs(repoRoot string) []string {
	return []string{"-C", repoRoot, "log", "-p", "-U0", "--full-history", "--no-color"}
}

// stagedArgs builds the argument slice for the staged-diff command — the source
// the pre-commit hook invokes (SCAN-04, criterion 3).
//
//   - `-C repoRoot` runs git in the target repo without changing our cwd.
//   - `diff --staged` emits the patch of what is staged for commit (index vs HEAD).
//   - `-U0` gives zero context lines so only added/deleted lines appear (exact
//     line attribution; mirrors historyArgs).
//   - `--no-ext-diff` ignores any external diff driver (`diff.external`) the user
//     may have configured, so we always parse machine-readable unified diff.
//   - `--no-color` keeps the patch stream free of ANSI escapes for the parser.
//
// Like historyArgs, repoRoot is a distinct argument (never interpolated into a
// shell string) — the command-injection mitigation for T-03-06 (Security V12).
// Staged diffs carry no commit preamble, so the parsed PatchHeader is empty and
// no commit metadata attaches to staged findings (Pitfall 5).
func stagedArgs(repoRoot string) []string {
	return []string{"-C", repoRoot, "diff", "-U0", "--no-ext-diff", "--no-color", "--staged"}
}

// startGit spawns `git <args...>` with a streamed stdout pipe and returns the
// started command plus its stdout reader. The caller MUST consume stdout (e.g.
// via gitdiff.Parse) and MUST call cmd.Wait() once the stream is drained — see
// the deferred cleanup in ScanHistory (Pitfall 2: an undrained pipe blocks the
// go-gitdiff goroutine and leaks the git process).
//
// exec.CommandContext (not exec.Command) is used so a cancelled context kills
// the git process, preventing zombie processes on early exit (T-03-04).
func startGit(ctx context.Context, args []string) (*exec.Cmd, io.ReadCloser, error) {
	// Fail loud if git is not on PATH — the new history mode has a documented
	// `git >= 2.x` runtime prerequisite (Pitfall 4). Returning an error here lets
	// runScan surface exit 2 rather than silently reporting "clean".
	if _, err := exec.LookPath("git"); err != nil {
		return nil, nil, fmt.Errorf("git executable not found on PATH (required for --git history scanning): %w", err)
	}

	cmd := exec.CommandContext(ctx, "git", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("creating git stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("starting git: %w", err)
	}
	return cmd, stdout, nil
}
