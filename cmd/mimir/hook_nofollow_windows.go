//go:build windows

package cmd

// oNoFollow is a no-op on Windows: the syscall package does not define
// O_NOFOLLOW there, and creating a symlink on Windows requires elevated
// privilege. The Lstat-based symlink refusal in runHookInstall/runHookUninstall
// still applies, so a symlinked pre-commit is detected and refused on every OS.
const oNoFollow = 0
