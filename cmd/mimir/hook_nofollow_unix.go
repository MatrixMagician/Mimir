//go:build !windows

package cmd

import "syscall"

// oNoFollow makes OpenFile refuse to traverse a final-path-component symlink, so
// the managed hook write can never be redirected through a race-planted symlink
// to a file outside the hooks directory (symlink-follow / TOCTOU, T-03-12).
const oNoFollow = syscall.O_NOFOLLOW
