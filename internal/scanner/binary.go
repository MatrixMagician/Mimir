// Package scanner implements the filesystem walker and worker pool for Mimir.
package scanner

import "bytes"

// isBinary reports whether data looks like a binary file.
//
// It uses the NUL-byte heuristic: if any NUL byte (0x00) is present in the
// first 512 bytes, the file is treated as binary and skipped.
//
// This is the same heuristic used by git, grep, and most Unix tools.
// It correctly identifies ELF, PE, ZIP, JPEG, and all other common binary
// formats (all have NUL bytes in their headers), while keeping Mimir
// dependency-free (no MIME-sniffing library needed).
func isBinary(data []byte) bool {
	return bytes.ContainsRune(data, 0)
}
