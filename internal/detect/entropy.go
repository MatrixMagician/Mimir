// Package detect implements the secret detection engine for Mimir.
package detect

import "math"

// shannonEntropy calculates the Shannon entropy of a string.
// Returns 0 for an empty string.
//
// Source: github.com/gitleaks/gitleaks/detect/utils.go (verified algorithm)
// This is a package-level unexported function used by the engine's entropy gate.
func shannonEntropy(data string) float64 {
	if data == "" {
		return 0
	}
	charCounts := make(map[rune]int)
	for _, char := range data {
		charCounts[char]++
	}
	invLength := 1.0 / float64(len(data))
	var entropy float64
	for _, count := range charCounts {
		freq := float64(count) * invLength
		entropy -= freq * math.Log2(freq)
	}
	return entropy
}
