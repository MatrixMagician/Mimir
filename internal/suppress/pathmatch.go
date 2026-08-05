package suppress

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// DefaultPathExcludes is the shipped default-noisy path glob set (SUP-04, D-07):
// vendored / generated / lockfile paths that are almost never the source of a
// real, actionable secret and dominate first-run false positives. Both a root
// form and a recursive `**/` form are included so the globs match whether the
// noisy path is at the scan root or nested.
var DefaultPathExcludes = []string{
	"**/vendor/**", "vendor/**",
	"**/node_modules/**", "node_modules/**",
	"**/dist/**", "**/build/**",
	"**/*.min.js", "**/*.min.css", "**/*.map",
	"**/package-lock.json", "**/npm-shrinkwrap.json",
	"**/yarn.lock", "**/pnpm-lock.yaml",
	"**/go.sum",
	"**/Gemfile.lock", "**/poetry.lock", "**/Pipfile.lock",
	"**/composer.lock", "**/Cargo.lock",
}

// pattern is a single compiled prune rule. negate=true marks a `!`-prefixed
// re-include rule (gitignore-style last-match-wins, D-07).
type pattern struct {
	glob   string
	negate bool
}

// PathMatcher decides whether a repo-relative path should be pruned from the
// walk (SUP-02/SUP-04, D-05..D-07). It combines the shipped default globs (when
// enabled) with the user's `.mimirignore` patterns, applying them in order with
// gitignore-style last-match-wins so a trailing `!negation` re-includes a path.
type PathMatcher struct {
	patterns []pattern
}

// NewPathMatcher builds a matcher from the default globs (when useDefaults is
// true) followed by the caller's ignore lines (in file order, so a user
// `!negation` can re-include a default-pruned path — D-07, Pitfall 2). Blank
// lines and `#` comments are skipped; a leading `!` marks a negation. A
// malformed USER pattern returns a descriptive error (Security V5 — fail loud).
// A malformed shipped default (a Mimir bug, not user input) is skipped rather
// than failing the scan.
func NewPathMatcher(ignoreLines []string, useDefaults bool) (*PathMatcher, error) {
	var pats []pattern
	if useDefaults {
		for _, g := range DefaultPathExcludes {
			if doublestar.ValidatePattern(g) {
				pats = append(pats, pattern{glob: g})
			}
		}
	}
	for _, raw := range ignoreLines {
		g := strings.TrimSpace(raw)
		if g == "" || strings.HasPrefix(g, "#") {
			continue
		}
		neg := false
		if strings.HasPrefix(g, "!") {
			neg = true
			g = strings.TrimSpace(g[1:])
		}
		if g == "" {
			continue
		}
		if !doublestar.ValidatePattern(g) {
			return nil, fmt.Errorf("invalid .mimirignore glob pattern %q", g)
		}
		pats = append(pats, pattern{glob: g, negate: neg})
	}
	return &PathMatcher{patterns: pats}, nil
}

// LoadMimirIgnore reads `<root>/.mimirignore` (D-06: a single root file, no
// nested per-directory files in v1) and returns its non-blank, non-comment
// lines verbatim (negations keep their leading `!`). A missing file is not an
// error — it returns (nil, nil).
func LoadMimirIgnore(root string) ([]string, error) {
	path := filepath.Join(root, ".mimirignore")
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return lines, err
	}
	return lines, nil
}

// Excluded reports whether the given path should be PRUNED (skipped without
// opening). The caller passes a repo-relative path; Excluded normalizes
// backslashes to forward slashes (Pitfall 1 — filepath.ToSlash is a no-op on
// Linux). Patterns apply in order; the last matching pattern wins, so a
// `!negation` after a positive match re-includes the path (Pitfall 2). For
// directories, a glob targeting the subtree (e.g. `vendor/**`) also prunes the
// directory itself so WalkDir can SkipDir the whole subtree.
func (m *PathMatcher) Excluded(relPath string, isDir bool) bool {
	if m == nil {
		return false
	}
	rel := strings.TrimPrefix(strings.ReplaceAll(relPath, `\`, "/"), "./")
	if rel == "" || rel == "." {
		return false
	}

	matched := false
	for _, p := range m.patterns {
		if globMatch(p.glob, rel, isDir) {
			matched = !p.negate
		}
	}
	return matched
}

// globMatch matches a single glob against a forward-slash path. For directories
// it also prunes when the glob targets the directory's subtree (e.g. glob
// `vendor/**` or `**/node_modules/**` prunes the dir `vendor` / `node_modules`).
func globMatch(glob, rel string, isDir bool) bool {
	if ok, err := doublestar.Match(glob, rel); err == nil && ok {
		return true
	}
	if isDir {
		// A trailing-/** glob should prune the directory node itself so WalkDir
		// can SkipDir the entire subtree.
		if trimmed := strings.TrimSuffix(glob, "/**"); trimmed != glob {
			if ok, err := doublestar.Match(trimmed, rel); err == nil && ok {
				return true
			}
		}
	}
	return false
}
