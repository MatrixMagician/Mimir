package detect

import (
	"slices"
	"strings"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"github.com/MatrixMagician/mimir/internal/config"
	"github.com/MatrixMagician/mimir/internal/finding"
)

// Engine holds the compiled Aho-Corasick trie and rule set.
// It is stateless after construction and safe to call from multiple goroutines.
type Engine struct {
	trie *ahocorasick.Trie
	cfg  *config.Config

	// keywordRules maps a lowercased keyword to the indices of the rules that
	// declare it, so a trie hit resolves straight to its candidate rules. The
	// alternative — re-lowercasing every keyword of every rule on every line —
	// was the hot path's dominant cost.
	keywordRules map[string][]int
}

// NewEngine builds a detection engine from a validated Config.
// Keywords for all rules are lowercased and added to a single Aho-Corasick trie
// for O(n) per-line keyword pre-filtering.
func NewEngine(cfg *config.Config) *Engine {
	keywordRules := make(map[string][]int)
	for i, rule := range cfg.Rules {
		for _, kw := range rule.Keywords {
			lower := strings.ToLower(kw)
			// A rule that declares the same keyword twice must not appear twice
			// in the candidate list.
			if rules := keywordRules[lower]; len(rules) > 0 && rules[len(rules)-1] == i {
				continue
			}
			keywordRules[lower] = append(keywordRules[lower], i)
		}
	}

	var trie *ahocorasick.Trie
	if len(keywordRules) > 0 {
		keywords := make([]string, 0, len(keywordRules))
		for kw := range keywordRules {
			keywords = append(keywords, kw)
		}
		trie = ahocorasick.NewTrieBuilder().AddStrings(keywords).Build()
	}

	return &Engine{trie: trie, cfg: cfg, keywordRules: keywordRules}
}

// ScanLine runs the detection pipeline on a single line of text.
//
// Pipeline: Aho-Corasick keyword gate → RE2 regex → entropy check → allowlist check → finding.New()
//
// The raw secret value is passed only to finding.New() which enforces redact-at-boundary.
// This function never stores or logs the raw secret value on the Finding.
//
// The raw map is a caller-provided side channel for opt-in live verification
// (Phase 4): for each finding produced, ScanLine writes raw[f.Fingerprint] =
// rawSecret. This is the ONE site where the raw value still exists. The raw map
// is NEVER assigned to a Finding field and NEVER serialized — it is consumed
// off-struct by internal/verify. Callers that do not need verification may pass
// a throwaway map.
//
// Parameters:
//   - line: the raw line content (NOT lowercased)
//   - filePath: repo-relative file path for the Finding
//   - lineNum: 1-indexed line number
//   - raw: side-channel sink keyed by fingerprint → raw secret (off-struct)
func (e *Engine) ScanLine(line, filePath string, lineNum int, raw map[string]string) []finding.Finding {
	// Fast path: if no trie (no rules) or no keyword matches, skip all regex work.
	if e.trie == nil {
		return nil
	}
	matches := e.trie.MatchString(strings.ToLower(line))
	if len(matches) == 0 {
		return nil
	}

	// Resolve the matched keywords to their candidate rules. Sorting the indices
	// keeps findings in rule-declaration order, which the output contract relies
	// on (a line matching two rules always reports them in config order).
	var candidates []int
	for _, m := range matches {
		for _, ri := range e.keywordRules[m.MatchString()] {
			if !slices.Contains(candidates, ri) {
				candidates = append(candidates, ri)
			}
		}
	}
	slices.Sort(candidates)

	var findings []finding.Finding

	for _, ri := range candidates {
		rule := e.cfg.Rules[ri]
		if rule.CompiledRegex == nil {
			continue
		}

		// Run the RE2 regex on the ORIGINAL (case-preserving) line.
		submatches := rule.CompiledRegex.FindAllStringSubmatchIndex(line, -1)
		for _, loc := range submatches {
			// Determine which group holds the secret
			secretGroup := rule.SecretGroup
			if secretGroup == 0 {
				secretGroup = 1 // default to group 1
			}

			// Ensure the submatch group exists
			groupStart := secretGroup * 2
			groupEnd := groupStart + 1
			if groupStart >= len(loc) || loc[groupStart] < 0 {
				// Fall back to full match (group 0) if named group absent
				if len(loc) < 2 || loc[0] < 0 {
					continue
				}
				groupStart = 0
				groupEnd = 1
			}

			rawSecret := line[loc[groupStart]:loc[groupEnd]]
			if rawSecret == "" {
				continue
			}

			// Entropy gate (D-10): skip if entropy below threshold
			if rule.Entropy > 0 && !e.cfg.NoEntropy && shannonEntropy(rawSecret) <= rule.Entropy {
				continue
			}

			// Global then per-rule allowlists.
			if isAllowlisted(rawSecret, filePath, e.cfg.GlobalAllowlists) ||
				isAllowlisted(rawSecret, filePath, rule.Allowlists) {
				continue
			}

			// Call finding.New() — this is the ONLY place rawSecret is used further.
			// finding.New() enforces redact-at-boundary: rawSecret is never stored.
			// Column is 1-indexed; the full match context is group 0.
			f := finding.New(rule.ID, filePath, lineNum, loc[groupStart]+1,
				rawSecret, line[loc[0]:loc[1]], rule.IsHeuristic)
			// Side-channel: carry the raw secret off-struct, keyed by fingerprint,
			// for opt-in live verification. Never stored on f, never serialized.
			raw[f.Fingerprint] = rawSecret
			findings = append(findings, f)
		}
	}

	return findings
}

// isAllowlisted returns true if rawSecret or filePath matches any allowlist entry.
func isAllowlisted(rawSecret, filePath string, allowlists []config.Allowlist) bool {
	for _, al := range allowlists {
		for _, re := range al.CompiledRegexes {
			if re.MatchString(rawSecret) {
				return true
			}
		}
		for _, re := range al.CompiledPaths {
			if re.MatchString(filePath) {
				return true
			}
		}
	}
	return false
}
