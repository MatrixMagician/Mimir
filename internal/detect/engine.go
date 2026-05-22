package detect

import (
	"strings"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"github.com/MatrixMagician/mimir/internal/config"
	"github.com/MatrixMagician/mimir/internal/finding"
)

// Engine holds the compiled Aho-Corasick trie and rule set.
// It is stateless after construction and safe to call from multiple goroutines.
type Engine struct {
	trie             *ahocorasick.Trie
	rules            []config.Rule
	cfg              *config.Config
	globalAllowlists []config.Allowlist
}

// NewEngine builds a detection engine from a validated Config.
// Keywords for all rules are lowercased and added to a single Aho-Corasick trie
// for O(n) per-line keyword pre-filtering.
func NewEngine(cfg *config.Config) *Engine {
	// Collect all keywords from all rules (lowercased)
	var keywords []string
	for _, rule := range cfg.Rules {
		for _, kw := range rule.Keywords {
			keywords = append(keywords, strings.ToLower(kw))
		}
	}

	var trie *ahocorasick.Trie
	if len(keywords) > 0 {
		trie = ahocorasick.NewTrieBuilder().AddStrings(keywords).Build()
	}

	return &Engine{
		trie:             trie,
		rules:            cfg.Rules,
		cfg:              cfg,
		globalAllowlists: cfg.GlobalAllowlists,
	}
}

// ScanLine runs the detection pipeline on a single line of text.
//
// Pipeline: Aho-Corasick keyword gate → RE2 regex → entropy check → allowlist check → finding.New()
//
// The raw secret value is passed only to finding.New() which enforces redact-at-boundary.
// This function never stores or logs the raw secret value.
//
// Parameters:
//   - line: the raw line content (NOT lowercased)
//   - filePath: repo-relative file path for the Finding
//   - lineNum: 1-indexed line number
func (e *Engine) ScanLine(line, filePath string, lineNum int) []finding.Finding {
	// Fast path: if no trie (no rules) or no keyword matches, skip all regex work
	if e.trie == nil {
		return nil
	}
	lineLower := strings.ToLower(line)
	if e.trie.MatchFirstString(lineLower) == nil {
		return nil
	}

	// Find which keywords matched to identify candidate rules
	matches := e.trie.MatchString(lineLower)
	matchedKeywords := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		matchedKeywords[m.MatchString()] = struct{}{}
	}

	var findings []finding.Finding

	for _, rule := range e.rules {
		// Check if any of this rule's keywords matched
		ruleMatched := false
		for _, kw := range rule.Keywords {
			if _, ok := matchedKeywords[strings.ToLower(kw)]; ok {
				ruleMatched = true
				break
			}
		}
		if !ruleMatched {
			continue
		}

		// Run the RE2 regex on the ORIGINAL (case-preserving) line
		if rule.CompiledRegex == nil {
			continue
		}

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
				secretGroup = 0
				groupStart = 0
				groupEnd = 1
			}

			rawSecret := line[loc[groupStart]:loc[groupEnd]]
			if rawSecret == "" {
				continue
			}

			// Entropy gate (D-10): skip if entropy below threshold
			if rule.Entropy > 0 && !e.cfg.NoEntropy {
				if shannonEntropy(rawSecret) <= rule.Entropy {
					continue
				}
			}

			// Check global allowlists
			if e.isAllowlisted(rawSecret, filePath, e.globalAllowlists) {
				continue
			}

			// Check per-rule allowlists
			if e.isAllowlisted(rawSecret, filePath, rule.Allowlists) {
				continue
			}

			// Column is 1-indexed, pointing to start of secret in the line
			col := loc[groupStart] + 1

			// Full match context is group 0
			fullMatch := line[loc[0]:loc[1]]

			// Call finding.New() — this is the ONLY place rawSecret is used further.
			// finding.New() enforces redact-at-boundary: rawSecret is never stored.
			f := finding.New(rule.ID, filePath, lineNum, col, rawSecret, fullMatch, rule.IsHeuristic)
			findings = append(findings, f)
		}
	}

	return findings
}

// isAllowlisted returns true if rawSecret or filePath matches any allowlist entry.
func (e *Engine) isAllowlisted(rawSecret, filePath string, allowlists []config.Allowlist) bool {
	for _, al := range allowlists {
		// Check value-based allowlist regexes
		for _, re := range al.CompiledRegexes {
			if re.MatchString(rawSecret) {
				return true
			}
		}
		// Check path-based allowlist patterns
		for _, re := range al.CompiledPaths {
			if re.MatchString(filePath) {
				return true
			}
		}
	}
	return false
}
