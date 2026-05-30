// Package config defines the configuration types for Mimir and loads the
// embedded default ruleset.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	extconfig "github.com/MatrixMagician/mimir/config"
	toml "github.com/pelletier/go-toml/v2"
)

// Rule defines a single secret-detection rule with its compiled regex.
type Rule struct {
	ID             string      `toml:"id"`
	Description    string      `toml:"description"`
	Regex          string      `toml:"regex"`
	CompiledRegex  *regexp.Regexp
	Entropy        float64     `toml:"entropy"`
	Keywords       []string    `toml:"keywords"`
	SecretGroup    int         `toml:"secret_group"`
	IsHeuristic    bool        `toml:"is_heuristic"`
	Allowlists     []Allowlist `toml:"allowlists"`
}

// Allowlist holds regex patterns and/or path patterns used to suppress findings.
type Allowlist struct {
	Description     string         `toml:"description"`
	Regexes         []string       `toml:"regexes"`
	CompiledRegexes []*regexp.Regexp
	Paths           []string       `toml:"paths"`
	CompiledPaths   []*regexp.Regexp
}

// Config holds the loaded and validated scanner configuration.
type Config struct {
	Rules            []Rule
	GlobalAllowlists []Allowlist
	MaxFileSizeMB    int
	NoEntropy        bool
	Verbose          bool

	// UseDefaultExcludes is the normalized master toggle for the shipped
	// default path-prune globs (SUP-04, D-07). It defaults to true; it is set
	// false only when the user config sets `[extend] use_default_allowlists = false`.
	UseDefaultExcludes bool
}

// rawConfig mirrors the TOML schema for decoding. After decoding, rules
// and allowlists are validated and moved into Config.
type rawConfig struct {
	Title      string        `toml:"title"`
	Extend     extendSection `toml:"extend"`
	Allowlists []rawAllowlist `toml:"allowlists"`
	Rules      []rawRule     `toml:"rules"`
}

// extendSection represents the [extend] block in a user config.
type extendSection struct {
	UseDefault    bool     `toml:"use_default"`
	DisabledRules []string `toml:"disabled_rules"`
	Path          string   `toml:"path"` // reserved for Phase 2; not implemented in Phase 1
	// UseDefaultAllowlists is the master toggle for the shipped default
	// path-prune globs (SUP-04, D-07). A pointer so absence (nil) means
	// default-ON; only an explicit `use_default_allowlists = false` disables them.
	UseDefaultAllowlists *bool `toml:"use_default_allowlists"`
}

// rawRule is the TOML decode target for a single rule (before regex compilation).
type rawRule struct {
	ID          string         `toml:"id"`
	Description string         `toml:"description"`
	Regex       string         `toml:"regex"`
	Entropy     float64        `toml:"entropy"`
	Keywords    []string       `toml:"keywords"`
	SecretGroup int            `toml:"secret_group"`
	IsHeuristic bool           `toml:"is_heuristic"`
	Allowlists  []rawAllowlist `toml:"allowlists"`
}

// rawAllowlist is the TOML decode target for an allowlist block (before regex compilation).
type rawAllowlist struct {
	Description string   `toml:"description"`
	Regexes     []string `toml:"regexes"`
	Paths       []string `toml:"paths"`
}

// LoadDefault loads and validates the embedded default configuration.
// It returns an error if any rule regex fails RE2 compilation.
func LoadDefault() (*Config, error) {
	raw, err := parseBytes(extconfig.DefaultConfig)
	if err != nil {
		return nil, err
	}
	return compile(raw)
}

// LoadConfig implements three-level config precedence (CFG-02):
//   1. --config flag (explicit path) — missing → error
//   2. .mimir.toml in scanRoot directory — missing → fall through
//   3. Embedded defaults
//
// When use_default=true is set in the user config, the embedded defaults are
// merged with the user config rules (extend model, CFG-01/D-09).
func LoadConfig(flagPath string, scanRoot string) (*Config, error) {
	if flagPath != "" {
		data, err := os.ReadFile(flagPath)
		if err != nil {
			return nil, fmt.Errorf("config file %q: %w", flagPath, err)
		}
		return loadFromFileBytes(data)
	}

	// Check for project config in scan root
	if scanRoot != "" {
		projectConfig := filepath.Join(scanRoot, ".mimir.toml")
		if _, err := os.Stat(projectConfig); err == nil {
			data, err := os.ReadFile(projectConfig)
			if err != nil {
				return nil, fmt.Errorf("project config file %q: %w", projectConfig, err)
			}
			return loadFromFileBytes(data)
		}
	}

	// Fall through: embedded defaults only
	return LoadDefault()
}

// loadFromFileBytes handles loading a user-provided config file, implementing
// the extend model (use_default + disabled_rules).
func loadFromFileBytes(data []byte) (*Config, error) {
	raw, err := parseBytes(data)
	if err != nil {
		return nil, err
	}

	if raw.Extend.UseDefault {
		defaultRaw, err := parseBytes(extconfig.DefaultConfig)
		if err != nil {
			return nil, fmt.Errorf("loading embedded defaults for extend: %w", err)
		}
		merged := mergeConfigs(defaultRaw, raw)
		return compile(merged)
	}

	return compile(raw)
}

// parseBytes decodes TOML config bytes into a rawConfig struct.
// Returns a descriptive error on parse failure.
func parseBytes(data []byte) (*rawConfig, error) {
	var raw rawConfig
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("config parse error: %w", err)
	}
	return &raw, nil
}

// mergeConfigs merges an overlay config on top of a base config.
// The overlay's rules are appended after the base rules.
// disabled_rules from the overlay are removed from the merged result.
// The overlay's global allowlists are merged with the base.
func mergeConfigs(base, overlay *rawConfig) *rawConfig {
	merged := &rawConfig{
		Title: base.Title,
		// Carry the overlay's [extend] block so the user's master toggle
		// (use_default_allowlists) survives the extend merge (D-07).
		Extend: overlay.Extend,
	}

	// Start with base rules, append overlay rules
	merged.Rules = make([]rawRule, 0, len(base.Rules)+len(overlay.Rules))
	merged.Rules = append(merged.Rules, base.Rules...)
	merged.Rules = append(merged.Rules, overlay.Rules...)

	// Apply disabled_rules filter
	if len(overlay.Extend.DisabledRules) > 0 {
		disabled := make(map[string]bool, len(overlay.Extend.DisabledRules))
		for _, id := range overlay.Extend.DisabledRules {
			disabled[id] = true
		}
		filtered := merged.Rules[:0]
		for _, r := range merged.Rules {
			if !disabled[r.ID] {
				filtered = append(filtered, r)
			}
		}
		merged.Rules = filtered
	}

	// Merge global allowlists
	merged.Allowlists = make([]rawAllowlist, 0, len(base.Allowlists)+len(overlay.Allowlists))
	merged.Allowlists = append(merged.Allowlists, base.Allowlists...)
	merged.Allowlists = append(merged.Allowlists, overlay.Allowlists...)

	return merged
}

// compile validates and compiles all regexes in a rawConfig, producing a Config.
// Returns an error naming the offending rule if any regex fails RE2 compilation (DET-05).
func compile(raw *rawConfig) (*Config, error) {
	cfg := &Config{
		MaxFileSizeMB: 10,
		// Default-ON unless the user explicitly set use_default_allowlists = false (D-07).
		UseDefaultExcludes: raw.Extend.UseDefaultAllowlists == nil || *raw.Extend.UseDefaultAllowlists,
	}

	// Compile and validate global allowlist regexes
	compiledAllowlists := make([]Allowlist, 0, len(raw.Allowlists))
	for _, al := range raw.Allowlists {
		compiled := Allowlist{
			Description: al.Description,
			Regexes:     al.Regexes,
			Paths:       al.Paths,
		}
		for _, pattern := range al.Regexes {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("global allowlist regex %q: %w", pattern, err)
			}
			compiled.CompiledRegexes = append(compiled.CompiledRegexes, re)
		}
		for _, pattern := range al.Paths {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("global allowlist path pattern %q: %w", pattern, err)
			}
			compiled.CompiledPaths = append(compiled.CompiledPaths, re)
		}
		compiledAllowlists = append(compiledAllowlists, compiled)
	}
	cfg.GlobalAllowlists = compiledAllowlists

	// Compile and validate rule regexes
	compiledRules := make([]Rule, 0, len(raw.Rules))
	for _, rr := range raw.Rules {
		re, err := regexp.Compile(rr.Regex)
		if err != nil {
			return nil, fmt.Errorf("rule %q: invalid regex %q: %w\n  (RE2 does not support lookaheads or backreferences; use entropy + allowlists instead)", rr.ID, rr.Regex, err)
		}

		rule := Rule{
			ID:            rr.ID,
			Description:   rr.Description,
			Regex:         rr.Regex,
			CompiledRegex: re,
			Entropy:       rr.Entropy,
			Keywords:      rr.Keywords,
			SecretGroup:   rr.SecretGroup,
			IsHeuristic:   rr.IsHeuristic,
		}

		// Compile per-rule allowlist regexes
		for _, al := range rr.Allowlists {
			compiledAl := Allowlist{
				Description: al.Description,
				Regexes:     al.Regexes,
				Paths:       al.Paths,
			}
			for _, pattern := range al.Regexes {
				alRe, alErr := regexp.Compile(pattern)
				if alErr != nil {
					return nil, fmt.Errorf("rule %q allowlist regex %q: %w", rr.ID, pattern, alErr)
				}
				compiledAl.CompiledRegexes = append(compiledAl.CompiledRegexes, alRe)
			}
			rule.Allowlists = append(rule.Allowlists, compiledAl)
		}

		compiledRules = append(compiledRules, rule)
	}
	cfg.Rules = compiledRules

	return cfg, nil
}

// loadFromBytes decodes TOML config bytes, compiles all regexes, and
// returns a validated Config. Used by LoadDefault and tests.
func loadFromBytes(data []byte) (*Config, error) {
	raw, err := parseBytes(data)
	if err != nil {
		return nil, err
	}
	return compile(raw)
}
