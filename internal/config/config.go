// Package config defines the configuration types for Mimir and loads the
// embedded default ruleset.
package config

import (
	"fmt"
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
}

// rawConfig mirrors the TOML schema for decoding. After decoding, rules
// and allowlists are validated and moved into Config.
type rawConfig struct {
	Title      string       `toml:"title"`
	Allowlists []Allowlist  `toml:"allowlists"`
	Rules      []Rule       `toml:"rules"`
}

// LoadDefault loads and validates the embedded default configuration.
// It returns an error if any rule regex fails RE2 compilation.
func LoadDefault() (*Config, error) {
	return loadFromBytes(extconfig.DefaultConfig)
}

// loadFromBytes decodes TOML config bytes, compiles all regexes, and
// returns a validated Config.
func loadFromBytes(data []byte) (*Config, error) {
	var raw rawConfig
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing config TOML: %w", err)
	}

	cfg := &Config{
		MaxFileSizeMB: 10,
	}

	// Compile and validate global allowlist regexes
	for i := range raw.Allowlists {
		al := &raw.Allowlists[i]
		for _, pattern := range al.Regexes {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("global allowlist regex %q: %w", pattern, err)
			}
			al.CompiledRegexes = append(al.CompiledRegexes, re)
		}
		for _, pattern := range al.Paths {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("global allowlist path pattern %q: %w", pattern, err)
			}
			al.CompiledPaths = append(al.CompiledPaths, re)
		}
	}
	cfg.GlobalAllowlists = raw.Allowlists

	// Compile and validate rule regexes
	for i := range raw.Rules {
		rule := &raw.Rules[i]
		re, err := regexp.Compile(rule.Regex)
		if err != nil {
			return nil, fmt.Errorf("rule %q: invalid regex %q: %w\n  (RE2 does not support lookaheads or backreferences; use entropy + allowlists instead)", rule.ID, rule.Regex, err)
		}
		rule.CompiledRegex = re

		// Compile per-rule allowlist regexes
		for j := range rule.Allowlists {
			al := &rule.Allowlists[j]
			for _, pattern := range al.Regexes {
				alRe, alErr := regexp.Compile(pattern)
				if alErr != nil {
					return nil, fmt.Errorf("rule %q allowlist regex %q: %w", rule.ID, pattern, alErr)
				}
				al.CompiledRegexes = append(al.CompiledRegexes, alRe)
			}
		}
	}
	cfg.Rules = raw.Rules

	return cfg, nil
}
