package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRulesetParse verifies the embedded default ruleset loads correctly
// with all v1 rules present, RE2-validated, and with required metadata.
func TestRulesetParse(t *testing.T) {
	cfg, err := LoadDefault()
	require.NoError(t, err, "LoadDefault() must return nil error")
	require.NotNil(t, cfg, "LoadDefault() must return non-nil Config")

	// Must have at least 15 rules (v1 set: ~15-25 rules per D-07)
	assert.GreaterOrEqual(t, len(cfg.Rules), 15,
		"expected >= 15 rules in the default config (got %d)", len(cfg.Rules))

	// Every rule must have a non-nil CompiledRegex (RE2 validation at load time)
	for _, rule := range cfg.Rules {
		assert.NotNil(t, rule.CompiledRegex,
			"rule %q must have a compiled (non-nil) regex", rule.ID)
		assert.NotEmpty(t, rule.ID,
			"every rule must have a non-empty ID")
		assert.NotEmpty(t, rule.Keywords,
			"rule %q must have at least one keyword", rule.ID)
	}

	// generic-api-key rule must have IsHeuristic=true (D-11)
	var foundGeneric bool
	for _, rule := range cfg.Rules {
		if rule.ID == "generic-api-key" {
			foundGeneric = true
			assert.True(t, rule.IsHeuristic,
				"generic-api-key rule must have IsHeuristic=true")
		}
	}
	assert.True(t, foundGeneric, "expected a rule with ID 'generic-api-key'")

	// connection-string rule must have SecretGroup=3 (D-08)
	var foundConnStr bool
	for _, rule := range cfg.Rules {
		if rule.ID == "connection-string" {
			foundConnStr = true
			assert.Equal(t, 3, rule.SecretGroup,
				"connection-string rule must have SecretGroup=3")
		}
	}
	assert.True(t, foundConnStr, "expected a rule with ID 'connection-string'")

	// All keywords must be lowercase (Aho-Corasick trie requirement, Pitfall 3)
	for _, rule := range cfg.Rules {
		for _, kw := range rule.Keywords {
			assert.Equal(t, kw, lower(kw),
				"rule %q keyword %q must be lowercase", rule.ID, kw)
		}
	}
}

// lower is a helper to check case without importing strings in this test file
// (avoids import for a single helper).
func lower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		result[i] = c
	}
	return string(result)
}

// TestInvalidRegexRejected verifies that a rule with an invalid RE2 pattern
// (e.g. a PCRE lookahead) causes LoadDefault to return an error.
func TestInvalidRegexRejected(t *testing.T) {
	// Construct a minimal TOML config with an invalid regex (lookahead).
	invalidTOML := []byte(`
title = "test"
[[rules]]
id = "bad-rule"
description = "rule with invalid RE2"
regex = '(?=invalid)'
keywords = ["test"]
`)
	_, err := loadFromBytes(invalidTOML)
	require.Error(t, err, "loadFromBytes must return error for invalid RE2 regex")
	assert.Contains(t, err.Error(), "bad-rule", "error message must name the offending rule")
}
