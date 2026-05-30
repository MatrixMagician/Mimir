package config

import (
	"os"
	"path/filepath"
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

// ---- Plan 01-03 tests below ----

// TestLoadConfigFallback verifies LoadConfig("", nonexistent) falls back to
// embedded defaults and returns a valid config with >= 15 rules.
func TestLoadConfigFallback(t *testing.T) {
	cfg, err := LoadConfig("", "/nonexistent/scan/root/path/xyz")
	require.NoError(t, err, "LoadConfig with nonexistent scanRoot must fall back to embedded defaults")
	require.NotNil(t, cfg)
	assert.GreaterOrEqual(t, len(cfg.Rules), 15,
		"fallback config must have >= 15 rules (got %d)", len(cfg.Rules))
	// All compiled
	for _, r := range cfg.Rules {
		assert.NotNil(t, r.CompiledRegex, "rule %q must have compiled regex", r.ID)
	}
}

// TestLoadConfigExplicitMissing verifies LoadConfig returns error when --config
// points to a non-existent file (explicit path, not fallback).
func TestLoadConfigExplicitMissing(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config/path.toml", "")
	require.Error(t, err, "LoadConfig with missing explicit path must return error")
}

// TestLoadConfigExtend verifies that a user config with use_default=true merges
// custom rules alongside all default rules (CFG-01 extend model).
func TestLoadConfigExtend(t *testing.T) {
	// Resolve testdata path from this package
	// config_test.go lives in internal/config/; fixtures at testdata/fixtures/
	root := filepath.Join("..", "..", "testdata", "fixtures")
	userExtendPath := filepath.Join(root, "user-extend.toml")

	cfg, err := LoadConfig(userExtendPath, "")
	require.NoError(t, err, "LoadConfig with user-extend.toml must not error")
	require.NotNil(t, cfg)

	// My custom rule must be present
	var foundCustom bool
	for _, r := range cfg.Rules {
		if r.ID == "my-custom-rule" {
			foundCustom = true
		}
	}
	assert.True(t, foundCustom, "my-custom-rule must be present in merged config")

	// Default rules must also be present (extend.use_default=true)
	var foundAWS bool
	for _, r := range cfg.Rules {
		if r.ID == "aws-access-token" {
			foundAWS = true
		}
	}
	assert.True(t, foundAWS, "aws-access-token (default rule) must be present after extend")

	// Total rules: defaults + 1 custom
	assert.GreaterOrEqual(t, len(cfg.Rules), 16,
		"merged config must have >= 16 rules (defaults + custom), got %d", len(cfg.Rules))
}

// TestLoadConfigREValidation verifies that a config file with an RE2-incompatible
// regex causes LoadConfig to return an error naming the offending rule (DET-05).
func TestLoadConfigREValidation(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "fixtures")
	badRegexPath := filepath.Join(root, "bad-regex.toml")

	_, err := LoadConfig(badRegexPath, "")
	require.Error(t, err, "LoadConfig with bad-regex.toml must return error")
	assert.Contains(t, err.Error(), "lookahead-rule",
		"error message must name the offending rule ID")
	// Must explain RE2 constraint
	assert.True(t,
		containsAny(err.Error(), "RE2", "lookahead"),
		"error message must contain 'RE2' or 'lookahead' to explain the problem; got: %s", err.Error())
}

// TestLoadConfigDisabledRules verifies that disabled_rules in user config removes
// the matching rule from the final Config.Rules.
func TestLoadConfigDisabledRules(t *testing.T) {
	disabledTOML := []byte(`
[extend]
use_default = true
disabled_rules = ["jwt"]
`)
	// Write to a temp file so LoadConfig can read it
	tmp, err := os.CreateTemp("", "mimir-test-*.toml")
	require.NoError(t, err)
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(disabledTOML)
	require.NoError(t, err)
	tmp.Close()

	cfg, err := LoadConfig(tmp.Name(), "")
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// jwt rule must NOT be present
	for _, r := range cfg.Rules {
		assert.NotEqual(t, "jwt", r.ID,
			"jwt rule must be absent when disabled_rules = [\"jwt\"]")
	}

	// Other default rules must still be present
	var foundAWS bool
	for _, r := range cfg.Rules {
		if r.ID == "aws-access-token" {
			foundAWS = true
		}
	}
	assert.True(t, foundAWS, "aws-access-token must still be present when only jwt is disabled")
}

// TestLoadConfigDiscovery verifies config discovery: project .mimir.toml in scan
// root is used when present; falls back to embedded defaults when absent (CFG-02).
func TestLoadConfigDiscovery(t *testing.T) {
	// Case 1: tmpdir with a .mimir.toml → LoadConfig("", tmpdir) uses project file
	dir := t.TempDir()
	projectTOML := []byte(`
[extend]
use_default = true
disabled_rules = ["jwt"]
`)
	err := os.WriteFile(filepath.Join(dir, ".mimir.toml"), projectTOML, 0600)
	require.NoError(t, err)

	cfg, err := LoadConfig("", dir)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	// jwt must be disabled (project config applied)
	for _, r := range cfg.Rules {
		assert.NotEqual(t, "jwt", r.ID,
			"project .mimir.toml must be used: jwt should be disabled")
	}

	// Case 2: tmpdir without .mimir.toml → uses embedded defaults
	dir2 := t.TempDir()
	cfg2, err := LoadConfig("", dir2)
	require.NoError(t, err)
	require.NotNil(t, cfg2)
	// jwt must be present (embedded defaults have jwt)
	var foundJWT bool
	for _, r := range cfg2.Rules {
		if r.ID == "jwt" {
			foundJWT = true
		}
	}
	assert.True(t, foundJWT, "embedded defaults must include jwt rule when no project config")
}

// TestConfigStructPreservation verifies Config still has NoEntropy and Verbose fields.
func TestConfigStructPreservation(t *testing.T) {
	cfg, err := LoadDefault()
	require.NoError(t, err)
	// These fields must exist (compile-time check, but let's also verify zero values)
	assert.False(t, cfg.NoEntropy, "NoEntropy must default to false")
	assert.False(t, cfg.Verbose, "Verbose must default to false")
}

// containsAny returns true if s contains any of the given substrings.
func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if contains(s, sub) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && indexStr(s, sub) >= 0)
}

func indexStr(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
