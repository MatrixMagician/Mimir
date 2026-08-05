package config

import (
	"strings"
	"testing"

	extconfig "github.com/MatrixMagician/mimir/config"
)

// FuzzLoadFromBytes drives the TOML config loader with arbitrary bytes. A
// .mimir.toml is read from the scanned repository, so it is untrusted input on
// any `git clone && mimir scan`. The loader must reject bad input with an error
// rather than panicking or — worse — succeeding with a half-built ruleset that
// silently scans for nothing.
func FuzzLoadFromBytes(f *testing.F) {
	seeds := []string{
		"",
		"title = 'x'",
		"[[rules]]\nid = 'a'\nregex = 'x'\nkeywords = ['x']\n",
		"[[rules]]\nid = 'a'\nregex = '('\nkeywords = ['x']\n",     // invalid regex
		"[[rules]]\nid = 'a'\nregex = '(?=x)'\nkeywords = ['x']\n", // RE2-unsupported
		"[extend]\nuse_default = true\n",
		"[extend]\nuse_default = true\ndisabled_rules = ['jwt']\n",
		"[extend]\nuse_default_allowlists = false\n",
		"[[allowlists]]\nregexes = ['[']\n", // invalid allowlist regex
		"[[allowlists]]\npaths = ['(']\n",
		"[[rules]]\nid = 'a'\nregex = 'x'\nentropy = 1e400\n", // float overflow
		"[[rules]]\nid = 'a'\nsecret_group = -1\nregex = '(x)'\nkeywords = ['x']\n",
		"[[rules]]\nid = 'a'\nsecret_group = 99\nregex = '(x)'\nkeywords = ['x']\n",
		strings.Repeat("[[rules]]\nid = 'a'\nregex = 'x'\n", 100),
		"\x00\xff\xfe",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, err := loadFromBytes(data)

		// Exactly one of (cfg, err) must be meaningful — never both nil, never
		// both set. A nil-nil return would hand the engine a nil config.
		if err != nil {
			if cfg != nil {
				t.Fatalf("returned both a config and an error")
			}
			return
		}
		if cfg == nil {
			t.Fatal("returned a nil config and a nil error")
		}

		// A successfully compiled config must be usable: every rule carries a
		// non-nil compiled regex, since the engine dereferences it per line.
		for _, r := range cfg.Rules {
			if r.CompiledRegex == nil {
				t.Fatalf("rule %q compiled successfully but has a nil regex", r.ID)
			}
		}
		for _, al := range cfg.GlobalAllowlists {
			for _, re := range al.CompiledRegexes {
				if re == nil {
					t.Fatal("global allowlist has a nil compiled regex")
				}
			}
			for _, re := range al.CompiledPaths {
				if re == nil {
					t.Fatal("global allowlist has a nil compiled path regex")
				}
			}
		}
	})
}

// FuzzMergeConfigs drives the extend-model merge with arbitrary overlay configs
// on top of the real shipped defaults. The merge decides which rules survive, so
// a bug here silently changes what gets scanned — as one did: overlay rules were
// appended rather than replacing same-ID defaults, double-reporting every match.
func FuzzMergeConfigs(f *testing.F) {
	seeds := []string{
		"[extend]\nuse_default = true\n",
		"[extend]\nuse_default = true\ndisabled_rules = ['aws-access-token']\n",
		"[[rules]]\nid = 'aws-access-token'\nregex = 'x'\nkeywords = ['x']\n",
		"[[rules]]\nid = 'new-rule'\nregex = 'x'\nkeywords = ['x']\n",
		"[[rules]]\nid = ''\nregex = 'x'\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	base, err := parseBytes(extconfig.DefaultConfig)
	if err != nil {
		f.Fatalf("parsing shipped defaults: %v", err)
	}

	f.Fuzz(func(t *testing.T, overlayData []byte) {
		overlay, err := parseBytes(overlayData)
		if err != nil {
			return // malformed TOML is the loader's problem, not the merge's
		}

		merged := mergeConfigs(base, overlay)
		if merged == nil {
			t.Fatal("mergeConfigs returned nil")
		}

		// Rule IDs must be unique after a merge. Duplicates mean a finding is
		// reported once per copy of the rule.
		seen := map[string]bool{}
		for _, r := range merged.Rules {
			if seen[r.ID] {
				t.Fatalf("duplicate rule ID %q after merge", r.ID)
			}
			seen[r.ID] = true
		}

		// A disabled rule must not survive under any overlay.
		for _, id := range overlay.Extend.DisabledRules {
			if seen[id] {
				t.Fatalf("rule %q survived despite being in disabled_rules", id)
			}
		}

		// Every overlay rule that was not disabled must be present: an override
		// that silently vanishes would leave the user scanning with the default
		// they meant to replace.
		disabled := map[string]bool{}
		for _, id := range overlay.Extend.DisabledRules {
			disabled[id] = true
		}
		for _, r := range overlay.Rules {
			if !disabled[r.ID] && !seen[r.ID] {
				t.Fatalf("overlay rule %q disappeared in the merge", r.ID)
			}
		}
	})
}
