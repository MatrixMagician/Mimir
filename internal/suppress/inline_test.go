package suppress

import "testing"

func TestInlineSuppresses(t *testing.T) {
	cases := []struct {
		name string
		line string
		rule string
		want bool
	}{
		{"blanket suppresses any rule", `key = "AKIAFAKEKEYABCDE2345" // mimir:ignore`, "aws-access-token", true},
		{"scoped suppresses named rule", `x // mimir:ignore:aws-access-token`, "aws-access-token", true},
		{"scoped does not suppress other rule", `x // mimir:ignore:aws-access-token`, "github-pat", false},
		{"scoped comma list", `x // mimir:ignore:foo,github-pat,bar`, "github-pat", true},
		{"no directive present", `just a normal line with a secret`, "aws-access-token", false},
		{"case-insensitive blanket", `x // MIMIR:IGNORE`, "any-rule", true},
		{"mixed-case scoped keeps rule case", `x // Mimir:Ignore:aws-access-token`, "aws-access-token", true},
		{"longer word does not trigger", `x // mimir:ignored for now`, "aws-access-token", false},
		{"hash comment style works", `secret # mimir:ignore`, "any-rule", true},
		{"semicolon comment style works", `secret ; mimir:ignore:github-pat`, "github-pat", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := InlineSuppresses(tc.line, tc.rule); got != tc.want {
				t.Errorf("InlineSuppresses(%q, %q) = %v, want %v", tc.line, tc.rule, got, tc.want)
			}
		})
	}
}
