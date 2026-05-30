// Package config provides the embedded default Mimir ruleset.
// This file must live in the config/ directory alongside mimir.toml —
// go:embed can only reference files in the same or sub-directories.
package config

import _ "embed"

// DefaultConfig is the embedded default ruleset TOML.
// It is loaded by internal/config.LoadDefault() and used when no
// user config file is found at the scan root.
//
//go:embed mimir.toml
var DefaultConfig []byte
