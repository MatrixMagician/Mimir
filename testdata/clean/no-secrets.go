// Package clean contains source files with no secrets for false-positive regression.
// The scanner must report 0 findings when scanning this file.
package clean

import "time"

// Config holds application configuration without any hardcoded credentials.
// All sensitive values must come from environment variables or config files.
type Config struct {
	Host     string
	Port     int
	Timeout  time.Duration
	LogLevel string
}

// DefaultConfig returns a Config populated with safe, non-secret defaults.
func DefaultConfig() Config {
	return Config{
		Host:     "localhost",
		Port:     8080,
		Timeout:  30 * time.Second,
		LogLevel: "info",
	}
}

// Validate checks that required Config fields are set.
// Returns an error description if validation fails.
func Validate(cfg Config) string {
	if cfg.Host == "" {
		return "host is required"
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return "port must be between 1 and 65535"
	}
	return ""
}
