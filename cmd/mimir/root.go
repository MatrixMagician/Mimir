// Package cmd implements the Mimir CLI using cobra.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// rootCmd is the base command for the mimir CLI.
var rootCmd = &cobra.Command{
	Use:           "mimir",
	Short:         "mimir — fast secret scanner for repositories",
	Long:          "mimir scans files and git history for leaked secrets, API keys, and credentials.",
	SilenceErrors: true, // Prevent cobra from printing errors twice
	SilenceUsage:  true, // Don't print usage on RunE errors
}

func init() {
	// Persistent flag: --no-color. The NO_COLOR env var is honored in two other
	// places already — fatih/color checks it at init, and runScan ORs it into the
	// flag value — so there is nothing to do here beyond declaring the flag.
	rootCmd.PersistentFlags().Bool("no-color", false, "Disable ANSI color output")
}

// Execute runs the root command and handles top-level errors.
// On error it prints to stderr and exits with code 2.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}
