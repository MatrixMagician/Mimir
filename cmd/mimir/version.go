package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version is set via -ldflags at build time:
//
//	go build -ldflags "-X github.com/MatrixMagician/mimir/cmd/mimir.version=1.0.0" ./cmd/mimir
var version = "dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the mimir version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
