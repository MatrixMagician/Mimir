package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	mimirconfig "github.com/MatrixMagician/mimir/internal/config"
	"github.com/MatrixMagician/mimir/internal/detect"
	"github.com/MatrixMagician/mimir/internal/output"
	"github.com/MatrixMagician/mimir/internal/scanner"
)

var scanCmd = &cobra.Command{
	Use:   "scan [paths...]",
	Short: "Scan files or directories for secrets",
	Long:  "Scan recursively walks paths looking for leaked secrets using signature rules and entropy analysis.",
	RunE:  runScan,
}

func init() {
	// D-14 flag surface (subset for Walking Skeleton; remaining flags wired in Plan 03)
	scanCmd.Flags().StringP("format", "f", "human", "Output format: human or json")
	scanCmd.Flags().Bool("exit-zero", false, "Always exit 0 even when findings are present (CI soft mode)")
	scanCmd.Flags().Int("max-file-size", 10, "Skip files larger than this size in MB (0 = no limit)")
	scanCmd.Flags().Bool("no-entropy", false, "Disable Shannon entropy check (more findings, more noise)")
	scanCmd.Flags().BoolP("verbose", "v", false, "Enable verbose diagnostic output to stderr")
	scanCmd.Flags().Bool("quiet", false, "Suppress end-of-scan summary line (findings still printed)")
	scanCmd.Flags().StringP("config", "c", "", "Path to custom config file (default: use embedded config)")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	// 1. Resolve paths: default to current directory (D-13)
	paths := args
	if len(paths) == 0 {
		paths = []string{"."}
	}

	// 2. Load default config (Plan 03 wires full config discovery)
	cfg, err := mimirconfig.LoadDefault()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error loading config:", err)
		os.Exit(2)
	}

	// 3. Apply flags to cfg
	noEntropy, _ := cmd.Flags().GetBool("no-entropy")
	cfg.NoEntropy = noEntropy

	maxSize, _ := cmd.Flags().GetInt("max-file-size")
	cfg.MaxFileSizeMB = maxSize

	verbose, _ := cmd.Flags().GetBool("verbose")
	cfg.Verbose = verbose

	// 4. Build engine
	engine := detect.NewEngine(cfg)

	// 5. Build scanner
	s := scanner.New(engine, cfg)

	// 6. Scan
	findings, stats, err := s.Scan(cmd.Context(), paths)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	// 7. Output
	noColor, _ := cmd.Root().PersistentFlags().GetBool("no-color")
	noColor = noColor || os.Getenv("NO_COLOR") != ""

	quiet, _ := cmd.Flags().GetBool("quiet")

	format, _ := cmd.Flags().GetString("format")
	if format == "json" {
		// JSON output is implemented in Plan 03
		fmt.Fprintln(os.Stderr, "JSON output not yet implemented")
		os.Exit(2)
	}

	output.WriteHuman(os.Stdout, findings, stats, noColor, quiet)

	// 8. Exit code (IFACE-02): 0=clean, 1=findings, 2=error
	exitZero, _ := cmd.Flags().GetBool("exit-zero")
	if len(findings) > 0 && !exitZero {
		os.Exit(1)
	}

	return nil
}
