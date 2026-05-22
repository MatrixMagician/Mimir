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
	// D-14 full flag surface for mimir scan
	scanCmd.Flags().StringP("format", "f", "human", "Output format: human or json")
	scanCmd.Flags().Bool("exit-zero", false, "Always exit 0 even when findings are present (CI soft mode)")
	scanCmd.Flags().Int("max-file-size", 10, "Skip files larger than this size in MB (0 = no limit)")
	scanCmd.Flags().Bool("no-entropy", false, "Disable Shannon entropy check (more findings, more noise)")
	scanCmd.Flags().BoolP("verbose", "v", false, "Enable verbose diagnostic output to stderr")
	scanCmd.Flags().Bool("quiet", false, "Suppress end-of-scan summary line (findings still printed)")
	scanCmd.Flags().StringP("config", "c", "", "Path to custom config file (default: auto-discover .mimir.toml or use embedded config)")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	// 1. Resolve paths: default to current directory (D-13)
	paths := args
	if len(paths) == 0 {
		paths = []string{"."}
	}

	// 2. Load config with full precedence: --config > .mimir.toml in scan root > embedded defaults (CFG-02)
	flagConfig, _ := cmd.Flags().GetString("config")
	scanRoot := resolveScanRoot(paths)
	cfg, err := mimirconfig.LoadConfig(flagConfig, scanRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	// 3. Apply CLI flags to cfg (these override config-file values for runtime behavior)
	noEntropy, _ := cmd.Flags().GetBool("no-entropy")
	cfg.NoEntropy = noEntropy

	maxSize, _ := cmd.Flags().GetInt("max-file-size")
	cfg.MaxFileSizeMB = maxSize

	verbose, _ := cmd.Flags().GetBool("verbose")
	cfg.Verbose = verbose

	// 4. Build engine and scanner
	engine := detect.NewEngine(cfg)
	s := scanner.New(engine, cfg)

	// 5. Scan
	findings, stats, err := s.Scan(cmd.Context(), paths)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	// 6. Output: determine format and color settings
	format, _ := cmd.Flags().GetString("format")
	noColor, _ := cmd.Root().PersistentFlags().GetBool("no-color")
	// Also honor NO_COLOR env var (D-14; fatih/color checks it at init, but explicit override for clarity)
	noColor = noColor || os.Getenv("NO_COLOR") != ""
	quiet, _ := cmd.Flags().GetBool("quiet")

	if format == "json" {
		// JSON output to stdout (D-03); findings already have redacted Secret fields (OUT-03)
		if err := output.WriteJSON(os.Stdout, findings, stats); err != nil {
			fmt.Fprintln(os.Stderr, "error encoding JSON:", err)
			os.Exit(2)
		}
	} else {
		// Human-readable output (default) (D-12)
		output.WriteHuman(os.Stdout, findings, stats, noColor, quiet)
	}

	// 7. Exit code contract (IFACE-02): 0=clean, 1=findings (unless --exit-zero), 2=error
	exitZero, _ := cmd.Flags().GetBool("exit-zero")
	if len(findings) > 0 && !exitZero {
		os.Exit(1)
	}

	return nil
}

// resolveScanRoot returns the first directory from paths, or "." if paths is
// empty or the first path is not a directory. Used for config discovery (CFG-02).
func resolveScanRoot(paths []string) string {
	if len(paths) == 0 {
		return "."
	}
	info, err := os.Stat(paths[0])
	if err != nil {
		return "."
	}
	if info.IsDir() {
		return paths[0]
	}
	// First path is a file; use its directory
	dir := paths[0]
	for i := len(dir) - 1; i >= 0; i-- {
		if dir[i] == '/' || dir[i] == '\\' {
			return dir[:i]
		}
	}
	return "."
}
