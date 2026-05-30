package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	mimirconfig "github.com/MatrixMagician/mimir/internal/config"
	"github.com/MatrixMagician/mimir/internal/detect"
	"github.com/MatrixMagician/mimir/internal/finding"
	"github.com/MatrixMagician/mimir/internal/gitscan"
	"github.com/MatrixMagician/mimir/internal/output"
	"github.com/MatrixMagician/mimir/internal/scanner"
	"github.com/MatrixMagician/mimir/internal/suppress"
	"github.com/MatrixMagician/mimir/internal/verify"
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
	scanCmd.Flags().Bool("show-suppressed", false, "Include suppressed findings (inline-ignore, allowlist, baseline) in output, annotated and informational only")
	scanCmd.Flags().Bool("no-default-excludes", false, "Disable the shipped default path excludes (vendor/, node_modules/, *.min.js, lockfiles)")
	scanCmd.Flags().Bool("git", false, "Scan current-branch git history for secrets (added-then-deleted included)")
	scanCmd.Flags().Bool("staged", false, "Scan the staged diff (git diff --staged) — used by the pre-commit hook")
	scanCmd.Flags().Bool("verify", false, "Live-verify AWS/GitHub findings (off by default; makes network calls; never used by the pre-commit hook)")
	scanCmd.Flags().String("baseline", "", "Suppress findings present in this baseline JSON file; alert only on NEW findings (e.g. .mimir-baseline.json)")
	scanCmd.Flags().String("baseline-out", "", "Write the current reportable findings as a baseline JSON snapshot (e.g. .mimir-baseline.json)")
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
	showSuppressed, _ := cmd.Flags().GetBool("show-suppressed")
	engine := detect.NewEngine(cfg)
	s := scanner.New(engine, cfg)
	// --show-suppressed drives the scanner's inline-ignore annotate-vs-drop
	// branch (D-12): keep+annotate suppressed findings instead of dropping them.
	s.ShowSuppressed = showSuppressed

	// Path-exclusion (SUP-02/SUP-04): combine the shipped default globs (unless
	// disabled by config or --no-default-excludes) with the .mimirignore at the
	// scan root, and prune matching paths during the walk (D-05).
	noDefaultExcludes, _ := cmd.Flags().GetBool("no-default-excludes")
	useDefaults := cfg.UseDefaultExcludes && !noDefaultExcludes
	ignoreGlobs, err := suppress.LoadMimirIgnore(scanRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error reading .mimirignore:", err)
		os.Exit(2)
	}
	matcher, err := suppress.NewPathMatcher(ignoreGlobs, useDefaults)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err) // malformed .mimirignore glob — fail loud (Security V14)
		os.Exit(2)
	}
	s.Matcher = matcher

	// 5. Scan — the mode flag selects the Source; everything downstream
	// (baseline, output, exit code) is shared and unchanged across modes (D-01).
	// --git streams current-branch history; --staged streams the staged diff (the
	// pre-commit hook's source); the default keeps the Phase 1 working-tree walk.
	gitMode, _ := cmd.Flags().GetBool("git")
	stagedMode, _ := cmd.Flags().GetBool("staged")
	// --git and --staged are mutually exclusive (Pitfall 6 / RESEARCH A2): they
	// select different sources, so passing both is misuse → exit 2 (matching the
	// other fail-loud os.Exit(2) calls in this function).
	if gitMode && stagedMode {
		fmt.Fprintln(os.Stderr, "error: --git and --staged are mutually exclusive")
		os.Exit(2)
	}
	var findings []finding.Finding
	var raw map[string]string // fingerprint→raw-secret side channel (Plan 01), consumed by --verify below
	var stats scanner.Stats
	switch {
	case gitMode:
		findings, raw, stats, err = gitscan.ScanHistory(cmd.Context(), engine, scanRoot, showSuppressed)
	case stagedMode:
		findings, raw, stats, err = gitscan.ScanStaged(cmd.Context(), engine, scanRoot, showSuppressed)
	default:
		findings, raw, stats, err = s.Scan(cmd.Context(), paths)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	// 5b. Baseline (SUP-03): a decoupled post-g.Wait() stage (the pipeline
	// position suppress/doc.go reserves for Phase 4). --baseline marks findings
	// present in the snapshot as suppressed; --baseline-out snapshots the
	// reportable set.
	if baselinePath, _ := cmd.Flags().GetString("baseline"); baselinePath != "" {
		bl, blErr := suppress.LoadBaseline(baselinePath)
		if blErr != nil {
			fmt.Fprintln(os.Stderr, "error:", blErr) // missing/malformed baseline — fail loud
			os.Exit(2)
		}
		if stats.Suppressed == nil {
			stats.Suppressed = map[string]int{}
		}
		for i := range findings {
			if findings[i].Suppressed {
				continue // earlier layer (inline-ignore) already owns the reason
			}
			if bl.IsBaselined(findings[i]) {
				findings[i].Suppressed = true
				findings[i].SuppressionReason = suppress.BaselineReason
				stats.Suppressed[suppress.BaselineReason]++
			}
		}
	}

	// newFindings is the reportable set: everything not suppressed by any layer.
	// It drives the exit code (Pitfall 5 / IFACE-02) and the --baseline-out snapshot.
	var newFindings []finding.Finding
	for _, f := range findings {
		if !f.Suppressed {
			newFindings = append(newFindings, f)
		}
	}

	// 5c. Opt-in live verification (VERIFY-01): strictly label-only and OFF by
	// default. Without --verify, verify.Run is never called → zero network
	// (T-04-default) and the JSON stays byte-identical to OUT-02 (T-04-schema).
	// It runs ONLY on the post-suppression reportable set (newFindings, never the
	// full set — RESEARCH Anti-Pattern), consuming the Plan 01 raw side channel,
	// and writes Verification in place. It NEVER touches the exit-code contract
	// below (T-04-exit). The pre-commit hook never passes --verify (T-04-hook,
	// guarded by TestHookOffline).
	doVerify, _ := cmd.Flags().GetBool("verify")
	if doVerify {
		verify.Run(cmd.Context(), newFindings, raw)
	}

	if baselineOut, _ := cmd.Flags().GetString("baseline-out"); baselineOut != "" {
		if werr := suppress.WriteBaseline(baselineOut, newFindings); werr != nil {
			fmt.Fprintln(os.Stderr, "error writing baseline:", werr)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "mimir: wrote baseline with %d finding(s) to %s\n", len(newFindings), baselineOut)
	}

	// display: suppressed findings are shown only under --show-suppressed (D-12).
	display := newFindings
	if showSuppressed {
		display = findings
	}

	// 6. Output: determine format and color settings
	format, _ := cmd.Flags().GetString("format")
	noColor, _ := cmd.Root().PersistentFlags().GetBool("no-color")
	// Also honor NO_COLOR env var (D-14; fatih/color checks it at init, but explicit override for clarity)
	noColor = noColor || os.Getenv("NO_COLOR") != ""
	quiet, _ := cmd.Flags().GetBool("quiet")

	if format == "json" {
		// JSON output to stdout (D-03); findings already have redacted Secret fields (OUT-03).
		// Suppressed findings are present only when --show-suppressed kept them, carrying
		// suppressed/suppression_reason for audit (D-12).
		if err := output.WriteJSON(os.Stdout, display, stats); err != nil {
			fmt.Fprintln(os.Stderr, "error encoding JSON:", err)
			os.Exit(2)
		}
	} else {
		// Human-readable output (default) (D-12)
		output.WriteHuman(os.Stdout, display, stats, noColor, quiet, verbose)
	}

	// 7. Exit code contract (IFACE-02): 0=clean, 1=findings (unless --exit-zero), 2=error.
	// Only NON-suppressed (NEW) findings flip the exit code (D-12, Pitfall 5) — a
	// suppressed finding never fails CI, even under --show-suppressed.
	exitZero, _ := cmd.Flags().GetBool("exit-zero")
	if len(newFindings) > 0 && !exitZero {
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
