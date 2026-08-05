package cmd

import (
	"fmt"
	"os"
	"path/filepath"

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

// runScan is the scan pipeline: resolve inputs → scan → suppress → verify →
// output → exit code.
//
// Fail-loud discipline: every error path here returns the error rather than
// calling os.Exit(2) directly, because Execute() prints "error: <err>" to stderr
// and exits 2 — exactly what the hand-rolled exits did. Exit 1 (findings
// present) is NOT an error and is still signalled with an explicit os.Exit,
// since it must not print an error message (IFACE-02).
func runScan(cmd *cobra.Command, args []string) error {
	// 1. Resolve paths: default to current directory (D-13)
	paths := args
	if len(paths) == 0 {
		paths = []string{"."}
	}
	scanRoot := resolveScanRoot(paths)

	cfg, err := loadScanConfig(cmd, scanRoot)
	if err != nil {
		return err
	}

	showSuppressed, _ := cmd.Flags().GetBool("show-suppressed")
	verbose, _ := cmd.Flags().GetBool("verbose")
	engine := detect.NewEngine(cfg)

	findings, raw, stats, err := runScanSource(cmd, engine, cfg, paths, scanRoot, showSuppressed)
	if err != nil {
		return err
	}

	// Baseline (SUP-03): a decoupled post-g.Wait() stage (the pipeline position
	// suppress/doc.go reserves for Phase 4). --baseline marks findings present in
	// the snapshot as suppressed.
	if err := applyBaseline(cmd, findings, &stats); err != nil {
		return err
	}

	// newFindings is the reportable set: everything not suppressed by any layer.
	// It drives the exit code (Pitfall 5 / IFACE-02) and the --baseline-out snapshot.
	var newFindings []finding.Finding
	for _, f := range findings {
		if !f.Suppressed {
			newFindings = append(newFindings, f)
		}
	}

	runVerification(cmd, scanRoot, findings, newFindings, raw, showSuppressed)

	if baselineOut, _ := cmd.Flags().GetString("baseline-out"); baselineOut != "" {
		if err := suppress.WriteBaseline(baselineOut, newFindings); err != nil {
			return fmt.Errorf("writing baseline: %w", err)
		}
		fmt.Fprintf(os.Stderr, "mimir: wrote baseline with %d finding(s) to %s\n", len(newFindings), baselineOut)
	}

	// display: suppressed findings are shown only under --show-suppressed (D-12).
	display := newFindings
	if showSuppressed {
		display = findings
	}
	if err := writeOutput(cmd, display, stats, verbose); err != nil {
		return err
	}

	// Exit code contract (IFACE-02): 0=clean, 1=findings (unless --exit-zero),
	// 2=error. Only NON-suppressed (NEW) findings flip the exit code (D-12,
	// Pitfall 5) — a suppressed finding never fails CI, even under
	// --show-suppressed.
	//
	// An INCOMPLETE scan also fails. If a file was selected but could not be
	// read, "no findings" does not mean "no secrets" — it means we did not look.
	// Exiting 0 there would let a pre-commit hook wave through the one file the
	// key was in, which is the failure mode this tool exists to prevent.
	// --exit-zero (the documented CI soft mode) still forces 0, so the escape
	// hatch is unchanged and no new flag is needed.
	exitZero, _ := cmd.Flags().GetBool("exit-zero")
	if (len(newFindings) > 0 || stats.FilesUnreadable > 0) && !exitZero {
		os.Exit(1)
	}
	return nil
}

// loadScanConfig loads the config with full precedence (--config > .mimir.toml in
// scan root > embedded defaults, CFG-02) and overlays the CLI flags that override
// config-file values for runtime behavior.
func loadScanConfig(cmd *cobra.Command, scanRoot string) (*mimirconfig.Config, error) {
	flagConfig, _ := cmd.Flags().GetString("config")
	cfg, err := mimirconfig.LoadConfig(flagConfig, scanRoot)
	if err != nil {
		return nil, err
	}
	cfg.NoEntropy, _ = cmd.Flags().GetBool("no-entropy")
	cfg.MaxFileSizeMB, _ = cmd.Flags().GetInt("max-file-size")
	cfg.Verbose, _ = cmd.Flags().GetBool("verbose")
	return cfg, nil
}

// runScanSource selects the scan source and runs it. The mode flag picks the
// Source; everything downstream (baseline, output, exit code) is shared and
// unchanged across modes (D-01). --git streams current-branch history; --staged
// streams the staged diff (the pre-commit hook's source); the default is the
// working-tree walk.
func runScanSource(cmd *cobra.Command, engine *detect.Engine, cfg *mimirconfig.Config,
	paths []string, scanRoot string, showSuppressed bool,
) ([]finding.Finding, map[string]string, scanner.Stats, error) {
	gitMode, _ := cmd.Flags().GetBool("git")
	stagedMode, _ := cmd.Flags().GetBool("staged")
	// --git and --staged select different sources, so passing both is misuse
	// (Pitfall 6 / RESEARCH A2) → exit 2.
	if gitMode && stagedMode {
		return nil, nil, scanner.Stats{}, fmt.Errorf("--git and --staged are mutually exclusive")
	}

	switch {
	case gitMode:
		return gitscan.ScanHistory(cmd.Context(), engine, scanRoot, showSuppressed)
	case stagedMode:
		return gitscan.ScanStaged(cmd.Context(), engine, scanRoot, showSuppressed)
	}

	s := scanner.New(engine, cfg)
	// --show-suppressed drives the scanner's inline-ignore annotate-vs-drop
	// branch (D-12): keep+annotate suppressed findings instead of dropping them.
	s.ShowSuppressed = showSuppressed

	// Path-exclusion (SUP-02/SUP-04): combine the shipped default globs (unless
	// disabled by config or --no-default-excludes) with the .mimirignore at the
	// scan root, and prune matching paths during the walk (D-05).
	noDefaultExcludes, _ := cmd.Flags().GetBool("no-default-excludes")
	ignoreGlobs, err := suppress.LoadMimirIgnore(scanRoot)
	if err != nil {
		return nil, nil, scanner.Stats{}, fmt.Errorf("reading .mimirignore: %w", err)
	}
	// A malformed .mimirignore glob fails loud (Security V14).
	s.Matcher, err = suppress.NewPathMatcher(ignoreGlobs, cfg.UseDefaultExcludes && !noDefaultExcludes)
	if err != nil {
		return nil, nil, scanner.Stats{}, err
	}

	return s.Scan(cmd.Context(), paths)
}

// applyBaseline marks findings present in the --baseline snapshot as suppressed,
// counting them under the baseline reason. A missing or malformed baseline fails
// loud. It is a no-op when --baseline was not passed.
func applyBaseline(cmd *cobra.Command, findings []finding.Finding, stats *scanner.Stats) error {
	baselinePath, _ := cmd.Flags().GetString("baseline")
	if baselinePath == "" {
		return nil
	}
	bl, err := suppress.LoadBaseline(baselinePath)
	if err != nil {
		return err
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
	return nil
}

// runVerification performs opt-in live verification (VERIFY-01): strictly
// label-only and OFF by default. Without --verify, verify.Run is never called →
// zero network (T-04-default) and the JSON stays byte-identical to OUT-02
// (T-04-schema). It runs ONLY on the post-suppression reportable set
// (newFindings, never the full set — RESEARCH Anti-Pattern), consuming the raw
// side channel, and NEVER touches the exit-code contract (T-04-exit). The
// pre-commit hook never passes --verify (T-04-hook, guarded by TestHookOffline).
//
// scanRoot is threaded so the AWS verifier resolves each finding's repo-relative
// File against the scan target rather than the process CWD (CR-02) — otherwise
// AWS pairing silently fails whenever mimir is run from outside the scanned
// directory.
func runVerification(cmd *cobra.Command, scanRoot string, findings, newFindings []finding.Finding,
	raw map[string]string, showSuppressed bool,
) {
	if doVerify, _ := cmd.Flags().GetBool("verify"); !doVerify {
		return
	}
	verify.Run(cmd.Context(), scanRoot, newFindings, raw)

	// WR-01: verify.Run wrote Verification onto the newFindings COPIES, but under
	// --show-suppressed the displayed slice is `findings` (the original), whose
	// elements never received the pointer — so the tags would silently vanish.
	// Back-propagate each result onto the matching original entry by fingerprint.
	// Fingerprints are content-based and unique per finding here.
	if !showSuppressed {
		return
	}
	verifByFP := make(map[string]*finding.Verification, len(newFindings))
	for i := range newFindings {
		if newFindings[i].Verification != nil {
			verifByFP[newFindings[i].Fingerprint] = newFindings[i].Verification
		}
	}
	for i := range findings {
		if v, ok := verifByFP[findings[i].Fingerprint]; ok {
			findings[i].Verification = v
		}
	}
}

// writeOutput renders the display set in the requested format. Findings already
// have redacted Secret fields (OUT-03); suppressed findings are present only when
// --show-suppressed kept them, carrying suppressed/suppression_reason for audit
// (D-12).
func writeOutput(cmd *cobra.Command, display []finding.Finding, stats scanner.Stats, verbose bool) error {
	format, _ := cmd.Flags().GetString("format")
	noColor, _ := cmd.Root().PersistentFlags().GetBool("no-color")
	// Also honor NO_COLOR env var (D-14; fatih/color checks it at init, but
	// explicit override for clarity).
	noColor = noColor || os.Getenv("NO_COLOR") != ""
	quiet, _ := cmd.Flags().GetBool("quiet")

	if format == "json" {
		if err := output.WriteJSON(os.Stdout, display, stats); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		return nil
	}
	output.WriteHuman(os.Stdout, display, stats, noColor, quiet, verbose)
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
	// First path is a file; use its directory.
	return filepath.Dir(paths[0])
}
