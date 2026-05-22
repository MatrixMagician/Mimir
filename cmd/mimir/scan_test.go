package cmd_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const mimirTestBin = "/tmp/mimir-cmd-test"

// TestMain builds the mimir binary once for all tests in this package.
func TestMain(m *testing.M) {
	// Determine repo root from this file's location.
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("could not determine source file path")
	}
	repoRoot := filepath.Join(filepath.Dir(file), "..", "..")

	// Build from the repo root (main package is at root, not ./cmd/mimir which is package cmd)
	buildCmd := exec.Command("go", "build", "-o", mimirTestBin, ".") //nolint:gosec
	buildCmd.Dir = repoRoot
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		panic("failed to build mimir binary: " + err.Error())
	}

	code := m.Run()
	os.Remove(mimirTestBin)
	os.Exit(code)
}

// repoRoot returns the absolute path to the repository root.
func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// runMimir runs the compiled mimir binary with the given arguments from the repo root.
// It returns stdout, stderr, and the exit code.
func runMimir(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	//#nosec G204 -- mimirTestBin is a compile-time constant path to the test binary
	cmd := exec.Command(mimirTestBin, args...) //nolint:gosec
	cmd.Dir = repoRoot()
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	stdout = outBuf.String()
	stderr = errBuf.String()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return stdout, stderr, exitCode
}

// TestExitCodeClean verifies that scanning a directory with no secrets exits 0.
func TestExitCodeClean(t *testing.T) {
	_, _, code := runMimir(t, "scan", "--no-color", "testdata/clean/")
	if code != 0 {
		t.Fatalf("expected exit code 0 for clean scan, got %d", code)
	}
}

// TestExitCodeFindings verifies that scanning a directory with secrets exits 1.
func TestExitCodeFindings(t *testing.T) {
	_, _, code := runMimir(t, "scan", "--no-color", "testdata/fixtures/")
	if code != 1 {
		t.Fatalf("expected exit code 1 for scan with findings, got %d", code)
	}
}

// TestExitZero verifies that --exit-zero suppresses the non-zero exit when findings are present.
func TestExitZero(t *testing.T) {
	_, _, code := runMimir(t, "scan", "--no-color", "--exit-zero", "testdata/fixtures/")
	if code != 0 {
		t.Fatalf("expected exit code 0 with --exit-zero, got %d", code)
	}
}

// TestQuietFlag verifies --quiet behavior: findings are printed, summary is suppressed, exit=1.
func TestQuietFlag(t *testing.T) {
	stdout, _, code := runMimir(t, "scan", "--no-color", "--quiet", "testdata/fixtures/")
	if code != 1 {
		t.Fatalf("expected exit code 1 with --quiet (findings present), got %d", code)
	}
	// At least one finding line should be present (path:line:col pattern)
	if !strings.Contains(stdout, ":") {
		t.Errorf("expected finding line in stdout with --quiet, got: %q", stdout)
	}
	// Summary line must be absent
	if strings.Contains(stdout, "finding(s) in") {
		t.Errorf("expected no summary line in stdout with --quiet, but found it: %q", stdout)
	}
	if strings.Contains(stdout, "no findings") {
		t.Errorf("expected no summary line in stdout with --quiet, but found it: %q", stdout)
	}
}

// TestNoSecretsInOutput verifies that raw secret values never appear in stdout.
func TestNoSecretsInOutput(t *testing.T) {
	rawSecrets := []string{
		"AKIAFAKEKEYABCDE2345",
		"AKIATESTKEY234567AB",
	}
	stdout, _, _ := runMimir(t, "scan", "--no-color", "testdata/fixtures/")
	for _, raw := range rawSecrets {
		if strings.Contains(stdout, raw) {
			t.Errorf("raw secret %q found in stdout output — redaction-at-boundary violated", raw)
		}
	}
}

// TestSummaryLineCleanScan verifies the "no findings" summary appears on a clean scan.
func TestSummaryLineCleanScan(t *testing.T) {
	stdout, _, code := runMimir(t, "scan", "--no-color", "testdata/clean/")
	if code != 0 {
		t.Fatalf("expected exit 0 for clean scan, got %d", code)
	}
	if !strings.Contains(stdout, "no findings") {
		t.Errorf("expected 'no findings' in stdout, got: %q", stdout)
	}
}

// TestSummaryLineFindingsScan verifies the findings summary appears when secrets are found.
func TestSummaryLineFindingsScan(t *testing.T) {
	stdout, _, _ := runMimir(t, "scan", "--no-color", "testdata/fixtures/")
	if !strings.Contains(stdout, "finding(s) in") {
		t.Errorf("expected summary line in stdout, got: %q", stdout)
	}
}

// TestVersionCommand verifies the version subcommand works.
func TestVersionCommand(t *testing.T) {
	_, _, code := runMimir(t, "version")
	if code != 0 {
		t.Fatalf("expected exit 0 for version command, got %d", code)
	}
}
