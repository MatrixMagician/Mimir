package scanner

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/MatrixMagician/mimir/internal/config"
	"github.com/MatrixMagician/mimir/internal/detect"
	"github.com/MatrixMagician/mimir/internal/finding"
	"github.com/MatrixMagician/mimir/internal/suppress"
)

// Stats records metrics from a completed scan.
type Stats struct {
	FilesScanned int
	Duration     time.Duration

	// PathsExcluded (D-13) is the aggregate count of paths skipped by the
	// path-exclusion layer (.mimirignore + default globs). Suppressed (D-11)
	// maps a suppression reason ("inline-ignore" | "allowlist" | "baseline")
	// to the number of findings withheld for that reason. Both are populated
	// by the suppression layers landing in Plans 02–04.
	PathsExcluded int
	Suppressed    map[string]int
}

// Scanner orchestrates the filesystem walk and detection engine.
// It is safe to call Scan concurrently from a single Scanner instance
// (each Scan call uses independent state).
type Scanner struct {
	engine *detect.Engine
	cfg    *config.Config

	// ShowSuppressed controls the inline-ignore annotate-vs-drop branch
	// (D-12). When false (default), an inline-ignored finding is DROPPED at
	// scan time; when true, it is KEPT and annotated (Suppressed=true,
	// SuppressionReason="inline-ignore") so it reaches the output stage. The
	// suppressed count is incremented in BOTH cases.
	ShowSuppressed bool

	// Matcher prunes paths from the walk before they are opened (SUP-02/SUP-04,
	// D-05). When nil, no path exclusion is applied.
	Matcher *suppress.PathMatcher
}

// New creates a Scanner with the given engine and config.
func New(engine *detect.Engine, cfg *config.Config) *Scanner {
	return &Scanner{engine: engine, cfg: cfg}
}

// Scan walks each path in paths, scans all eligible files using a bounded
// worker pool, and returns the sorted list of findings, a fingerprint→raw
// side-channel map (for opt-in live verification), scan stats, and any error.
// A nil error means the scan completed (individual file errors are logged to
// stderr when Verbose is set and do not abort the scan).
//
// The returned raw map is keyed by finding fingerprint and carries the raw
// secret off-struct; it is NEVER stored on a Finding or serialized. It is always
// non-nil (empty when there are no findings) so callers may range it safely.
func (s *Scanner) Scan(ctx context.Context, paths []string) ([]finding.Finding, map[string]string, Stats, error) {
	start := time.Now()

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(runtime.GOMAXPROCS(0))

	var mu sync.Mutex
	var allFindings []finding.Finding
	rawByFP := map[string]string{}
	suppressedCounts := map[string]int{}
	var filesScanned atomic.Int64
	var pathsExcluded atomic.Int64

	for _, root := range paths {
		// go.mod pins go 1.25, where each loop iteration already has its own
		// `root` — no pre-1.22 `root := root` capture shadow is needed (IN-01).
		walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				// A failure on the root path itself (e.g. it does not exist) is
				// fatal: the user named a target that cannot be scanned, and
				// silently reporting "clean" (exit 0) would hide a typo'd path
				// in CI — the opposite of trustworthy. Deeper per-entry errors
				// (permissions, races during the walk) remain non-fatal.
				if path == root {
					return err
				}
				// Permission errors etc. — log and skip
				if s.cfg.Verbose {
					fmt.Fprintf(os.Stderr, "mimir: skipping %s: %v\n", path, err)
				}
				return nil
			}

			// Repo-relative, forward-slash path for path-prune matching (D-05).
			rel := relForMatch(root, path)

			// Skip .git directory
			if d.IsDir() {
				if d.Name() == ".git" {
					return filepath.SkipDir
				}
				// Path-prune: a matched directory's whole subtree is skipped
				// without descending into it (SUP-02/SUP-04, D-05). The pruned
				// directory counts as one excluded path (D-13).
				if s.Matcher != nil && rel != "" && s.Matcher.Excluded(rel, true) {
					pathsExcluded.Add(1)
					return filepath.SkipDir
				}
				return nil
			}

			// Only process regular files
			if !d.Type().IsRegular() {
				return nil
			}

			// Path-prune matched files: never opened, only counted (D-05/D-13).
			if s.Matcher != nil && rel != "" && s.Matcher.Excluded(rel, false) {
				pathsExcluded.Add(1)
				return nil
			}

			// Check file size before enqueueing
			info, statErr := d.Info()
			if statErr != nil {
				return nil
			}
			maxBytes := int64(s.cfg.MaxFileSizeMB) * 1024 * 1024
			if maxBytes > 0 && info.Size() > maxBytes {
				if s.cfg.Verbose {
					fmt.Fprintf(os.Stderr, "mimir: skipping oversized file %s (%d bytes > %d bytes limit)\n",
						path, info.Size(), maxBytes)
				}
				return nil
			}

			// Capture path for goroutine closure
			filePath := path
			rootPath := root

			g.Go(func() error {
				findings, fileSuppressed, fileRaw, scanErr := s.scanFile(ctx, filePath, rootPath)
				if scanErr != nil {
					if s.cfg.Verbose {
						fmt.Fprintf(os.Stderr, "mimir: error scanning %s: %v\n", filePath, scanErr)
					}
					return nil // file errors are non-fatal
				}
				filesScanned.Add(1)
				if len(findings) > 0 || len(fileSuppressed) > 0 {
					mu.Lock()
					allFindings = append(allFindings, findings...)
					for reason, n := range fileSuppressed {
						suppressedCounts[reason] += n
					}
					// Merge the per-file raw side channel under the same lock
					// that guards allFindings (keys are unique per fingerprint).
					for k, v := range fileRaw {
						rawByFP[k] = v
					}
					mu.Unlock()
				}
				return nil
			})

			return nil
		})

		if walkErr != nil {
			return nil, nil, Stats{}, walkErr
		}
	}

	if err := g.Wait(); err != nil {
		return nil, nil, Stats{}, err
	}

	// Sort deterministically: File → Line → Column
	sort.Slice(allFindings, func(i, j int) bool {
		if allFindings[i].File != allFindings[j].File {
			return allFindings[i].File < allFindings[j].File
		}
		if allFindings[i].Line != allFindings[j].Line {
			return allFindings[i].Line < allFindings[j].Line
		}
		return allFindings[i].Column < allFindings[j].Column
	})

	// suppressedCounts was accumulated during the walk (D-11). It counts every
	// inline-ignored finding regardless of the annotate-vs-drop branch, so the
	// summary is accurate even when suppressed findings were dropped at scan time.
	return allFindings, rawByFP, Stats{
		FilesScanned:  int(filesScanned.Load()),
		PathsExcluded: int(pathsExcluded.Load()),
		Duration:      time.Since(start),
		Suppressed:    suppressedCounts,
	}, nil
}

// relForMatch returns the repo-relative, forward-slash path of p under root,
// used for path-prune matching. It mirrors the normalization scanFile applies
// to finding paths so glob matches and reported paths agree.
func relForMatch(root, p string) string {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		rel = p
	}
	return strings.TrimPrefix(filepath.ToSlash(rel), "./")
}

// scanFile reads a single file and returns its findings plus a per-reason
// suppression count. It enforces binary detection and uses the engine for
// line-by-line scanning. Inline-ignored findings are dropped (default) or
// kept+annotated (when s.ShowSuppressed) but counted in either case.
func (s *Scanner) scanFile(ctx context.Context, filePath, scanRoot string) ([]finding.Finding, map[string]int, map[string]string, error) {
	// Per-file raw-secret side channel (fingerprint → raw secret) for opt-in
	// live verification. Populated by engine.ScanLine, merged into the run-level
	// map under mu in Scan, NEVER stored on a Finding or serialized.
	fileRaw := map[string]string{}

	// Open and read the file
	f, err := os.Open(filePath)
	if err != nil {
		return nil, nil, nil, err
	}
	defer f.Close()

	// Peek at first 512 bytes for binary detection
	header := make([]byte, 512)
	n, err := f.Read(header)
	if err != nil && n == 0 {
		return nil, nil, fileRaw, nil // empty file
	}
	header = header[:n]

	if isBinary(header) {
		return nil, nil, fileRaw, nil // skip binary files
	}

	// Rewind and read full content line by line
	if _, err := f.Seek(0, 0); err != nil {
		return nil, nil, nil, err
	}

	// Compute repo-relative path (forward-slash normalized)
	relPath, err := filepath.Rel(scanRoot, filePath)
	if err != nil {
		relPath = filePath // fall back to full path
	}
	relPath = filepath.ToSlash(relPath)
	// Remove leading "./" if present
	relPath = strings.TrimPrefix(relPath, "./")

	var findings []finding.Finding
	suppressed := map[string]int{}
	lineNum := 0
	scanner := bufio.NewScanner(f)
	// Increase scanner buffer for long lines
	scanner.Buffer(make([]byte, 64*1024), 64*1024)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return findings, suppressed, fileRaw, ctx.Err()
		default:
		}
		lineNum++
		line := scanner.Text()
		lineFindings := s.engine.ScanLine(line, relPath, lineNum, fileRaw)
		// Inline-ignore suppression (SUP-01/D-12): if a finding's own source
		// line carries a mimir-ignore directive for its rule, count it and
		// either drop it (default) or annotate-and-keep (--show-suppressed).
		for i := range lineFindings {
			if suppress.InlineSuppresses(line, lineFindings[i].RuleID) {
				suppressed[suppress.InlineReason]++
				if !s.ShowSuppressed {
					continue // drop: do not append
				}
				lineFindings[i].Suppressed = true
				lineFindings[i].SuppressionReason = suppress.InlineReason
			}
			findings = append(findings, lineFindings[i])
		}
	}
	if err := scanner.Err(); err != nil {
		return findings, suppressed, fileRaw, err
	}

	return findings, suppressed, fileRaw, nil
}
