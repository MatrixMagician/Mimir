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
)

// Stats records metrics from a completed scan.
type Stats struct {
	FilesScanned int
	Duration     time.Duration
}

// Scanner orchestrates the filesystem walk and detection engine.
// It is safe to call Scan concurrently from a single Scanner instance
// (each Scan call uses independent state).
type Scanner struct {
	engine *detect.Engine
	cfg    *config.Config
}

// New creates a Scanner with the given engine and config.
func New(engine *detect.Engine, cfg *config.Config) *Scanner {
	return &Scanner{engine: engine, cfg: cfg}
}

// Scan walks each path in paths, scans all eligible files using a bounded
// worker pool, and returns the sorted list of findings, scan stats, and any
// error. A nil error means the scan completed (individual file errors are
// logged to stderr when Verbose is set and do not abort the scan).
func (s *Scanner) Scan(ctx context.Context, paths []string) ([]finding.Finding, Stats, error) {
	start := time.Now()

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(runtime.GOMAXPROCS(0))

	var mu sync.Mutex
	var allFindings []finding.Finding
	var filesScanned atomic.Int64

	for _, root := range paths {
		root := root // capture loop variable
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

			// Skip .git directory
			if d.IsDir() {
				if d.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}

			// Only process regular files
			if !d.Type().IsRegular() {
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
				findings, scanErr := s.scanFile(ctx, filePath, rootPath)
				if scanErr != nil {
					if s.cfg.Verbose {
						fmt.Fprintf(os.Stderr, "mimir: error scanning %s: %v\n", filePath, scanErr)
					}
					return nil // file errors are non-fatal
				}
				filesScanned.Add(1)
				if len(findings) > 0 {
					mu.Lock()
					allFindings = append(allFindings, findings...)
					mu.Unlock()
				}
				return nil
			})

			return nil
		})

		if walkErr != nil {
			return nil, Stats{}, walkErr
		}
	}

	if err := g.Wait(); err != nil {
		return nil, Stats{}, err
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

	return allFindings, Stats{
		FilesScanned: int(filesScanned.Load()),
		Duration:     time.Since(start),
	}, nil
}

// scanFile reads a single file and returns all findings.
// It enforces binary detection and uses the engine for line-by-line scanning.
func (s *Scanner) scanFile(ctx context.Context, filePath, scanRoot string) ([]finding.Finding, error) {
	// Open and read the file
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Peek at first 512 bytes for binary detection
	header := make([]byte, 512)
	n, err := f.Read(header)
	if err != nil && n == 0 {
		return nil, nil // empty file
	}
	header = header[:n]

	if isBinary(header) {
		return nil, nil // skip binary files
	}

	// Rewind and read full content line by line
	if _, err := f.Seek(0, 0); err != nil {
		return nil, err
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
	lineNum := 0
	scanner := bufio.NewScanner(f)
	// Increase scanner buffer for long lines
	scanner.Buffer(make([]byte, 64*1024), 64*1024)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}
		lineNum++
		line := scanner.Text()
		lineFindings := s.engine.ScanLine(line, relPath, lineNum)
		if len(lineFindings) > 0 {
			findings = append(findings, lineFindings...)
		}
	}
	if err := scanner.Err(); err != nil {
		return findings, err
	}

	return findings, nil
}
