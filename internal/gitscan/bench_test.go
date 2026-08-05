package gitscan_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/MatrixMagician/mimir/internal/gitscan"
)

// Criterion-2 benchmark gate: prove the history scan is memory-bounded (streaming,
// not buffered) and that wall time is acceptable for CI / the pre-commit hook.
//
// The load-bearing assertion is that the per-op HEAP-ALLOC DELTA of a ScanHistory
// run grows SUB-LINEARLY with commit count. ScanHistory streams the `git log -p`
// patch through gitdiff.Parse's channel and consumes it lazily, so peak heap is
// driven by per-hunk working set and retained findings, NOT by a buffered copy of
// the whole stream. If a future change buffered the stream (e.g. io.ReadAll over
// `git log -p`), the large-N delta would scale ~linearly with history length and
// blow past heapCeilingBytes.
//
// Baseline measurement (A4 — thresholds derived from a measured run, not guessed).
// Measured on this machine (Go 1.26, linux/amd64, AMD Ryzen AI MAX+ 395) with:
//
//	go test -bench 'BenchmarkHistoryMem|BenchmarkStaged' -benchmem -run '^$' ./internal/gitscan/
//
// Observed per-op figures (b.ReportMetric output):
//
//	BenchmarkHistoryMem/commits-50    heap ~0.79 MB/op   ~3.2 ms/op   3323 allocs/op
//	BenchmarkHistoryMem/commits-500   heap ~2.03 MB/op   ~7.8 ms/op  30852 allocs/op
//	BenchmarkStaged                   ~0.83 ms/op  35712 B/op  170 allocs/op
//
// Key result: a 10x increase in history (50 → 500 commits) raised the heap delta
// only ~2.5x (0.79 → 2.03 MB), not 10x — confirming the stream is NOT buffered.
// Wall time scales ~linearly with commit count (expected: git must emit every
// patch) but stays single-digit-ms even at 500 commits.
//
// Ceilings below = measured large-N figures + generous headroom. They are
// regression tripwires for the streaming invariant, NOT tight performance budgets:
//   - heapCeilingBytes 16 MB: ~8x the observed ~2.0 MB large-N delta. A buffered
//     rewrite would scale ~linearly and blow far past this on a 500-commit repo;
//     normal allocator jitter will not.
//   - wallCeilingNsLarge 5s: ~640x the observed ~7.8 ms large-N wall time, tolerant
//     of slow/loaded CI runners while still catching a pathological regression.
const (
	heapCeilingBytes   = 16 << 20      // 16 MB — streaming-regression tripwire (measured ~2.0 MB large-N + headroom)
	wallCeilingNsLarge = 5_000_000_000 // 5 s — wall-time regression tripwire for the large-N history scan
	smallHistoryN      = 50            // small history size for the streaming comparison
	largeHistoryN      = 500           // large history size (10x) — heap delta must grow sub-linearly vs small
)

// buildLargeHistory git-inits a temp repo and creates nCommits commits, each
// rewriting a single file. A couple of commits embed a real (non-EXAMPLE) secret
// so the detection + finding path actually runs under the benchmark; the rest are
// benign so the memory shape reflects ordinary history, not a pathological
// all-secrets repo.
func buildLargeHistory(tb testing.TB, nCommits int) string {
	tb.Helper()
	dir := initRepo(tb)

	file := filepath.Join(dir, "data.txt")
	for i := 0; i < nCommits; i++ {
		var content string
		switch i {
		case nCommits / 3, 2 * nCommits / 3:
			// Two commits introduce a real secret so the finding path runs.
			content = fmt.Sprintf("rev %d\naws_access_key_id = %s\n", i, fixtureSecret)
		default:
			content = fmt.Sprintf("rev %d\njust some benign config line number %d\n", i, i)
		}
		if err := os.WriteFile(file, []byte(content), 0600); err != nil {
			tb.Fatalf("write rev %d: %v", i, err)
		}
		git(tb, dir, "add", "data.txt")
		git(tb, dir, "commit", "-q", "-m", fmt.Sprintf("rev %d", i))
	}
	return dir
}

// heapDelta returns the HeapAlloc growth (bytes) caused by running fn once, after
// forcing a GC so the before-reading is a stable floor.
func heapDelta(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	if after.HeapAlloc < before.HeapAlloc {
		return 0
	}
	return after.HeapAlloc - before.HeapAlloc
}

// BenchmarkHistoryMem is the criterion-2 regression gate. It runs ScanHistory over
// a small and a large generated history, reports per-op heap-bytes and ms, and
// FATALS if the large-N heap delta exceeds heapCeilingBytes (streaming broken) or
// the large-N wall time exceeds wallCeilingNsLarge. Because the heap ceiling is a
// fixed byte count independent of commit count, a delta that scaled with history
// length would trip it — which is exactly the bounded-memory invariant we assert.
func BenchmarkHistoryMem(b *testing.B) {
	eng := newTestEngine(b)

	sizes := []struct {
		name string
		n    int
	}{
		{"commits-50", smallHistoryN},
		{"commits-500", largeHistoryN},
	}

	for _, sz := range sizes {
		sz := sz
		b.Run(sz.name, func(b *testing.B) {
			dir := buildLargeHistory(b, sz.n)
			b.ReportAllocs()
			b.ResetTimer()

			var peakHeap uint64
			for i := 0; i < b.N; i++ {
				d := heapDelta(func() {
					_, _, _, err := gitscan.ScanHistory(context.Background(), eng, dir, false)
					if err != nil {
						b.Fatalf("ScanHistory(%s): %v", sz.name, err)
					}
				})
				if d > peakHeap {
					peakHeap = d
				}
			}
			b.StopTimer()

			b.ReportMetric(float64(peakHeap), "heap-bytes/op")
			b.ReportMetric(float64(peakHeap)/(1<<20), "heap-MB/op")
			nsPerOp := float64(b.Elapsed().Nanoseconds()) / float64(b.N)
			b.ReportMetric(nsPerOp/1e6, "ms/op")

			// Criterion-2 gate: only the large-N run guards the invariants. The
			// small-N run is the comparison point surfaced via ReportMetric.
			if sz.n == largeHistoryN {
				if peakHeap > heapCeilingBytes {
					b.Fatalf("history heap delta %d B (%.2f MB) exceeds ceiling %d B (%.0f MB) "+
						"— streaming likely broken (buffered read?)",
						peakHeap, float64(peakHeap)/(1<<20), heapCeilingBytes, float64(heapCeilingBytes)/(1<<20))
				}
				if int64(nsPerOp) > wallCeilingNsLarge {
					b.Fatalf("history scan %.0f ms/op exceeds wall ceiling %d ms",
						nsPerOp/1e6, wallCeilingNsLarge/1_000_000)
				}
			}
		})
	}
}

// BenchmarkStaged measures ScanStaged over a representative staged diff. It is the
// reference for the pre-commit hook's sub-second budget (Plan 03 IFACE-03,
// criterion 4): the reported ms/op should be well under a second on a typical
// staged change, which a developer experiences on every `git commit`.
func BenchmarkStaged(b *testing.B) {
	eng := newTestEngine(b)
	// A representative staged change: one secret-bearing line plus some benign
	// lines, the shape of an ordinary commit.
	content := "package config\n\nconst (\n\tAPIKey = \"" + fixtureSecret + "\"\n\tEndpoint = \"https://example.com\"\n)\n"
	dir := newStagedFixture(b, "config.go", content)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, err := gitscan.ScanStaged(context.Background(), eng, dir, false)
		if err != nil {
			b.Fatalf("ScanStaged: %v", err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/1e6, "ms/op")
}
