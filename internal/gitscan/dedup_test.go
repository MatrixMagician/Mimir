package gitscan

import (
	"testing"

	"github.com/MatrixMagician/mimir/internal/finding"
)

// TestDedupKeepsEarliestCommitLocationAndProvenance is the WR-01 regression: when
// the same secret (same fingerprint) appears in multiple commits, the kept
// finding's Line/Column AND CommitSHA must both come from the earliest commit, so
// the "file:line @ sha" link is internally consistent. git log -p emits
// newest-first, so the first-seen occurrence carries the LATER commit.
func TestDedupKeepsEarliestCommitLocationAndProvenance(t *testing.T) {
	const file, rule, secret = "config/app.go", "aws-access-token", "AKIAFAKEKEYABCDE2345"

	// Newer commit, seen first (git log -p is newest-first): secret on line 42.
	newer := finding.New(rule, file, 42, 5, secret, "ctx", false)
	newer.CommitSHA = "new333333333333333333333333333333333333"
	newer.CommitAuthor = "New Author"
	newer.CommitDate = "2026-05-20T10:00:00Z"

	// Older introducing commit, seen second: same secret, line 7.
	older := finding.New(rule, file, 7, 9, secret, "ctx", false)
	older.CommitSHA = "old111111111111111111111111111111111111"
	older.CommitAuthor = "Old Author"
	older.CommitDate = "2026-05-01T10:00:00Z"

	if newer.Fingerprint != older.Fingerprint {
		t.Fatalf("precondition: same secret must share a fingerprint; got %q vs %q",
			newer.Fingerprint, older.Fingerprint)
	}

	got := dedupByFingerprint([]finding.Finding{newer, older})
	if len(got) != 1 {
		t.Fatalf("expected 1 deduped finding, got %d", len(got))
	}
	f := got[0]
	// Provenance and location must both reflect the EARLIEST commit.
	if f.CommitSHA != older.CommitSHA {
		t.Errorf("CommitSHA = %q, want earliest %q", f.CommitSHA, older.CommitSHA)
	}
	if f.CommitDate != older.CommitDate {
		t.Errorf("CommitDate = %q, want earliest %q", f.CommitDate, older.CommitDate)
	}
	if f.Line != 7 || f.Column != 9 {
		t.Errorf("location = %d:%d, want earliest commit's 7:9 (line must match the SHA)", f.Line, f.Column)
	}
}
