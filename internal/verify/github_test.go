package verify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MatrixMagician/mimir/internal/finding"
	"github.com/stretchr/testify/assert"
)

const ghFixtureToken = "ghp_FAKEtoken0123456789abcdefABCDEF012345"

// newGitHubVerifierForServer builds a githubVerifier pointed at a test server.
func newGitHubVerifierForServer(srv *httptest.Server) githubVerifier {
	return githubVerifier{
		baseURL: srv.URL,
		client:  srv.Client(),
	}
}

// TestGitHubClassify drives the status-code → Status mapping via httptest:
// 200→Active, 401→Inactive, 403/429 (no retry budget left) →Unknown,
// network/timeout→Unknown.
func TestGitHubClassify(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   Status
	}{
		{"200 is active", http.StatusOK, Active},
		{"401 is inactive", http.StatusUnauthorized, Inactive},
		{"403 without retry-after is unknown", http.StatusForbidden, Unknown},
		{"429 without retry-after is unknown", http.StatusTooManyRequests, Unknown},
		{"500 is unknown", http.StatusInternalServerError, Unknown},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()
			v := newGitHubVerifierForServer(srv)
			got := v.Verify(context.Background(), "", ghFixtureToken, finding.Finding{})
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestGitHubHeaders asserts the request carries the required headers and that
// the token is sent in the Authorization header only — never in the URL/query.
func TestGitHubHeaders(t *testing.T) {
	var gotAuth, gotUA, gotAccept, gotVersion, gotURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotUA = r.Header.Get("User-Agent")
		gotAccept = r.Header.Get("Accept")
		gotVersion = r.Header.Get("X-GitHub-Api-Version")
		gotURL = r.URL.String()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	v := newGitHubVerifierForServer(srv)
	v.Verify(context.Background(), "", ghFixtureToken, finding.Finding{})

	assert.Equal(t, "Bearer "+ghFixtureToken, gotAuth)
	assert.NotEmpty(t, gotUA, "User-Agent must be non-empty (omitting it yields 403)")
	assert.Equal(t, "application/vnd.github+json", gotAccept)
	assert.Equal(t, "2022-11-28", gotVersion)
	assert.NotContains(t, gotURL, ghFixtureToken, "token must NEVER appear in the URL/query")
}

// TestRetryAfterOnce asserts a 429/403 with Retry-After is retried at most once,
// and a persistent rate-limit yields Unknown (no retry storm — Pitfall 3).
func TestRetryAfterOnce(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	v := newGitHubVerifierForServer(srv)
	got := v.Verify(context.Background(), "", ghFixtureToken, finding.Finding{})
	assert.Equal(t, Unknown, got)
	assert.Equal(t, 2, calls, "exactly one retry after Retry-After, then give up")
}

// TestRetryAfterSucceedsSecond asserts that if the second attempt succeeds after
// honoring Retry-After once, the result reflects that attempt.
func TestRetryAfterSucceedsSecond(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	v := newGitHubVerifierForServer(srv)
	got := v.Verify(context.Background(), "", ghFixtureToken, finding.Finding{})
	assert.Equal(t, Active, got)
	assert.Equal(t, 2, calls)
}

// TestForbiddenWithRateLimitSignalRetries is the WR-05 guard: a 403 carrying a
// rate-limit signal (X-RateLimit-Remaining: 0) is treated as a secondary
// rate-limit and retried once; a 403 with NO such signal is Unknown with no
// retry (covered by TestGitHubClassify's "403 without retry-after" case).
func TestForbiddenWithRateLimitSignalRetries(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	v := newGitHubVerifierForServer(srv)
	got := v.Verify(context.Background(), "", ghFixtureToken, finding.Finding{})
	assert.Equal(t, Unknown, got)
	assert.Equal(t, 2, calls, "a rate-limited 403 retries exactly once")
}

// TestForbiddenNoSignalNoRetry asserts a plain 403 (no rate-limit headers) is
// Unknown WITHOUT a retry (WR-05) — distinct from a secondary rate-limit.
func TestForbiddenNoSignalNoRetry(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	v := newGitHubVerifierForServer(srv)
	got := v.Verify(context.Background(), "", ghFixtureToken, finding.Finding{})
	assert.Equal(t, Unknown, got)
	assert.Equal(t, 1, calls, "a non-rate-limit 403 must not burn a retry")
}

// TestParseRetryAfter exercises the WR-04 Retry-After parsing matrix:
// delta-seconds, HTTP-date (future/past), empty, and an unparseable value
// (which must back off the cap, not retry immediately).
func TestParseRetryAfter(t *testing.T) {
	assert.Equal(t, time.Nanosecond, parseRetryAfter(""), "empty → immediate retry")
	assert.Equal(t, time.Nanosecond, parseRetryAfter("0"), "0 → immediate retry")
	assert.Equal(t, 3*time.Second, parseRetryAfter("3"), "delta-seconds")
	assert.Equal(t, retryAfterCap, parseRetryAfter("not-a-date"),
		"unparseable → back off the cap, never immediate retry (WR-04)")

	// HTTP-date in the past → immediate retry.
	past := time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)
	assert.Equal(t, time.Nanosecond, parseRetryAfter(past), "past HTTP-date → immediate retry")

	// HTTP-date in the future → a positive wait (HTTP-date has 1s resolution).
	future := time.Now().Add(2 * time.Minute).UTC().Format(http.TimeFormat)
	d := parseRetryAfter(future)
	assert.Greater(t, d, time.Duration(0), "future HTTP-date → positive wait (WR-04)")
}

// TestGitHubTimeout asserts a hanging server yields Unknown once the per-call
// context deadline elapses (never inactive on timeout).
func TestGitHubTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	v := newGitHubVerifierForServer(srv)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	got := v.Verify(ctx, "", ghFixtureToken, finding.Finding{})
	assert.Equal(t, Unknown, got)
}

// TestGitHubNetworkError asserts a connection error (server closed) yields Unknown.
func TestGitHubNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	client := srv.Client()
	srv.Close() // now connections will be refused
	v := githubVerifier{baseURL: url, client: client}
	got := v.Verify(context.Background(), "", ghFixtureToken, finding.Finding{})
	assert.Equal(t, Unknown, got)
}

// TestGitHubErrorNoToken asserts the sanitized error path never contains the token.
func TestGitHubErrorNoToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	v := newGitHubVerifierForServer(srv)
	_, err := v.verify(context.Background(), ghFixtureToken)
	if err != nil {
		assert.False(t, strings.Contains(err.Error(), ghFixtureToken), "token must not appear in error")
	}
}
