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
