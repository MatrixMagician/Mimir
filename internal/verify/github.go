package verify

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/MatrixMagician/mimir/internal/finding"
)

// githubVerifier verifies a detected GitHub token by making a single read-only
// GET https://api.github.com/user with the token in the Authorization header.
// It uses bare net/http (no go-github SDK) to keep the binary lean.
//
// SECURITY: the token is sent ONLY in the Authorization header — never in the
// URL/query. On any error the token is never placed in a message; error paths
// return a sanitizedError{provider:"github", reason} and the verifier surfaces
// Unknown.
type githubVerifier struct {
	// baseURL is the API base (default https://api.github.com); injectable so
	// httptest can drive the classifier without real network calls.
	baseURL string
	// client is the HTTP client; injectable for tests. nil falls back to a
	// default client.
	client *http.Client
}

func (githubVerifier) Provider() string { return "github" }

const (
	githubBaseURL    = "https://api.github.com"
	githubUserAgent  = "mimir"
	githubAPIVersion = "2022-11-28"
	githubAccept     = "application/vnd.github+json"
	// retryAfterCap bounds how long we will sleep honoring a Retry-After header
	// so a hostile/large value cannot stall the run beyond the per-call budget.
	retryAfterCap = 5 * time.Second
)

// Verify makes the GET /user call and maps the outcome to a Status. It honors a
// single Retry-After on a 403/429, then gives up (Unknown) — no retry storm.
func (g githubVerifier) Verify(ctx context.Context, raw string, f finding.Finding) Status {
	st, _ := g.verify(ctx, raw)
	return st
}

// verify performs the call(s) and returns the Status plus a sanitized error (for
// optional logging by the caller). The error NEVER contains the token.
func (g githubVerifier) verify(ctx context.Context, token string) (Status, error) {
	// First attempt.
	st, retryAfter, err := g.doOnce(ctx, token)
	if err != nil {
		return Unknown, err
	}
	if st != "" {
		return st, nil
	}

	// Rate-limited: honor Retry-After at most ONCE (Pitfall 3 — no loop).
	if retryAfter > 0 {
		if retryAfter > retryAfterCap {
			retryAfter = retryAfterCap
		}
		t := time.NewTimer(retryAfter)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return Unknown, sanitizedError{provider: "github", reason: reasonTimeout}
		case <-t.C:
		}
	}

	// Second (final) attempt.
	st2, _, err := g.doOnce(ctx, token)
	if err != nil {
		return Unknown, err
	}
	if st2 != "" {
		return st2, nil
	}
	// Still rate-limited or non-definitive — give up.
	return Unknown, sanitizedError{provider: "github", reason: reasonRateLimited}
}

// doOnce makes one GET /user request. It returns a definitive Status (Active/
// Inactive) when the response is conclusive, or "" with a non-zero retryAfter
// when the response is a rate-limit we may retry once. A non-rate-limit,
// non-definitive response (e.g. 5xx) returns Unknown directly.
func (g githubVerifier) doOnce(ctx context.Context, token string) (Status, time.Duration, error) {
	base := g.baseURL
	if base == "" {
		base = githubBaseURL
	}
	client := g.client
	if client == nil {
		client = http.DefaultClient
	}

	// Token is carried ONLY in the Authorization header below — never in the URL.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/user", nil)
	if err != nil {
		return "", 0, sanitizedError{provider: "github", reason: reasonAPIError}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", githubUserAgent)
	req.Header.Set("Accept", githubAccept)
	req.Header.Set("X-GitHub-Api-Version", githubAPIVersion)

	resp, err := client.Do(req)
	if err != nil {
		// Distinguish timeout/cancellation from other transport errors, but
		// NEVER wrap the underlying error (it can embed request context).
		if ctx.Err() != nil {
			return "", 0, sanitizedError{provider: "github", reason: reasonTimeout}
		}
		return "", 0, sanitizedError{provider: "github", reason: reasonNetwork}
	}
	defer resp.Body.Close()
	// Drain the body for keep-alive reuse; we do NOT decode the username.
	_, _ = io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		return Active, 0, nil
	case http.StatusUnauthorized:
		return Inactive, 0, nil
	case http.StatusForbidden, http.StatusTooManyRequests:
		// Rate-limited / secondary-limit: signal a possible single retry.
		return "", parseRetryAfter(resp.Header.Get("Retry-After")), nil
	default:
		// 5xx and anything else non-definitive → Unknown.
		return Unknown, 0, nil
	}
}

// parseRetryAfter parses a Retry-After delta-seconds header into a Duration.
// An empty or unparseable value returns 0 (treated as "no wait, but a retry is
// permitted once"). HTTP-date form is not honored (GitHub uses delta-seconds).
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		// No header but still a rate-limit response: permit one immediate retry.
		return time.Nanosecond
	}
	secs, err := strconv.Atoi(v)
	if err != nil || secs < 0 {
		return time.Nanosecond
	}
	if secs == 0 {
		// Retry-After: 0 → retry immediately (but still only once).
		return time.Nanosecond
	}
	return time.Duration(secs) * time.Second
}
