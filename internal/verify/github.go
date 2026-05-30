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
func (g githubVerifier) Verify(ctx context.Context, scanRoot, raw string, f finding.Finding) Status {
	// scanRoot is unused: the GitHub verifier needs no filesystem access — the
	// token is self-contained and sent in the Authorization header.
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
	case http.StatusTooManyRequests:
		// Primary rate-limit: signal a possible single retry.
		return "", parseRetryAfter(resp.Header.Get("Retry-After")), nil
	case http.StatusForbidden:
		// WR-05: GitHub returns 403 for many non-rate-limit reasons (missing
		// scope, SAML enforcement, IP allowlist). Only a 403 that carries a
		// rate-limit signal — a Retry-After header or X-RateLimit-Remaining: 0 —
		// is a secondary rate-limit worth a single retry. A 403 with no such
		// signal is non-definitive (the token may well be valid but the endpoint
		// forbidden); classify it Unknown directly, without burning a retry.
		if isRateLimited403(resp.Header) {
			return "", parseRetryAfter(resp.Header.Get("Retry-After")), nil
		}
		return Unknown, 0, nil
	default:
		// 5xx and anything else non-definitive → Unknown.
		return Unknown, 0, nil
	}
}

// isRateLimited403 reports whether a 403 response carries a secondary-rate-limit
// signal: a Retry-After header, or X-RateLimit-Remaining: 0 (WR-05).
func isRateLimited403(h http.Header) bool {
	if h.Get("Retry-After") != "" {
		return true
	}
	if h.Get("X-RateLimit-Remaining") == "0" {
		return true
	}
	return false
}

// parseRetryAfter parses a Retry-After header into a Duration. RFC 7231 permits
// two forms: delta-seconds (the common GitHub case) and an HTTP-date (WR-04).
//
//   - empty header  → one immediate retry (rate-limit response with no hint).
//   - delta-seconds → that many seconds (0 ⇒ immediate retry).
//   - HTTP-date     → the wait until that instant.
//   - unparseable / a date in the past → wait the cap, NOT an immediate retry,
//     so a server that asked us to back off is not effectively ignored.
//
// The returned value is always clamped to retryAfterCap by the caller, so a
// hostile/large value cannot stall the run beyond the per-call budget.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		// No header but still a rate-limit response: permit one immediate retry.
		return time.Nanosecond
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs <= 0 {
			// Retry-After: 0 (or negative) → retry immediately (but still once).
			return time.Nanosecond
		}
		return time.Duration(secs) * time.Second
	}
	// Not delta-seconds — try the HTTP-date form (RFC 7231).
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
		// A date at/in the past → retry immediately.
		return time.Nanosecond
	}
	// Unparseable: the server asked us to wait but we cannot tell how long.
	// Back off the full cap rather than hammering it with an immediate retry.
	return retryAfterCap
}
