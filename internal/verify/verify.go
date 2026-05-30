// Package verify performs opt-in live verification of detected AWS and GitHub
// credentials, labelling each verifiable finding active / inactive / unknown.
//
// SECURITY: This package is the network boundary. It makes read-only API calls
// (AWS STS GetCallerIdentity, GitHub GET /user) using OTHER PEOPLE'S
// credentials, so it observes a strict no-leak discipline:
//
//   - The raw secret value is used ONLY transiently to make the call. It is
//     never logged, never stored on a Finding, and never placed in an error.
//   - Every SDK / HTTP error is reduced to a sanitizedError{provider, reason}
//     carrying only a provider name and a reason enum. SDK/HTTP errors are
//     NEVER wrapped with %w/%v, because they can embed request context that may
//     include the token.
//   - The AWS verifier constructs its STS client directly from the passed
//     static credentials and NEVER reads ambient AWS_* env / profile / IMDS
//     (no config.LoadDefaultConfig), so an operator's own credentials can never
//     produce a false "active" result.
package verify

import (
	"context"
	"sync"
	"time"

	"github.com/MatrixMagician/mimir/internal/finding"
	"golang.org/x/sync/errgroup"
)

// perCallTimeout bounds each individual verification call (CONTEXT decision: 5s
// default for v1).
const perCallTimeout = 5 * time.Second

// concurrencyLimit bounds the verification worker pool so we never hammer a
// provider's API (CONTEXT decision: ~5).
const concurrencyLimit = 5

// cacheKey deduplicates verification per (provider, secret): the SAME string
// value under two different providers never shares a result (RESEARCH Open
// Question 3).
type cacheKey struct {
	provider string
	secret   string
}

// Run performs opt-in live verification over the reportable finding set,
// labelling each finding whose rule ID has a registered verifier. It is the
// public entry point used by the scan pipeline.
//
// For each verifiable finding it resolves the raw secret from the off-struct
// side channel (rawByFP, keyed by fingerprint), verifies each distinct
// (provider, secret) at most once under a bounded worker pool with a per-call
// timeout, and writes findings[i].Verification in place. Findings whose rule ID
// has no verifier are left unlabeled (Verification stays nil). A missing/empty
// raw secret yields Unknown. Run NEVER returns an error and NEVER aborts the
// scan — verification is label-only.
//
// scanRoot is the directory the scan targeted (cmd/mimir resolveScanRoot). It is
// threaded to the verifiers so the AWS pairing can resolve a finding's
// repo-relative File against the actual scan root rather than the process CWD
// (CR-02). For --git/--staged findings — whose File has no on-disk counterpart —
// the verifier degrades gracefully to Unknown.
func Run(ctx context.Context, scanRoot string, findings []finding.Finding, rawByFP map[string]string) {
	runWithRegistry(ctx, registry, scanRoot, findings, rawByFP)
}

// runWithRegistry is the testable core of Run, accepting an explicit registry so
// unit tests can inject fake verifiers.
func runWithRegistry(ctx context.Context, reg map[string]Verifier, scanRoot string, findings []finding.Finding, rawByFP map[string]string) {
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(concurrencyLimit)

	// cacheEntry holds an in-flight reservation: the FIRST worker to reserve a
	// (provider, secret) computes the status; all others block on done and read
	// the shared result. This guarantees each distinct (provider, secret) is
	// verified at most once even under the worker pool.
	type cacheEntry struct {
		done   chan struct{}
		status Status
	}
	var mu sync.Mutex
	cache := map[cacheKey]*cacheEntry{}

	for i := range findings {
		// IN-02: f is a deliberate value copy of the finding, captured by the
		// g.Go closure below and handed to v.Verify; the whole struct is kept
		// available so future verifiers can read fields beyond f.File.
		f := findings[i]

		v, ok := reg[f.RuleID]
		if !ok {
			// No verifier for this rule ID — leave the finding unlabeled.
			continue
		}
		provider := v.Provider()

		raw, hasRaw := rawByFP[f.Fingerprint]
		if !hasRaw || raw == "" {
			// Matched rule but no raw secret available → cannot call; Unknown.
			findings[i].Verification = &finding.Verification{
				Status:   string(Unknown),
				Provider: provider,
			}
			continue
		}

		key := cacheKey{provider: provider, secret: raw}

		g.Go(func() error {
			mu.Lock()
			entry, exists := cache[key]
			if exists {
				// Another worker owns this (provider, secret); wait for it.
				mu.Unlock()
				<-entry.done
			} else {
				// We own the verification for this key.
				entry = &cacheEntry{done: make(chan struct{})}
				cache[key] = entry
				mu.Unlock()

				// CR-01: close(entry.done) MUST run unconditionally. If
				// v.Verify panics (an SDK bug on adversarial input, a future
				// verifier, a malformed pairing edge), a bare close after the
				// call would be skipped — every waiter on this key would block
				// on <-entry.done forever and g.Wait() would never return,
				// hanging the entire scan. A recover() classifies the
				// panicking secret as Unknown (the three-state never-fail-the-
				// scan contract) and guarantees the cache holds a result before
				// the channel is closed, so waiters read Unknown, not a deadlock.
				func() {
					defer close(entry.done)
					defer func() {
						if r := recover(); r != nil {
							entry.status = Unknown
						}
					}()
					callCtx, cancel := context.WithTimeout(ctx, perCallTimeout)
					defer cancel()
					entry.status = v.Verify(callCtx, scanRoot, raw, f)
				}()
			}

			findings[i].Verification = &finding.Verification{
				Status:   string(entry.status),
				Provider: provider,
			}
			return nil
		})
	}

	// g.Wait()'s error is intentionally ignored: verification is label-only and
	// must never error the scan.
	_ = g.Wait()
}

// Status is the three-state verification outcome recorded on a finding.
type Status string

const (
	// Active means the credential was confirmed live by the provider.
	Active Status = "active"
	// Inactive means the provider definitively rejected the credential
	// (e.g. invalid token, expired, signature mismatch).
	Inactive Status = "inactive"
	// Unknown means the result could not be determined: a network error, a
	// timeout, a rate-limit, a throttle, a missing credential pair, or any
	// non-definitive provider response. A network failure is ALWAYS unknown,
	// never inactive.
	Unknown Status = "unknown"
)

// Verifier checks whether a single detected secret is live for one provider.
//
// Verify must never return an error that contains the secret; on any failure it
// returns Unknown and (where it surfaces an error for logging) a sanitizedError.
// Implementations are stateless after construction and safe for concurrent use.
type Verifier interface {
	// Provider returns the stable provider name ("aws" | "github") recorded on
	// the finding's Verification.Provider.
	Provider() string
	// Verify makes the read-only provider call for raw (the secret carried via
	// the Plan 01 side channel) in the context of finding f, returning one of
	// the three Status values. It must honor ctx's deadline/cancellation.
	//
	// scanRoot is the directory the scan targeted; the AWS verifier joins it
	// with f.File (a repo-relative path) to locate the on-disk file holding the
	// co-located secret key (CR-02). Verifiers that need no filesystem access
	// (GitHub) ignore it.
	Verify(ctx context.Context, scanRoot, raw string, f finding.Finding) Status
}

// registry maps detection rule IDs to the verifier that can check them. Only
// the six AWS/GitHub rule IDs are present; findings produced by any other rule
// have no entry and are left unlabeled (status omitted), per the phase
// decision. The rule IDs mirror config/mimir.toml.
var registry = map[string]Verifier{
	"aws-access-token":        awsVerifier{},
	"github-pat":              githubVerifier{},
	"github-oauth":            githubVerifier{},
	"github-app-token":        githubVerifier{},
	"github-refresh-token":    githubVerifier{},
	"github-fine-grained-pat": githubVerifier{},
}

// reason is an enum-like classification of why a verification could not confirm
// a credential. It is the ONLY free-form-ish value carried out of the network
// boundary, and it is a fixed vocabulary — never an SDK/HTTP error string, never
// the secret.
type reason string

const (
	// reasonAPIError: the provider returned an error response we treat as a
	// definitive rejection or an opaque API failure.
	reasonAPIError reason = "api_error"
	// reasonNetwork: transport-level failure (connection refused, DNS, TLS).
	reasonNetwork reason = "network_error"
	// reasonTimeout: the per-call context deadline elapsed.
	reasonTimeout reason = "timeout"
	// reasonRateLimited: the provider rate-limited us (429 / 403 secondary).
	reasonRateLimited reason = "rate_limited"
	// reasonNoSecretKey: AWS — no co-located secret access key was found, so no
	// call could be made.
	reasonNoSecretKey reason = "no_secret_key"
)

// sanitizedError carries ONLY a provider name and a reason enum. It deliberately
// has no field that could hold a secret or a wrapped SDK/HTTP error. Verifiers
// return it (instead of the raw provider error) so the secret can never leak via
// an error string or a log line.
type sanitizedError struct {
	provider string
	reason   reason
}

func (e sanitizedError) Error() string {
	return e.provider + ": " + string(e.reason)
}
