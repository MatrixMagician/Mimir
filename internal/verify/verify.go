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

	"github.com/MatrixMagician/mimir/internal/finding"
)

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
	Verify(ctx context.Context, raw string, f finding.Finding) Status
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
