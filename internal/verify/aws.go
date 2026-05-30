package verify

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/MatrixMagician/mimir/internal/finding"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithy "github.com/aws/smithy-go"
)

// awsVerifier verifies a detected AWS access-key ID by calling STS
// GetCallerIdentity with the access key and its co-located secret access key.
//
// SECURITY (Pitfall 2): the STS client is built DIRECTLY from the passed static
// credentials via sts.New(sts.Options{...}) — this verifier NEVER calls
// config.LoadDefaultConfig, so ambient AWS_* env / shared profiles / IMDS can
// never influence the result and produce a false "active".
type awsVerifier struct{}

func (awsVerifier) Provider() string { return "aws" }

// stsGlobalEndpoint pins the call to the global STS endpoint so no region/
// endpoint resolution touches ambient config (A1: most explicit ambient-free
// form).
const stsGlobalEndpoint = "https://sts.amazonaws.com"

// awsRegion is a non-empty region required by SigV4 signing; "aws-global" is
// the global pseudo-region matching the global STS endpoint.
const awsRegion = "aws-global"

// definitiveRejectCodes are STS/SigV4 error codes that mean the credential is
// conclusively not usable. Any code outside this set (throttling, transient,
// unrecognized) yields Unknown, never Inactive.
var definitiveRejectCodes = map[string]struct{}{
	"InvalidClientTokenId":      {},
	"SignatureDoesNotMatch":     {},
	"ExpiredToken":              {},
	"AccessDenied":              {},
	"InvalidSignatureException": {},
}

// maxPairingReadBytes caps how much of the finding's file is read when pairing
// the access key with its secret key (RESEARCH V5: avoid loading huge files).
const maxPairingReadBytes = 1 << 20 // 1 MiB

// secretKeyRE matches a 40-char AWS secret access key (base64 alphabet without
// padding) as a WHOLE token. RE2 / linear-time, consistent with the engine's
// allowlist discipline.
//
// WR-06: the boundary guards (?:^|[^A-Za-z0-9/+]) and (?:[^A-Za-z0-9/+]|$) stop
// a 40-char prefix of a LONGER base64 blob (e.g. a 60-char hash) from being
// sliced out as a spurious candidate — FindAllStringSubmatch returns the inner
// capture group (group 1), the true 40-char token only. This narrows the
// candidate set and compounds the WR-02 false-inactive mitigation.
var secretKeyRE = regexp.MustCompile(`(?:^|[^A-Za-z0-9/+])([A-Za-z0-9/+]{40})(?:[^A-Za-z0-9/+]|$)`)

// secretKeyHintRE marks lines that look like a secret-key assignment, used to
// prefer the nearest candidate when several 40-char tokens exist.
var secretKeyHintRE = regexp.MustCompile(`(?i)(aws.{0,20}secret|secret_access_key|secretaccesskey)`)

// Verify pairs the access key with a co-located secret key, then calls STS.
// If no secret key is found, the result is Unknown (Pitfall 7) and no network
// call is made. All error paths are sanitized — the secret never leaks.
//
// CR-02: f.File is a repo-relative, forward-slash path (built in scanner.go via
// filepath.Rel(scanRoot, ...)). It is resolved against scanRoot — NOT the
// process CWD — so pairing works regardless of the directory mimir is run from.
// For --git/--staged findings the joined path has no on-disk counterpart;
// findSecretKey's os.ReadFile then fails and returns ("", false), so the result
// degrades gracefully to Unknown with no network call (never a false inactive).
func (awsVerifier) Verify(ctx context.Context, scanRoot, raw string, f finding.Finding) Status {
	secretKey, ok := findSecretKey(filepath.Join(scanRoot, filepath.FromSlash(f.File)))
	if !ok {
		// Cannot call STS without the pair; never claim inactive.
		return Unknown
	}

	client := sts.New(sts.Options{
		Region:       awsRegion,
		BaseEndpoint: aws.String(stsGlobalEndpoint),
		Credentials:  aws.NewCredentialsCache(staticProviderFor(raw, secretKey)),
	})

	_, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	return classifyAWSError(err)
}

// staticProviderFor returns a static-credentials provider seeded ONLY with the
// passed access key and secret key. It is the verifier's sole credential source;
// no ambient resolution is possible.
func staticProviderFor(accessKeyID, secretKey string) credentials.StaticCredentialsProvider {
	return credentials.NewStaticCredentialsProvider(accessKeyID, secretKey, "")
}

// classifyAWSError maps a GetCallerIdentity result to a three-state Status. It
// is a pure function (no network, no env) so the classification table is unit-
// testable in isolation. nil → Active; a smithy.APIError with a definitive
// reject code → Inactive; everything else (network, timeout, throttling,
// unrecognized code) → Unknown.
func classifyAWSError(err error) Status {
	if err == nil {
		return Active
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		if _, reject := definitiveRejectCodes[apiErr.ErrorCode()]; reject {
			return Inactive
		}
	}
	// Network failures, timeouts, throttling, and any unrecognized code are
	// non-definitive: never claim inactive on these.
	return Unknown
}

// findSecretKey best-effort scans the finding's file for a 40-char base64 AWS
// secret access key co-located with a secret-key hint. If several candidates
// exist it prefers the one nearest a hint line. Returns ("", false) when none
// is found — the caller then yields Unknown. The file read is size-capped and
// the returned value is used ONLY transiently; it is never logged or stored.
func findSecretKey(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	if len(data) > maxPairingReadBytes {
		data = data[:maxPairingReadBytes]
	}

	lines := strings.Split(string(data), "\n")

	type candidate struct {
		value string
		line  int
	}
	var candidates []candidate
	hintLines := []int{}
	for i, line := range lines {
		if secretKeyHintRE.MatchString(line) {
			hintLines = append(hintLines, i)
		}
		// WR-06: take capture group 1 — the bounded 40-char token — never the
		// whole match (which includes a leading/trailing boundary byte).
		for _, m := range secretKeyRE.FindAllStringSubmatch(line, -1) {
			candidates = append(candidates, candidate{value: m[1], line: i})
		}
	}
	if len(candidates) == 0 {
		return "", false
	}

	// WR-02: require a secret-key HINT line to pair. Without a hint, the file's
	// first 40-char base64 token is just as likely to be a hash/JWT segment/
	// vendored blob as a real secret key; pairing it would send the wrong
	// secret to STS, yield SignatureDoesNotMatch (a definitive reject), and
	// report a genuinely-live access key as INACTIVE — a false negative on the
	// highest-severity outcome. Returning ("", false) here yields Unknown
	// instead, which is the correct three-state answer when we cannot
	// confidently identify the pair.
	if len(hintLines) == 0 {
		return "", false
	}
	best := candidates[0]
	bestDist := lineDistance(best.line, hintLines)
	for _, c := range candidates[1:] {
		if d := lineDistance(c.line, hintLines); d < bestDist {
			best, bestDist = c, d
		}
	}
	return best.value, true
}

// lineDistance returns the minimum absolute distance from line to any hint line.
func lineDistance(line int, hints []int) int {
	best := 1 << 30
	for _, h := range hints {
		d := line - h
		if d < 0 {
			d = -d
		}
		if d < best {
			best = d
		}
	}
	return best
}
