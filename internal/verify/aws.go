package verify

import (
	"context"

	"github.com/MatrixMagician/mimir/internal/finding"
)

// awsVerifier verifies AWS access keys. Full implementation in Task 2.
type awsVerifier struct{}

func (awsVerifier) Provider() string { return "aws" }

func (awsVerifier) Verify(ctx context.Context, raw string, f finding.Finding) Status {
	return Unknown
}
