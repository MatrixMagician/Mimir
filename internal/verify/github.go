package verify

import (
	"context"

	"github.com/MatrixMagician/mimir/internal/finding"
)

// githubVerifier verifies GitHub tokens. Full implementation in Task 3.
type githubVerifier struct{}

func (githubVerifier) Provider() string { return "github" }

func (githubVerifier) Verify(ctx context.Context, raw string, f finding.Finding) Status {
	return Unknown
}
