package src

// scopedKeys places two secrets matching two different rules on one line. The
// SCOPED inline directive `mimir:ignore:aws-access-token` suppresses ONLY the
// aws-access-token finding; the github-pat finding on the same line must still
// be reported. Exercised by Plan 02's scoped-vs-blanket tests.
const scopedKeys = "AKIAFAKEKEYABCDE2345 ghp_FakeGitHubToken123456789012345678901" // mimir:ignore:aws-access-token
