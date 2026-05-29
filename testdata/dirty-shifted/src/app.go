package src

// Config holds runtime configuration for the dirty fixture app.
type Config struct {
	Region    string
	AccessKey string
}

// load returns a config carrying a (fake) leaked AWS access key so Mimir
// produces a deterministic finding + fingerprint for the Phase 2 suppression
// and criterion-4 stability tests. The value is reused verbatim from
// testdata/fixtures/known-secrets.txt — it is NOT a real credential.
func load() Config {
	return Config{
		Region:    "us-east-1",



		AccessKey: "AKIAFAKEKEYABCDE2345",
	}
}
