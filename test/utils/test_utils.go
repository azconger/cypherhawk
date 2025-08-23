package testutils

import (
	"os"
	"testing"
)

// ClearProxyEnvironment clears all proxy environment variables to ensure clean network access
func ClearProxyEnvironment(t *testing.T) func() {
	// Store original values and whether they were set
	type envVar struct {
		value  string
		wasSet bool
	}

	originalVars := map[string]envVar{
		"HTTP_PROXY":  {os.Getenv("HTTP_PROXY"), envVarExists("HTTP_PROXY")},
		"HTTPS_PROXY": {os.Getenv("HTTPS_PROXY"), envVarExists("HTTPS_PROXY")},
		"http_proxy":  {os.Getenv("http_proxy"), envVarExists("http_proxy")},
		"https_proxy": {os.Getenv("https_proxy"), envVarExists("https_proxy")},
		"FTP_PROXY":   {os.Getenv("FTP_PROXY"), envVarExists("FTP_PROXY")},
		"ftp_proxy":   {os.Getenv("ftp_proxy"), envVarExists("ftp_proxy")},
		"NO_PROXY":    {os.Getenv("NO_PROXY"), envVarExists("NO_PROXY")},
		"no_proxy":    {os.Getenv("no_proxy"), envVarExists("no_proxy")},
	}

	// Clear all proxy variables
	for key := range originalVars {
		os.Unsetenv(key)
	}

	// Log cleanup for debugging
	t.Logf("Cleared all proxy environment variables for clean network testing")

	// Return cleanup function
	return func() {
		for key, original := range originalVars {
			if original.wasSet {
				os.Setenv(key, original.value)
			} else {
				os.Unsetenv(key)
			}
		}
		t.Logf("Restored original proxy environment variables")
	}
}

// envVarExists checks if an environment variable is actually set (not just empty)
func envVarExists(key string) bool {
	_, exists := os.LookupEnv(key)
	return exists
}

// IsNetworkTestSkipped returns true if network tests should be skipped
func IsNetworkTestSkipped() bool {
	return os.Getenv("CYPHERHAWK_SKIP_NETWORK_TESTS") == "1"
}
