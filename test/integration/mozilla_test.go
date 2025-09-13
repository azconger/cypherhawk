package integration_test

import (
	"testing"

	"github.com/kaakaww/cypherhawk/internal/bundle"
	testutils "github.com/kaakaww/cypherhawk/test/utils"
)

// TestMozillaCABundleDownload tests Mozilla CA bundle download with clean environment
func TestMozillaCABundleDownload(t *testing.T) {
	// This test verifies that Mozilla CA bundle download works when not in corporate network
	// Skip if network tests are disabled
	if testutils.IsNetworkTestSkipped() {
		t.Skip("Skipping network-dependent test in fast mode")
	}

	// Clear any proxy settings that might interfere from previous tests
	cleanup := testutils.ClearProxyEnvironment(t)
	defer cleanup()

	// Test Mozilla CA bundle download
	mozillaCAs, info, err := bundle.DownloadAndValidate()
	if err != nil {
		t.Logf("Mozilla CA bundle download failed: %v", err)
		t.Logf("This may be expected in corporate environments with restrictive firewalls")
		t.Skip("Mozilla CA bundle download failed - may be corporate network restriction")
	}

	// Verify we got a reasonable number of CAs
	subjects := mozillaCAs.Subjects()
	if len(subjects) < 100 {
		t.Errorf("Expected at least 100 CA certificates, got %d", len(subjects))
	}

	t.Logf("✅ Successfully downloaded Mozilla CA bundle: %s", info)
	t.Logf("   CA certificates: %d", len(subjects))
}
