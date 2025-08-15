package bundle

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Source represents a source for downloading CA bundles
type Source struct {
	Name        string
	URL         string
	Primary     bool // Whether this is a primary source for validation
	Description string
}

// DefaultSources contains multiple CA bundle sources for cross-validation
var DefaultSources = []Source{
	{
		Name:        "Mozilla (curl.se)",
		URL:         "https://curl.se/ca/cacert.pem",
		Primary:     true,
		Description: "Mozilla's trusted CA bundle maintained by curl project",
	},
	{
		Name:        "Mozilla (raw.githubusercontent.com)",
		URL:         "https://raw.githubusercontent.com/bagder/ca-bundle/master/ca-bundle.crt",
		Primary:     false,
		Description: "Mozilla CA bundle from GitHub mirror",
	},
}

// DownloadAndValidate downloads CA bundles from multiple sources and cross-validates them
func DownloadAndValidate() (*x509.CertPool, string, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	var primaryBundle *x509.CertPool
	var primarySource string
	var bundleSizes []int
	var successfulSources []string

	// Download from all sources
	for _, source := range DefaultSources {
		resp, err := client.Get(source.URL)
		if err != nil {
			if source.Primary {
				return nil, "", fmt.Errorf("failed to download primary CA bundle from %s: %w", source.Name, err)
			}
			continue // Skip failed secondary sources
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			if source.Primary {
				return nil, "", fmt.Errorf("failed to download primary CA bundle from %s: HTTP %d", source.Name, resp.StatusCode)
			}
			continue
		}

		pemData, err := io.ReadAll(resp.Body)
		if err != nil {
			if source.Primary {
				return nil, "", fmt.Errorf("failed to read primary CA bundle from %s: %w", source.Name, err)
			}
			continue
		}

		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(pemData) {
			if source.Primary {
				return nil, "", fmt.Errorf("failed to parse primary CA bundle from %s", source.Name)
			}
			continue
		}

		bundleSize := len(certPool.Subjects())
		bundleSizes = append(bundleSizes, bundleSize)
		successfulSources = append(successfulSources, source.Name)

		if source.Primary {
			primaryBundle = certPool
			primarySource = source.Name
		}
	}

	if primaryBundle == nil {
		return nil, "", fmt.Errorf("failed to download primary CA bundle from any source")
	}

	// Cross-validate bundle sizes - they should be similar
	primarySize := len(primaryBundle.Subjects())
	for i, size := range bundleSizes {
		if i == 0 {
			continue // Skip primary
		}

		// Allow up to 10% variance in CA bundle sizes
		variance := float64(abs(size-primarySize)) / float64(primarySize)
		if variance > 0.10 {
			return nil, "", fmt.Errorf("CA bundle size mismatch detected: %s has %d CAs vs primary %d CAs (%.1f%% variance)",
				successfulSources[i], size, primarySize, variance*100)
		}
	}

	info := fmt.Sprintf("primary: %s, validated against %d sources", primarySource, len(successfulSources)-1)
	return primaryBundle, info, nil
}

// abs returns absolute value of integer
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
