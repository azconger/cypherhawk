package bundle

import (
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kaakaww/cypherhawk/internal/bundle/embedded"
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
	// Create HTTP client with proxy support for corporate environments
	client := createHTTPClient()
	if client == nil {
		return nil, "", fmt.Errorf("failed to create HTTP client")
	}

	var primaryBundle *x509.CertPool
	var primarySource string
	var bundleSizes []int
	var successfulSources []string

	// Download from all sources with retry logic
	for _, source := range DefaultSources {
		resp, err := downloadWithRetry(client, source)
		if err != nil {
			if source.Primary {
				return nil, "", enhanceBundleDownloadError(err, source)
			}
			continue // Skip failed secondary sources
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			if source.Primary {
				return nil, "", fmt.Errorf("failed to download primary CA bundle from %s: HTTP %d\n"+
					"Corporate network guidance:\n"+
					"  - Corporate proxy might be blocking access to %s\n"+
					"  - Try configuring HTTP_PROXY/HTTPS_PROXY environment variables\n"+
					"  - Contact IT support for external URL access permissions",
					source.Name, resp.StatusCode, source.URL)
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

		// Note: Subjects() is deprecated, but we only use it for validation
		// In the future, we could implement certificate counting differently
		bundleSize := len(certPool.Subjects()) //nolint:SA1019
		bundleSizes = append(bundleSizes, bundleSize)
		successfulSources = append(successfulSources, source.Name)

		if source.Primary {
			primaryBundle = certPool
			primarySource = source.Name
		}
	}

	if primaryBundle == nil {
		// Fall back to embedded CA bundle for offline/restricted environments
		return loadEmbeddedBundle()
	}

	// Cross-validate bundle sizes - they should be similar
	primarySize := len(primaryBundle.Subjects()) //nolint:SA1019
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

// createHTTPClient creates an HTTP client with corporate proxy support
func createHTTPClient() *http.Client {
	transport := &http.Transport{}

	// Configure proxy from environment variables
	if err := configureProxyForTransport(transport); err != nil {
		// Log error but continue - proxy configuration is optional
		return &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second, // Reduced timeout for faster test feedback
	}
}

// enhanceBundleDownloadError provides helpful error messages for CA bundle download failures
func enhanceBundleDownloadError(err error, source Source) error {
	errStr := err.Error()

	// DNS resolution failures
	if _, ok := err.(*net.DNSError); ok {
		return fmt.Errorf("failed to download CA bundle from %s: DNS resolution failed for %s\n"+
			"Corporate network guidance:\n"+
			"  - Corporate DNS might be blocking external lookups\n"+
			"  - %s is required for certificate validation\n"+
			"  - Contact IT support to allow access to certificate authority sources\n"+
			"  - Consider using embedded CA bundle backup if available",
			source.Name, source.URL, source.Description)
	}

	// Connection timeout
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return fmt.Errorf("failed to download CA bundle from %s: connection timeout\n"+
			"Corporate network guidance:\n"+
			"  - Corporate firewall might be blocking access to %s\n"+
			"  - Try setting HTTP_PROXY/HTTPS_PROXY environment variables\n"+
			"  - Contact IT support for proxy configuration\n"+
			"  - CA bundle download is required for certificate validation",
			source.Name, source.URL)
	}

	// Proxy-related errors
	if strings.Contains(errStr, "proxy") || strings.Contains(errStr, "407") {
		httpProxy := os.Getenv("HTTP_PROXY")
		httpsProxy := os.Getenv("HTTPS_PROXY")
		if httpProxy == "" {
			httpProxy = os.Getenv("http_proxy")
		}
		if httpsProxy == "" {
			httpsProxy = os.Getenv("https_proxy")
		}

		guidance := fmt.Sprintf("failed to download CA bundle from %s: proxy error\n"+
			"Corporate proxy guidance:\n"+
			"  - Your corporate proxy might require authentication for %s\n"+
			"  - Try configuring proxy with credentials: http://user:pass@proxy.corp.com:8080\n"+
			"  - Contact IT support for correct proxy settings\n", source.Name, source.URL)

		if httpProxy != "" || httpsProxy != "" {
			guidance += fmt.Sprintf("  - Current proxy settings: HTTP_PROXY=%s, HTTPS_PROXY=%s\n", httpProxy, httpsProxy)
		} else {
			guidance += "  - No proxy environment variables detected\n" +
				"  - Set HTTP_PROXY and/or HTTPS_PROXY environment variables\n"
		}

		return fmt.Errorf("%s\nOriginal error: %v", guidance, err)
	}

	// Generic network error
	return fmt.Errorf("failed to download CA bundle from %s: %v\n"+
		"Corporate network guidance:\n"+
		"  - Corporate firewall might be blocking access to %s\n"+
		"  - %s is required for certificate validation\n"+
		"  - Try configuring HTTP_PROXY/HTTPS_PROXY environment variables\n"+
		"  - Contact IT support for external URL access permissions",
		source.Name, err, source.URL, source.Description)
}

// loadEmbeddedBundle loads the embedded CA bundle as a fallback
func loadEmbeddedBundle() (*x509.CertPool, string, error) {
	pemData := embedded.GetEmbeddedCACerts()
	if len(pemData) == 0 {
		return nil, "", fmt.Errorf("embedded CA bundle is empty or missing\n" +
			"Corporate network guidance:\n" +
			"  - All external CA sources are blocked by corporate firewall\n" +
			"  - Embedded backup CA bundle is missing or corrupted\n" +
			"  - Contact IT support to allow access to certificate authority sources\n" +
			"  - Consider using corporate CA bundle if available")
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemData) {
		return nil, "", fmt.Errorf("failed to parse embedded CA bundle\n" +
			"Corporate network guidance:\n" +
			"  - Embedded CA bundle appears to be corrupted\n" +
			"  - This is likely a build-time issue\n" +
			"  - Please report this issue or rebuild from source")
	}

	// Note: Subjects() is deprecated, but we only use it for validation
	bundleSize := len(certPool.Subjects()) //nolint:SA1019
	info := fmt.Sprintf("embedded backup bundle (%d CAs) - external sources blocked", bundleSize)

	return certPool, info, nil
}

// downloadWithRetry attempts to download from a CA source with retry logic
func downloadWithRetry(client *http.Client, source Source) (*http.Response, error) {
	const maxRetries = 3
	const baseDelay = 2 * time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		resp, err := client.Get(source.URL)
		if err == nil {
			return resp, nil
		}

		// Don't retry for certain errors
		if isBundleNonRetryableError(err) {
			return nil, err
		}

		// If this was the last attempt, return the error
		if attempt == maxRetries {
			return nil, fmt.Errorf("failed after %d attempts: %v", maxRetries, err)
		}

		// Wait before retrying with exponential backoff
		delay := time.Duration(attempt) * baseDelay
		time.Sleep(delay)
	}

	return nil, fmt.Errorf("unexpected error in retry logic")
}

// isBundleNonRetryableError checks if a bundle download error should not be retried
func isBundleNonRetryableError(err error) bool {
	errStr := err.Error()

	// Don't retry DNS resolution errors
	if _, ok := err.(*net.DNSError); ok {
		return true
	}

	// Don't retry proxy authentication errors
	if strings.Contains(errStr, "407") {
		return true
	}

	// Don't retry connection refused
	if strings.Contains(errStr, "connection refused") {
		return true
	}

	// Retry timeouts and temporary network errors
	return false
}

// configureProxyForTransport configures HTTP proxy for the transport
func configureProxyForTransport(transport *http.Transport) error {
	// Check for HTTP_PROXY and HTTPS_PROXY environment variables
	httpProxy := os.Getenv("HTTP_PROXY")
	httpsProxy := os.Getenv("HTTPS_PROXY")

	// Also check lowercase versions (common in Unix environments)
	if httpProxy == "" {
		httpProxy = os.Getenv("http_proxy")
	}
	if httpsProxy == "" {
		httpsProxy = os.Getenv("https_proxy")
	}

	// If no proxy is configured, use default behavior
	if httpProxy == "" && httpsProxy == "" {
		return nil
	}

	// Create proxy function
	transport.Proxy = func(req *http.Request) (*url.URL, error) {
		var proxyURL string

		switch req.URL.Scheme {
		case "http":
			if httpProxy != "" {
				proxyURL = httpProxy
			}
		case "https":
			if httpsProxy != "" {
				proxyURL = httpsProxy
			} else if httpProxy != "" {
				// Fall back to HTTP_PROXY for HTTPS if HTTPS_PROXY not set
				proxyURL = httpProxy
			}
		}

		if proxyURL == "" {
			return nil, nil // No proxy
		}

		// Parse and validate proxy URL
		proxy, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL %s: %v", proxyURL, err)
		}

		return proxy, nil
	}

	return nil
}
