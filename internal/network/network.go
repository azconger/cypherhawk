package network

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
)

// GetCertificateChain connects to an endpoint and extracts the certificate chain
// with enhanced retry logic for corporate networks
func GetCertificateChain(targetURL string) ([]*x509.Certificate, error) {
	return GetCertificateChainWithConfig(targetURL, DefaultNetworkConfig())
}

// GetCertificateChainWithConfig allows custom network configuration
func GetCertificateChainWithConfig(targetURL string, config NetworkConfig) ([]*x509.Certificate, error) {
	client, err := createRetryableHTTPClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	return getCertificateChainWithRetryableClient(client, targetURL)
}

// NetworkConfig allows customization of network behavior
type NetworkConfig struct {
	MaxRetries          int
	BaseDelay           time.Duration
	ConnectTimeout      time.Duration
	TLSHandshakeTimeout time.Duration
	ClientTimeout       time.Duration
}

// DefaultNetworkConfig returns the default network configuration
func DefaultNetworkConfig() NetworkConfig {
	return NetworkConfig{
		MaxRetries:          3,
		BaseDelay:           2 * time.Second,
		ConnectTimeout:      5 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
		ClientTimeout:       10 * time.Second,
	}
}

// FastNetworkConfig returns a configuration optimized for fast timeouts (useful for testing)
func FastNetworkConfig() NetworkConfig {
	return NetworkConfig{
		MaxRetries:          2,
		BaseDelay:           1 * time.Second,
		ConnectTimeout:      2 * time.Second,
		TLSHandshakeTimeout: 2 * time.Second,
		ClientTimeout:       3 * time.Second,
	}
}

// createRetryableHTTPClient creates a retryable HTTP client with corporate proxy support
func createRetryableHTTPClient(config NetworkConfig) (*retryablehttp.Client, error) {
	// Create base transport with TLS configuration
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Required to capture all certificate chains
		},
		DialContext: (&net.Dialer{
			Timeout:   config.ConnectTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   config.TLSHandshakeTimeout,
		ResponseHeaderTimeout: config.ClientTimeout,
	}

	// Configure HTTP proxy support from environment variables
	if err := configureProxy(tr); err != nil {
		return nil, fmt.Errorf("proxy configuration error: %w", err)
	}

	// Create retryable HTTP client
	client := retryablehttp.NewClient()
	client.HTTPClient.Transport = tr
	client.HTTPClient.Timeout = config.ClientTimeout
	client.RetryMax = config.MaxRetries - 1 // retryablehttp counts initial attempt
	client.RetryWaitMin = config.BaseDelay
	client.RetryWaitMax = config.BaseDelay * 4 // Max backoff
	client.Logger = slog.Default()             // Use structured logging

	// Custom retry policy for certificate extraction
	client.CheckRetry = func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		if err != nil {
			// Don't retry certain errors that are what we want to capture
			if isNonRetryableError(err) {
				return false, nil
			}
		}

		// Use default retry logic for other cases
		return retryablehttp.DefaultRetryPolicy(ctx, resp, err)
	}

	return client, nil
}

// getCertificateChainWithRetryableClient extracts certificates using retryable client
func getCertificateChainWithRetryableClient(client *retryablehttp.Client, targetURL string) ([]*x509.Certificate, error) {
	req, err := retryablehttp.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, enhanceNetworkError(err, targetURL)
	}
	defer resp.Body.Close()

	// Extract certificates from TLS connection state
	if resp.TLS == nil {
		return nil, fmt.Errorf("no TLS connection established")
	}

	return resp.TLS.PeerCertificates, nil
}

// configureProxy configures HTTP proxy support from environment variables
func configureProxy(transport *http.Transport) error {
	// Use Go's built-in proxy detection first
	transport.Proxy = http.ProxyFromEnvironment
	return nil
}

// enhanceNetworkError provides helpful error messages with corporate network guidance
func enhanceNetworkError(err error, targetURL string) error {
	errStr := err.Error()

	// DNS resolution failures
	if dnsErr, ok := err.(*net.DNSError); ok {
		if dnsErr.IsTimeout {
			return fmt.Errorf("DNS resolution timeout for %s\n"+
				"Corporate network guidance:\n"+
				"  - Your corporate DNS might be blocking external lookups\n"+
				"  - Try using internal DNS servers or contact IT support\n"+
				"  - For internal URLs, ensure you're connected to the corporate VPN",
				targetURL)
		}
		return fmt.Errorf("DNS resolution failed for %s: %v\n"+
			"Corporate network guidance:\n"+
			"  - Domain might not exist or be blocked by corporate DNS\n"+
			"  - For internal URLs, ensure you're connected to the corporate network\n"+
			"  - Check if the URL requires VPN access",
			targetURL, dnsErr)
	}

	// Connection timeout
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return fmt.Errorf("connection timeout to %s\n"+
			"Corporate network guidance:\n"+
			"  - Corporate firewall might be blocking the connection\n"+
			"  - Try setting HTTP_PROXY/HTTPS_PROXY environment variables\n"+
			"  - Contact IT support for proxy configuration\n"+
			"  - Example: export HTTPS_PROXY=http://proxy.corp.com:8080",
			targetURL)
	}

	// Connection refused
	if strings.Contains(errStr, "connection refused") {
		return fmt.Errorf("connection refused to %s\n"+
			"Corporate network guidance:\n"+
			"  - Service might be down or blocked by corporate firewall\n"+
			"  - For internal services, ensure you're on the corporate network\n"+
			"  - Check if the service requires VPN access",
			targetURL)
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

		guidance := "Corporate proxy guidance:\n" +
			"  - Your corporate proxy might require authentication\n" +
			"  - Try configuring proxy with credentials: http://user:pass@proxy.corp.com:8080\n" +
			"  - Contact IT support for correct proxy settings\n"

		if httpProxy != "" || httpsProxy != "" {
			guidance += fmt.Sprintf("  - Current proxy settings: HTTP_PROXY=%s, HTTPS_PROXY=%s\n", httpProxy, httpsProxy)
		} else {
			guidance += "  - No proxy environment variables detected\n" +
				"  - Set HTTP_PROXY and/or HTTPS_PROXY environment variables\n"
		}

		return fmt.Errorf("proxy error for %s: %v\n%s", targetURL, err, guidance)
	}

	// TLS/Certificate errors
	if strings.Contains(errStr, "tls") || strings.Contains(errStr, "certificate") || strings.Contains(errStr, "x509") {
		return fmt.Errorf("TLS connection error to %s: %v\n"+
			"Corporate network guidance:\n"+
			"  - This might indicate corporate DPI/MitM is active\n"+
			"  - Use CypherHawk to extract corporate CA certificates\n"+
			"  - The detected certificates can then be added to your Java trust store",
			targetURL, err)
	}

	// Generic network error with corporate guidance
	return fmt.Errorf("network error connecting to %s: %v\n"+
		"Corporate network guidance:\n"+
		"  - Check if you're connected to the corporate network/VPN\n"+
		"  - Corporate firewall might be blocking the connection\n"+
		"  - Try configuring HTTP_PROXY/HTTPS_PROXY environment variables\n"+
		"  - Contact IT support if issues persist",
		targetURL, err)
}

// isNonRetryableError checks if an error should not be retried
func isNonRetryableError(err error) bool {
	errStr := err.Error()

	// Don't retry DNS resolution errors (unlikely to resolve quickly)
	if _, ok := err.(*net.DNSError); ok {
		return true
	}

	// Don't retry TLS certificate verification errors (those are what we want to capture)
	if strings.Contains(errStr, "certificate") || strings.Contains(errStr, "x509") {
		return true
	}

	// Don't retry connection refused (service likely down)
	if strings.Contains(errStr, "connection refused") {
		return true
	}

	// Don't retry proxy authentication errors
	if strings.Contains(errStr, "407") {
		return true
	}

	// Retry timeouts and temporary network errors
	return false
}
