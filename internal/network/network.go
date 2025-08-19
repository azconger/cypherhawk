package network

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// GetCertificateChain connects to an endpoint and extracts the certificate chain
// with retry logic for corporate networks
func GetCertificateChain(targetURL string) ([]*x509.Certificate, error) {
	const maxRetries = 3
	const baseDelay = 2 * time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		certs, err := getCertificateChainAttempt(targetURL)
		if err == nil {
			return certs, nil
		}

		// Don't retry for certain errors
		if isNonRetryableError(err) {
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

// getCertificateChainAttempt performs a single attempt to get certificates
func getCertificateChainAttempt(targetURL string) ([]*x509.Certificate, error) {
	// Create HTTP transport with corporate proxy support
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	// Configure HTTP proxy support from environment variables
	if err := configureProxy(tr); err != nil {
		return nil, fmt.Errorf("proxy configuration error: %v", err)
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   45 * time.Second, // Increased timeout for corporate networks
	}

	resp, err := client.Get(targetURL)
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
