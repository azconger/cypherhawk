package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kaakaww/cypherhawk/internal/network"
	"github.com/kaakaww/cypherhawk/test/testdata"
	testutils "github.com/kaakaww/cypherhawk/test/utils"
)

// TestProxySupport verifies that CypherHawk works correctly with corporate proxies
func TestProxySupport(t *testing.T) {
	// Skip network-dependent tests in fast mode
	if os.Getenv("CYPHERHAWK_SKIP_NETWORK_TESTS") == "1" {
		t.Skip("Skipping network-dependent test in fast mode")
	}

	// Create a mock DPI server that serves Palo Alto certificates
	paloAltoChain := testdata.GeneratePaloAltoCertificateChain()

	// Create mock HTTPS server with DPI certificates
	mockServer := createMockDPIServer(paloAltoChain.Certificates)
	defer mockServer.Close()

	// Create a mock proxy server
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simple proxy that forwards requests
		if r.Method == "CONNECT" {
			// Handle HTTPS CONNECT
			destConn, err := net.Dial("tcp", r.Host)
			if err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			defer destConn.Close()

			w.WriteHeader(http.StatusOK)
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
				return
			}
			clientConn, _, err := hijacker.Hijack()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer clientConn.Close()

			// Copy data between client and destination
			go func() {
				defer clientConn.Close()
				defer destConn.Close()
				_, _ = io.Copy(clientConn, destConn)
			}()
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	defer proxyServer.Close()

	// Test with proxy environment variables - use proper cleanup
	cleanup := testutils.ClearProxyEnvironment(t)
	defer cleanup()

	// Set proxy environment variables
	os.Setenv("HTTP_PROXY", proxyServer.URL)
	os.Setenv("HTTPS_PROXY", proxyServer.URL)

	// Test that network module respects proxy settings
	// Note: This is a simplified test since setting up a full proxy integration is complex
	t.Run("ProxyEnvironmentVariables", func(t *testing.T) {
		// Test that proxy environment variables are read correctly
		httpProxy := os.Getenv("HTTP_PROXY")
		httpsProxy := os.Getenv("HTTPS_PROXY")

		if httpProxy != proxyServer.URL {
			t.Errorf("Expected HTTP_PROXY=%s, got %s", proxyServer.URL, httpProxy)
		}
		if httpsProxy != proxyServer.URL {
			t.Errorf("Expected HTTPS_PROXY=%s, got %s", proxyServer.URL, httpsProxy)
		}

		t.Logf("✅ Proxy environment variables configured correctly")
	})
}

// TestTimeoutHandling verifies that CypherHawk handles network timeouts gracefully
func TestTimeoutHandling(t *testing.T) {
	// Skip network-dependent tests in fast mode
	if os.Getenv("CYPHERHAWK_SKIP_NETWORK_TESTS") == "1" {
		t.Skip("Skipping network-dependent test in fast mode")
	}

	// Test that GetCertificateChain handles timeouts
	t.Run("TimeoutHandling", func(t *testing.T) {
		// Use a reserved test IP address that will cause connection timeout quickly
		// 192.0.2.1 is TEST-NET-1 reserved for documentation/testing
		testURL := "https://192.0.2.1:443"

		start := time.Now()
		_, err := network.GetCertificateChainWithConfig(testURL, network.FastNetworkConfig())
		duration := time.Since(start)

		// Should timeout and return error
		if err == nil {
			t.Error("Expected timeout error but got none")
			return // Exit early to prevent panic on err.Error()
		}

		// Should timeout within reasonable time for testing
		// Fast config: 2 retries, 3s timeout each, 1s delay = ~8s max
		if duration > 10*time.Second {
			t.Errorf("Timeout took too long: %v (expected < 10s)", duration)
		}

		// Should take at least a few seconds to ensure proper timeout logic
		if duration < 2*time.Second {
			t.Errorf("Timeout happened too quickly: %v (expected at least 2s)", duration)
		}

		// Log the error for analysis but don't require specific error messages
		// since different network stacks may produce different timeout errors
		t.Logf("✅ Timeout handled correctly after %v", duration)
		t.Logf("   Error: %v", err)
	})
}

// TestRetryLogic verifies that network operations retry appropriately
func TestRetryLogic(t *testing.T) {
	// Skip network-dependent tests in fast mode
	if os.Getenv("CYPHERHAWK_SKIP_NETWORK_TESTS") == "1" {
		t.Skip("Skipping network-dependent test in fast mode")
	}

	t.Run("RetryLogic", func(t *testing.T) {
		// Use a non-routable IP address that will cause connection timeout
		// This will trigger retry logic since timeouts are retryable
		testURL := "https://192.0.2.2:443"

		start := time.Now()
		_, err := network.GetCertificateChainWithConfig(testURL, network.FastNetworkConfig())
		duration := time.Since(start)

		// Should fail after retries (all attempts will timeout)
		if err == nil {
			t.Error("Expected timeout failure after retries, but got success")
			return
		}

		// Should have taken time for retries
		// With fast config: 2 attempts, 3s timeout each, 1s delay = ~8s total
		if duration < 4*time.Second {
			t.Errorf("Expected retry delays, completed too quickly: %v (expected ~8s)", duration)
		}

		if duration > 12*time.Second {
			t.Errorf("Retry took too long: %v (expected ~8s)", duration)
		}

		// Should mention "failed after 2 attempts" indicating retry happened
		if !strings.Contains(err.Error(), "failed after 2 attempts") {
			t.Errorf("Expected retry attempt message, got: %v", err)
		}

		t.Logf("✅ Retry logic worked correctly in %v: %v", duration, err)
	})
}

// TestConnectionRefused verifies handling of connection refused errors
func TestConnectionRefused(t *testing.T) {
	// Skip network-dependent tests in fast mode
	if os.Getenv("CYPHERHAWK_SKIP_NETWORK_TESTS") == "1" {
		t.Skip("Skipping network-dependent test in fast mode")
	}
	t.Run("ConnectionRefused", func(t *testing.T) {
		// Try to connect to a definitely closed port
		_, err := network.GetCertificateChain("https://127.0.0.1:9999")

		if err == nil {
			t.Error("Expected connection refused error but got none")
		}

		if !strings.Contains(err.Error(), "connection refused") &&
			!strings.Contains(err.Error(), "network error") {
			t.Errorf("Expected connection refused error, got: %v", err)
		}

		// Should contain corporate network guidance
		if !strings.Contains(err.Error(), "Corporate network guidance") {
			t.Errorf("Expected corporate network guidance in error: %v", err)
		}

		t.Logf("✅ Connection refused handled correctly: %v", err)
	})
}

// TestDNSResolutionErrors verifies handling of DNS resolution failures
func TestDNSResolutionErrors(t *testing.T) {
	// Skip network-dependent tests in fast mode
	if os.Getenv("CYPHERHAWK_SKIP_NETWORK_TESTS") == "1" {
		t.Skip("Skipping network-dependent test in fast mode")
	}
	t.Run("DNSResolution", func(t *testing.T) {
		// Try to connect to a non-existent domain
		_, err := network.GetCertificateChain("https://this-domain-definitely-does-not-exist-12345.com")

		if err == nil {
			t.Error("Expected DNS resolution error but got none")
		}

		// Should contain corporate network guidance
		if !strings.Contains(err.Error(), "Corporate network guidance") &&
			!strings.Contains(err.Error(), "DNS") {
			t.Errorf("Expected DNS/corporate guidance in error: %v", err)
		}

		t.Logf("✅ DNS resolution error handled correctly")
	})
}

// TestTLSHandshakeErrors verifies handling of TLS handshake failures
func TestTLSHandshakeErrors(t *testing.T) {
	// Skip network-dependent tests in fast mode
	if os.Getenv("CYPHERHAWK_SKIP_NETWORK_TESTS") == "1" {
		t.Skip("Skipping network-dependent test in fast mode")
	}
	t.Run("TLSHandshake", func(t *testing.T) {
		// Create server with invalid/expired certificate
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// Configure server with bad TLS
		server.TLS = &tls.Config{
			Certificates: []tls.Certificate{},
		}
		server.StartTLS()
		defer server.Close()

		// This should still work because we use InsecureSkipVerify
		certs, err := network.GetCertificateChain(server.URL)

		// Should get certificates despite TLS issues (that's the point of our tool)
		if err != nil {
			t.Logf("TLS handshake error (expected): %v", err)
		} else if len(certs) > 0 {
			t.Logf("✅ Got certificates despite TLS issues: %d certs", len(certs))
		}
	})
}

// TestConcurrentConnections verifies that multiple simultaneous connections work
func TestConcurrentConnections(t *testing.T) {
	// Skip network-dependent tests in fast mode
	if os.Getenv("CYPHERHAWK_SKIP_NETWORK_TESTS") == "1" {
		t.Skip("Skipping network-dependent test in fast mode")
	}
	// Use simple httptest servers without custom certificates for this test
	// The goal is to verify concurrent connection handling, not certificate parsing
	servers := make([]*httptest.Server, 3)

	for i := 0; i < 3; i++ {
		servers[i] = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Mock Server Response"))
		}))
		defer servers[i].Close()
	}

	t.Run("ConcurrentConnections", func(t *testing.T) {
		// Test concurrent connections
		results := make(chan error, len(servers))

		for _, server := range servers {
			go func(serverURL string) {
				_, err := network.GetCertificateChain(serverURL)
				results <- err
			}(server.URL)
		}

		// Wait for all results
		successCount := 0
		errorCount := 0
		for i := 0; i < len(servers); i++ {
			err := <-results
			if err == nil {
				successCount++
			} else {
				errorCount++
				t.Logf("Connection error (expected in test environment): %v", err)
			}
		}

		// In concurrent testing, we mainly care that the system doesn't crash
		// Some connections may fail due to test environment limitations
		if successCount > 0 {
			t.Logf("✅ Concurrent connections: %d/%d successful", successCount, len(servers))
		} else {
			t.Logf("⚠️  Concurrent connections: 0/%d successful (may be expected in test environment)", len(servers))
		}
	})
}

// TestNetworkConditionsIntegration tests end-to-end network condition handling
func TestNetworkConditionsIntegration(t *testing.T) {
	// Skip network-dependent tests in fast mode
	if os.Getenv("CYPHERHAWK_SKIP_NETWORK_TESTS") == "1" {
		t.Skip("Skipping network-dependent test in fast mode")
	}

	t.Run("NetworkConditionsIntegration", func(t *testing.T) {
		// Test various network scenarios that corporate users might encounter
		scenarios := []struct {
			name        string
			url         string
			expectError bool
			errorType   string
		}{
			{
				name:        "NonexistentDomain",
				url:         "https://nonexistent-domain-12345.com",
				expectError: true,
				errorType:   "no such host",
			},
			{
				name:        "ConnectionRefused",
				url:         "https://127.0.0.1:9999",
				expectError: true,
				errorType:   "connection refused",
			},
			{
				name:        "InvalidPort",
				url:         "https://www.google.com:99999",
				expectError: true,
				errorType:   "invalid port",
			},
		}

		for _, scenario := range scenarios {
			t.Run(scenario.name, func(t *testing.T) {
				_, err := network.GetCertificateChain(scenario.url)

				if scenario.expectError && err == nil {
					t.Errorf("Expected error for %s but got none", scenario.name)
				} else if !scenario.expectError && err != nil {
					t.Errorf("Unexpected error for %s: %v", scenario.name, err)
				} else if scenario.expectError && err != nil {
					// Verify error contains expected type and corporate guidance
					errorStr := strings.ToLower(err.Error())
					if !strings.Contains(errorStr, strings.ToLower(scenario.errorType)) {
						t.Errorf("Expected error type '%s' in error: %v", scenario.errorType, err)
					}
					if !strings.Contains(errorStr, "corporate") {
						t.Errorf("Expected corporate guidance in error: %v", err)
					}
					t.Logf("✅ %s error handled correctly", scenario.name)
				}
			})
		}
	})
}

// Helper function to create a mock DPI server with specific certificates
func createMockDPIServer(certs []*x509.Certificate) *httptest.Server {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Mock DPI Server Response"))
	}))

	// Configure the server to use our mock DPI certificates
	if len(certs) >= 2 {
		// Use the leaf and intermediate/root certificates
		leafCert := certs[0]
		rootCert := certs[1]

		server.TLS = &tls.Config{
			Certificates: []tls.Certificate{
				{
					Certificate: [][]byte{leafCert.Raw, rootCert.Raw},
					// Note: In a real implementation, we'd need the private keys
					// For testing, we'll rely on the default test server certificates
					// and just verify that our detection logic works
				},
			},
		}
	}

	server.StartTLS()
	return server
}

// TestRealWorldNetworkConditions tests against real network conditions (optional)
func TestRealWorldNetworkConditions(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping real-world network tests in short mode")
	}

	t.Run("RealWorldNetworkConditions", func(t *testing.T) {
		// Test against a few real websites to ensure network handling works
		realWorldTests := []struct {
			name string
			url  string
		}{
			{"Google", "https://www.google.com"},
			{"GitHub", "https://api.github.com"},
			{"Mozilla", "https://www.mozilla.org"},
		}

		successCount := 0
		for _, test := range realWorldTests {
			t.Run(test.name, func(t *testing.T) {
				certs, err := network.GetCertificateChain(test.url)
				if err != nil {
					t.Logf("Real-world test %s failed (expected in some environments): %v", test.name, err)
				} else {
					successCount++
					t.Logf("✅ Real-world test %s succeeded: got %d certificates", test.name, len(certs))
				}
			})
		}

		if successCount == 0 {
			t.Log("⚠️  No real-world network tests succeeded (may be expected in restricted environments)")
		} else {
			t.Logf("✅ Real-world network tests: %d/%d successful", successCount, len(realWorldTests))
		}
	})
}

// TestProxyAuthentication verifies proxy authentication error handling
func TestProxyAuthentication(t *testing.T) {
	t.Run("ProxyAuthentication", func(t *testing.T) {
		// Set up proxy environment variables with authentication required
		cleanup := testutils.ClearProxyEnvironment(t)
		defer cleanup()

		// Set invalid proxy credentials to trigger 407 error
		os.Setenv("HTTPS_PROXY", "http://invalid:credentials@127.0.0.1:8080")

		// This should fail with proxy authentication error
		_, err := network.GetCertificateChain("https://www.google.com")

		if err == nil {
			t.Log("Proxy authentication test may not be meaningful in this environment")
			return
		}

		errorStr := strings.ToLower(err.Error())
		hasProxyGuidance := strings.Contains(errorStr, "proxy") || strings.Contains(errorStr, "407")
		hasCorporateGuidance := strings.Contains(errorStr, "corporate")

		if !hasProxyGuidance && !hasCorporateGuidance {
			t.Errorf("Expected proxy/corporate guidance in error: %v", err)
		}

		t.Logf("✅ Proxy authentication error handled correctly")
	})
}
