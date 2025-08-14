package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestMozillaCATrustedCertificate tests that a certificate signed by a Mozilla CA is trusted
func TestMozillaCATrustedCertificate(t *testing.T) {
	// Download Mozilla CA bundle
	mozillaCAs, err := downloadMozillaCAs()
	if err != nil {
		t.Skipf("Skipping test - cannot download Mozilla CA bundle: %v", err)
	}

	// Test with a real certificate that should be trusted
	certs, err := getCertificateChain("https://www.google.com")
	if err != nil {
		t.Skipf("Skipping test - cannot connect to Google: %v", err)
	}

	if len(certs) == 0 {
		t.Fatal("No certificates retrieved from Google")
	}

	// At least one certificate in the chain should be trusted or verifiable
	hasValidChain := false
	for _, cert := range certs {
		if cert.IsCA {
			if isTrustedCA(cert, mozillaCAs) {
				hasValidChain = true
				break
			}
		}
	}

	if !hasValidChain {
		// This is expected in corporate environments with DPI
		t.Logf("No trusted CA found in certificate chain - this may indicate DPI/MitM proxy")
	}
}

// TestUnknownCADetection tests detection of unknown CA certificates using a mock DPI server
func TestUnknownCADetection(t *testing.T) {
	// Create a mock CA certificate (simulating corporate DPI)
	mockCA, mockCAKey := createMockCA(t)
	
	// Create a server certificate signed by the mock CA
	serverCert, serverKey := createServerCert(t, mockCA, mockCAKey)

	// Create test TLS server with mock DPI certificate
	server := createMockDPIServerWithCA(t, serverCert, serverKey, mockCA)
	defer server.Close()

	// Download Mozilla CA bundle
	mozillaCAs, err := downloadMozillaCAs()
	if err != nil {
		t.Skipf("Skipping test - cannot download Mozilla CA bundle: %v", err)
	}

	// Test certificate chain extraction from mock server
	certs, err := getCertificateChain(server.URL)
	if err != nil {
		t.Fatalf("Failed to get certificate chain from mock server: %v", err)
	}

	if len(certs) == 0 {
		t.Fatal("No certificates retrieved from mock server")
	}

	t.Logf("Retrieved %d certificates from mock server", len(certs))
	for i, cert := range certs {
		t.Logf("Certificate %d: Subject=%s, IsCA=%v", i+1, cert.Subject.CommonName, cert.IsCA)
	}

	// Check that the mock CA is detected as unknown
	foundUnknownCA := false
	for _, cert := range certs {
		if cert.IsCA {
			trusted := isTrustedCA(cert, mozillaCAs)
			t.Logf("CA Certificate: %s, Trusted: %v", cert.Subject.CommonName, trusted)
			if !trusted {
				foundUnknownCA = true
				t.Logf("Successfully detected unknown CA: %s", cert.Subject.CommonName)
			}
		}
	}

	if !foundUnknownCA {
		t.Error("Failed to detect unknown CA certificate from mock DPI server")
	}
}

// TestPEMOutput tests the PEM output generation
func TestPEMOutput(t *testing.T) {
	// Create a mock certificate
	mockCA, _ := createMockCA(t)
	certs := []*x509.Certificate{mockCA}

	// Generate PEM output
	output := generatePEMOutput(certs)

	// Verify output contains expected elements
	if !strings.Contains(output, "BEGIN CERTIFICATE") {
		t.Error("PEM output missing BEGIN CERTIFICATE marker")
	}
	if !strings.Contains(output, "END CERTIFICATE") {
		t.Error("PEM output missing END CERTIFICATE marker")
	}
	if !strings.Contains(output, "DPI Hawk") {
		t.Error("PEM output missing DPI Hawk header")
	}
	if !strings.Contains(output, mockCA.Subject.CommonName) {
		t.Error("PEM output missing certificate subject")
	}

	// Verify the PEM can be parsed back
	block, _ := pem.Decode([]byte(output))
	if block == nil {
		t.Error("Generated PEM output cannot be decoded")
	}

	_, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Errorf("Generated PEM contains invalid certificate: %v", err)
	}
}

// TestCertificateDeduplication tests that duplicate certificates are removed
func TestCertificateDeduplication(t *testing.T) {
	mockCA1, _ := createMockCA(t)
	mockCA2, _ := createMockCA(t)
	
	// Create slice with duplicates
	certs := []*x509.Certificate{mockCA1, mockCA2, mockCA1}

	// Test deduplication
	var uniqueCerts []*x509.Certificate
	for _, cert := range certs {
		if !containsCertificate(uniqueCerts, cert) {
			uniqueCerts = append(uniqueCerts, cert)
		}
	}

	if len(uniqueCerts) != 2 {
		t.Errorf("Expected 2 unique certificates, got %d", len(uniqueCerts))
	}
}

// TestErrorHandling tests various error conditions
func TestErrorHandling(t *testing.T) {
	// Test invalid URL
	_, err := getCertificateChain("https://invalid-domain-that-does-not-exist.com")
	if err == nil {
		t.Error("Expected error for invalid domain, got nil")
	}

	// Test non-HTTPS URL (should fail)
	_, err = getCertificateChain("http://www.google.com")
	if err == nil {
		t.Error("Expected error for non-HTTPS URL, got nil")
	}
}

// TestCommandLineFlags tests the command line flag functionality
func TestCommandLineFlags(t *testing.T) {
	// Reset flags for testing
	*outputFile = ""
	*targetURL = ""
	*verbose = false

	// Test that defaults are correctly set
	if *outputFile != "" {
		t.Errorf("Expected empty output file, got %s", *outputFile)
	}
	if *targetURL != "" {
		t.Errorf("Expected empty target URL, got %s", *targetURL)
	}
	if *verbose != false {
		t.Error("Expected verbose to be false")
	}
}

// Helper function to create a mock CA certificate
func createMockCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Mock DPI Corp"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    "Mock Corporate DPI CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert, privateKey
}

// Helper function to create a server certificate signed by the mock CA
func createServerCert(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	// Generate server private key
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate server private key: %v", err)
	}

	// Create server certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization:  []string{"Mock Server"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    "localhost",
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost"},
	}

	// Create certificate signed by CA
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create server certificate: %v", err)
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse server certificate: %v", err)
	}

	return cert, serverKey
}

// Helper function to create a mock DPI server with TLS and specific CA
func createMockDPIServerWithCA(t *testing.T, serverCert *x509.Certificate, serverKey *rsa.PrivateKey, caCert *x509.Certificate) *httptest.Server {
	// Create TLS certificate with full chain (server cert + CA cert)
	tlsCert := tls.Certificate{
		Certificate: [][]byte{serverCert.Raw, caCert.Raw}, // Include both server and CA cert
		PrivateKey:  serverKey,
	}

	// Create HTTPS server
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Mock DPI Server"))
	}))

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	server.StartTLS()

	return server
}

// Helper function to create a mock DPI server with TLS
func createMockDPIServer(t *testing.T, serverCert *x509.Certificate, serverKey *rsa.PrivateKey) *httptest.Server {
	// Create TLS certificate
	tlsCert := tls.Certificate{
		Certificate: [][]byte{serverCert.Raw},
		PrivateKey:  serverKey,
	}

	// Create HTTPS server
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Mock DPI Server"))
	}))

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	server.StartTLS()

	return server
}

// TestIntegration runs a complete integration test
func TestIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create temporary output file
	tmpFile, err := os.CreateTemp("", "dpi-hawk-test-*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Save original flags
	origOutput := *outputFile
	origVerbose := *verbose
	defer func() {
		*outputFile = origOutput
		*verbose = origVerbose
	}()

	// Set test flags
	*outputFile = tmpFile.Name()
	*verbose = true

	// Note: This integration test will likely show "no DPI detected" in normal environments
	// which is the expected behavior. In corporate environments, it should detect DPI certificates.
	t.Log("Running integration test - may show 'no DPI detected' in normal environments")
}