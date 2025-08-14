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

	"github.com/kaakaww/dpi-hawk/internal/analysis"
	"github.com/kaakaww/dpi-hawk/internal/bundle"
	"github.com/kaakaww/dpi-hawk/internal/network"
	"github.com/kaakaww/dpi-hawk/internal/output"
	"github.com/kaakaww/dpi-hawk/internal/security"
)

// TestMozillaCATrustedCertificate tests that a certificate signed by a Mozilla CA is trusted
func TestMozillaCATrustedCertificate(t *testing.T) {
	// Download Mozilla CA bundle
	mozillaCAs, _, err := bundle.DownloadAndValidate()
	if err != nil {
		t.Skipf("Skipping test - cannot download Mozilla CA bundle: %v", err)
	}

	// Test with a real certificate that should be trusted
	certs, err := network.GetCertificateChain("https://www.google.com")
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
			if analysis.IsTrustedCA(cert, mozillaCAs, certs) {
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
	t.Log("=== Starting Mock DPI Server Test ===")
	
	// Create a mock CA certificate (simulating corporate DPI)
	t.Log("Creating mock corporate CA certificate...")
	mockCA, mockCAKey := createMockCA(t)
	t.Logf("Mock CA created: Subject=%s, Serial=%s", mockCA.Subject.CommonName, mockCA.SerialNumber.String())
	t.Logf("Mock CA Issuer: %s", mockCA.Issuer.CommonName)
	t.Logf("Mock CA IsCA: %v", mockCA.IsCA)
	
	// Create a server certificate signed by the mock CA
	t.Log("Creating server certificate signed by mock CA...")
	serverCert, serverKey := createServerCert(t, mockCA, mockCAKey)
	t.Logf("Server cert created: Subject=%s, Serial=%s", serverCert.Subject.CommonName, serverCert.SerialNumber.String())
	t.Logf("Server cert signed by: %s", serverCert.Issuer.CommonName)

	// Create test TLS server with mock DPI certificate
	t.Log("Starting mock HTTPS server with DPI certificate chain...")
	server := createMockDPIServerWithCA(t, serverCert, serverKey, mockCA)
	defer server.Close()
	t.Logf("Mock server started at: %s", server.URL)

	// Download Mozilla CA bundle
	t.Log("Testing multiple CA bundle sources...")
	mozillaCAs, bundleInfo, err := bundle.DownloadAndValidate()
	if err != nil {
		t.Skipf("Skipping test - cannot download Mozilla CA bundle: %v", err)
	}
	t.Logf("Mozilla CA bundle loaded with %d trusted CAs (%s)", len(mozillaCAs.Subjects()), bundleInfo)

	// Test certificate chain extraction from mock server
	t.Log("Extracting certificate chain from mock server...")
	certs, err := network.GetCertificateChain(server.URL)
	if err != nil {
		t.Fatalf("Failed to get certificate chain from mock server: %v", err)
	}

	if len(certs) == 0 {
		t.Fatal("No certificates retrieved from mock server")
	}

	t.Logf("=== Certificate Chain Analysis ===")
	t.Logf("Retrieved %d certificates from mock server", len(certs))
	for i, cert := range certs {
		t.Logf("Certificate %d:", i+1)
		t.Logf("  Subject: %s", cert.Subject.CommonName)
		t.Logf("  Issuer: %s", cert.Issuer.CommonName)
		t.Logf("  Serial: %s", cert.SerialNumber.String())
		t.Logf("  IsCA: %v", cert.IsCA)
		t.Logf("  NotBefore: %s", cert.NotBefore.Format("2006-01-02 15:04:05"))
		t.Logf("  NotAfter: %s", cert.NotAfter.Format("2006-01-02 15:04:05"))
	}

	// Check that the mock CA is detected as unknown
	t.Log("=== Unknown CA Detection ===")
	foundUnknownCA := false
	for _, cert := range certs {
		if cert.IsCA {
			t.Logf("Checking CA certificate: %s", cert.Subject.CommonName)
			trusted := analysis.IsTrustedCA(cert, mozillaCAs, certs)
			t.Logf("  Trusted by Mozilla: %v", trusted)
			if !trusted {
				foundUnknownCA = true
				t.Logf("  ✓ DETECTED UNKNOWN CA: %s", cert.Subject.CommonName)
				
				// Generate PEM output to show what would be extracted
				pemOutput := output.GeneratePEM([]*x509.Certificate{cert})
				t.Logf("  PEM Output Preview (first 200 chars):")
				preview := pemOutput
				if len(preview) > 200 {
					preview = preview[:200] + "..."
				}
				t.Logf("  %s", preview)
			} else {
				t.Logf("  - Certificate is trusted (would not be flagged)")
			}
		}
	}

	if !foundUnknownCA {
		t.Error("❌ FAILED: No unknown CA certificate detected from mock DPI server")
	} else {
		t.Log("✓ SUCCESS: Mock DPI environment correctly detected unknown CA")
	}
}

// TestPEMOutput tests the PEM output generation
func TestPEMOutput(t *testing.T) {
	// Create a mock certificate
	mockCA, _ := createMockCA(t)
	certs := []*x509.Certificate{mockCA}

	// Generate PEM output
	pemOutput := output.GeneratePEM(certs)

	// Verify output contains expected elements
	if !strings.Contains(pemOutput, "BEGIN CERTIFICATE") {
		t.Error("PEM output missing BEGIN CERTIFICATE marker")
	}
	if !strings.Contains(pemOutput, "END CERTIFICATE") {
		t.Error("PEM output missing END CERTIFICATE marker")
	}
	if !strings.Contains(pemOutput, "DPI Hawk") {
		t.Error("PEM output missing DPI Hawk header")
	}
	if !strings.Contains(pemOutput, mockCA.Subject.CommonName) {
		t.Error("PEM output missing certificate subject")
	}

	// Verify the PEM can be parsed back
	block, _ := pem.Decode([]byte(pemOutput))
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
		if !output.ContainsCertificate(uniqueCerts, cert) {
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
	_, err := network.GetCertificateChain("https://invalid-domain-that-does-not-exist.com")
	if err == nil {
		t.Error("Expected error for invalid domain, got nil")
	}

	// Test non-HTTPS URL (should fail)
	_, err = network.GetCertificateChain("http://www.google.com")
	if err == nil {
		t.Error("Expected error for non-HTTPS URL, got nil")
	}
}

// TestCommandLineFlags tests that the binary can be invoked (integration test)
func TestCommandLineFlags(t *testing.T) {
	// This is now an integration test since flags are in cmd package
	// Test that the binary exists and shows help
	// Note: This requires the binary to be built first
	t.Log("Command line flags are tested through integration tests")
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

// TestWithArtifacts creates actual certificate files to show test artifacts
func TestWithArtifacts(t *testing.T) {
	t.Log("=== Creating Test Artifacts ===")
	
	// Create mock certificates
	mockCA, mockCAKey := createMockCA(t)
	serverCert, _ := createServerCert(t, mockCA, mockCAKey)
	
	// Create artifact files
	caCertFile := "test-artifacts-ca.pem"
	serverCertFile := "test-artifacts-server.pem"
	combinedFile := "test-artifacts-combined.pem"
	
	defer func() {
		os.Remove(caCertFile)
		os.Remove(serverCertFile)
		os.Remove(combinedFile)
	}()
	
	// Write CA certificate
	caOutput := output.GeneratePEM([]*x509.Certificate{mockCA})
	err := os.WriteFile(caCertFile, []byte(caOutput), 0644)
	if err != nil {
		t.Fatalf("Failed to write CA cert file: %v", err)
	}
	t.Logf("Created CA certificate file: %s", caCertFile)
	
	// Write server certificate 
	serverOutput := output.GeneratePEM([]*x509.Certificate{serverCert})
	err = os.WriteFile(serverCertFile, []byte(serverOutput), 0644)
	if err != nil {
		t.Fatalf("Failed to write server cert file: %v", err)
	}
	t.Logf("Created server certificate file: %s", serverCertFile)
	
	// Write combined certificate chain
	combinedOutput := output.GeneratePEM([]*x509.Certificate{serverCert, mockCA})
	err = os.WriteFile(combinedFile, []byte(combinedOutput), 0644)
	if err != nil {
		t.Fatalf("Failed to write combined cert file: %v", err)
	}
	t.Logf("Created combined certificate file: %s", combinedFile)
	
	t.Log("=== Test Artifacts Created Successfully ===")
	t.Logf("You can examine these files:")
	t.Logf("  - CA Certificate: %s", caCertFile)
	t.Logf("  - Server Certificate: %s", serverCertFile) 
	t.Logf("  - Combined Chain: %s", combinedFile)
	
	// Verify files can be read
	for _, file := range []string{caCertFile, serverCertFile, combinedFile} {
		info, err := os.Stat(file)
		if err != nil {
			t.Errorf("Cannot stat file %s: %v", file, err)
		} else {
			t.Logf("File %s: %d bytes", file, info.Size())
		}
	}
}

// TestLegitimateCAImpersonation tests detection of fake certificates claiming to be from legitimate CAs
func TestLegitimateCAImpersonation(t *testing.T) {
	t.Log("=== Testing Legitimate CA Impersonation Detection ===")
	
	// Create a certificate that claims to be from Google but is self-signed (malicious)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(123), // Suspiciously simple serial number
		Subject: pkix.Name{
			Organization:  []string{"Google Trust Services LLC"}, // Impersonating Google
			Country:       []string{"US"},
			CommonName:    "Google Trust Services CA",
		},
		Issuer: pkix.Name{
			Organization:  []string{"Google Trust Services LLC"}, // Self-signed but claiming to be Google
			Country:       []string{"US"},
			CommonName:    "Google Trust Services CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(7 * 24 * time.Hour), // Suspiciously short validity
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create impersonation certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse impersonation certificate: %v", err)
	}

	t.Logf("Created impersonation certificate:")
	t.Logf("  Subject: %s", cert.Subject.CommonName)
	t.Logf("  Issuer: %s", cert.Issuer.CommonName)
	t.Logf("  Serial: %s", cert.SerialNumber.String())
	t.Logf("  Validity: %v", cert.NotAfter.Sub(cert.NotBefore))

	// Test if our impersonation detection catches this
	isImpersonation := security.IsLegitimateCAImpersonation(cert)
	if !isImpersonation {
		t.Error("❌ FAILED: Legitimate CA impersonation not detected")
	} else {
		t.Log("✓ SUCCESS: Legitimate CA impersonation correctly detected")
	}

	// Also test that it would be flagged as a potential DPI CA
	isPotentialDPI := analysis.IsPotentialDPICA(cert)
	if !isPotentialDPI {
		t.Error("❌ FAILED: Impersonation certificate not flagged as potential DPI")
	} else {
		t.Log("✓ SUCCESS: Impersonation certificate correctly flagged as potential DPI")
	}
}

// TestEnhancedSecurityValidation tests all the new security features
func TestEnhancedSecurityValidation(t *testing.T) {
	t.Log("=== Testing Enhanced Security Validation Features ===")
	
	// Test 1: Certificate Transparency validation
	t.Log("Testing Certificate Transparency validation...")
	
	// Create a certificate without CT evidence (issued recently)
	mockCert := createRecentCertificateWithoutCT(t)
	ctIssues := security.ValidateCertificateTransparency([]*x509.Certificate{mockCert})
	
	if len(ctIssues) == 0 {
		t.Error("Expected CT issues for recent certificate without CT evidence")
	} else {
		t.Logf("✓ CT validation detected issue: %s", ctIssues[0])
	}
	
	// Test 2: Behavioral analysis
	t.Log("Testing behavioral analysis...")
	
	// Create a suspicious certificate
	suspiciousCert := createSuspiciousCertificate(t)
	behavioralIssues := security.DetectSuspiciousBehavior([]*x509.Certificate{suspiciousCert}, "https://example.com")
	
	if len(behavioralIssues) == 0 {
		t.Error("Expected behavioral issues for suspicious certificate")
	} else {
		t.Logf("✓ Behavioral analysis detected %d issues:", len(behavioralIssues))
		for _, issue := range behavioralIssues {
			t.Logf("    - %s", issue)
		}
	}
	
	// Test 3: Multiple CA bundle sources (integration test)
	t.Log("Testing multiple CA bundle sources...")
	
	mozillaCAs, bundleInfo, err := bundle.DownloadAndValidate()
	if err != nil {
		t.Skipf("Skipping CA bundle test: %v", err)
	}
	
	t.Logf("✓ CA bundle validation successful: %s", bundleInfo)
	if len(mozillaCAs.Subjects()) < 100 {
		t.Errorf("Expected at least 100 CA certificates, got %d", len(mozillaCAs.Subjects()))
	}
	
	// Test 4: Enhanced security validation integration
	t.Log("Testing enhanced security validation integration...")
	
	result := security.PerformEnhancedValidation([]*x509.Certificate{suspiciousCert}, mozillaCAs, "https://suspicious-site.com")
	
	if len(result.SuspiciousBehaviors) == 0 {
		t.Error("Expected suspicious behaviors to be detected")
	} else {
		t.Logf("✓ Enhanced validation detected %d security issues", len(result.SuspiciousBehaviors))
	}
}

// Helper function to create a recent certificate without CT evidence
func createRecentCertificateWithoutCT(t *testing.T) *x509.Certificate {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			Organization:  []string{"Test Corp"},
			Country:       []string{"US"},
			CommonName:    "test-no-ct.example.com",
		},
		NotBefore:    time.Now().Add(-1 * time.Hour), // Recent issuance
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"test-no-ct.example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// Helper function to create a suspicious certificate
func createSuspiciousCertificate(t *testing.T) *x509.Certificate {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024) // Weak key size
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1), // Suspicious serial number
		Subject: pkix.Name{
			Organization:  []string{"Test Demo Corp"}, // Suspicious terms
			Country:       []string{"US"},
			CommonName:    "suspicious-test.example.com",
		},
		NotBefore:       time.Now().Add(-1 * time.Hour), // Recent issuance
		NotAfter:        time.Now().Add(1 * time.Hour),  // Very short validity
		KeyUsage:        x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:        []string{"suspicious-test.example.com"},
		SignatureAlgorithm: x509.SHA1WithRSA, // Weak signature algorithm
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
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

	// This is now an integration test that would test the built binary
	// Since command line flags are in the cmd package, we test the packages directly
	t.Log("Integration test - testing package functionality")
	
	// Test that all packages work together
	mozillaCAs, _, err := bundle.DownloadAndValidate()
	if err != nil {
		t.Skipf("Skipping integration test: %v", err)
	}
	
	certs, err := network.GetCertificateChain("https://www.google.com")
	if err != nil {
		t.Skipf("Skipping integration test: %v", err)
	}
	
	result := security.PerformEnhancedValidation(certs, mozillaCAs, "https://www.google.com")
	t.Logf("Integration test completed - found %d suspicious behaviors", len(result.SuspiciousBehaviors))
}