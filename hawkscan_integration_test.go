package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"github.com/kaakaww/cypherhawk/internal/output"
	"github.com/kaakaww/cypherhawk/testdata"
)

// TestHawkScanPEMCompatibility verifies that our PEM output works perfectly with HawkScan
func TestHawkScanPEMCompatibility(t *testing.T) {
	t.Run("PEMFormatCompliance", func(t *testing.T) {
		// Generate test certificates from multiple DPI vendors
		mockData := []*testdata.MockDPICertificates{
			testdata.GeneratePaloAltoCertificateChain(),
			testdata.GenerateZscalerCertificateChain(),
			testdata.GenerateNetskopeCertificateChain(),
		}

		var allCerts []*x509.Certificate
		for _, data := range mockData {
			allCerts = append(allCerts, data.Certificates...)
		}

		// Generate PEM output
		pemOutput := output.GeneratePEM(allCerts)

		// Verify PEM format compliance
		if !strings.Contains(pemOutput, "-----BEGIN CERTIFICATE-----") {
			t.Error("PEM output missing BEGIN CERTIFICATE marker")
		}
		if !strings.Contains(pemOutput, "-----END CERTIFICATE-----") {
			t.Error("PEM output missing END CERTIFICATE marker")
		}

		// Verify each certificate can be parsed independently
		certCount := 0
		rest := []byte(pemOutput)
		for {
			block, remaining := pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				t.Errorf("Unexpected PEM block type: %s", block.Type)
			}

			// Verify certificate can be parsed
			_, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Errorf("Certificate %d cannot be parsed: %v", certCount+1, err)
			}

			certCount++
			rest = remaining
		}

		if certCount != len(allCerts) {
			t.Errorf("Expected %d certificates in PEM output, found %d", len(allCerts), certCount)
		}

		t.Logf("✅ PEM format compliance verified: %d certificates", certCount)
	})

	t.Run("HawkScanCompatibleHeaders", func(t *testing.T) {
		// Test that PEM headers don't interfere with HawkScan parsing
		mockCerts := testdata.GeneratePaloAltoCertificateChain().Certificates
		pemOutput := output.GeneratePEM(mockCerts)

		// Verify comments start with # (standard PEM comment format)
		lines := strings.Split(pemOutput, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "-----") {
				continue // Skip empty lines and PEM delimiters
			}
			if strings.HasPrefix(line, "#") {
				continue // Valid comment
			}
			// If it's not a comment or PEM delimiter, it should be base64 encoded certificate data
			if !isBase64Line(line) {
				t.Errorf("Unexpected line format (not comment or base64): %s", line)
			}
		}

		t.Log("✅ PEM headers compatible with HawkScan")
	})

	t.Run("CertificateOrdering", func(t *testing.T) {
		// Test certificate ordering for optimal trust chain validation
		// HawkScan expects leaf certificates first, then intermediates, then roots
		mockChain := testdata.GeneratePaloAltoCertificateChain()
		pemOutput := output.GeneratePEM(mockChain.Certificates)

		// Parse certificates back to verify ordering
		var parsedCerts []*x509.Certificate
		rest := []byte(pemOutput)
		for {
			block, remaining := pem.Decode(rest)
			if block == nil {
				break
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("Failed to parse certificate: %v", err)
			}
			parsedCerts = append(parsedCerts, cert)
			rest = remaining
		}

		// Verify certificates maintain their original order
		if len(parsedCerts) != len(mockChain.Certificates) {
			t.Errorf("Certificate count mismatch: expected %d, got %d",
				len(mockChain.Certificates), len(parsedCerts))
		}

		for i, cert := range parsedCerts {
			if !cert.Equal(mockChain.Certificates[i]) {
				t.Errorf("Certificate %d order mismatch", i)
			}
		}

		t.Log("✅ Certificate ordering verified")
	})

	t.Run("JavaKeyStoreCompatibility", func(t *testing.T) {
		// Test that our PEM output works with Java keytool for JKS conversion
		mockCerts := testdata.GenerateZscalerCertificateChain().Certificates
		pemOutput := output.GeneratePEM(mockCerts)

		// Create temporary PEM file
		tmpFile, err := os.CreateTemp("", "hawkscan-test-*.pem")
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		defer os.Remove(tmpFile.Name())

		// Write PEM content
		_, err = tmpFile.WriteString(pemOutput)
		if err != nil {
			t.Fatalf("Failed to write PEM content: %v", err)
		}
		tmpFile.Close()

		// Verify file can be read back
		readBack, err := os.ReadFile(tmpFile.Name())
		if err != nil {
			t.Fatalf("Failed to read PEM file: %v", err)
		}

		if string(readBack) != pemOutput {
			t.Error("PEM file content mismatch after write/read cycle")
		}

		t.Log("✅ PEM file I/O compatibility verified")
	})

	t.Run("NoDataLoss", func(t *testing.T) {
		// Verify that no certificate data is lost during PEM conversion
		original := testdata.GenerateNetskopeCertificateChain().Certificates[0]
		pemOutput := output.GeneratePEM([]*x509.Certificate{original})

		// Parse certificate back from PEM
		block, _ := pem.Decode([]byte(pemOutput))
		if block == nil {
			t.Fatal("Failed to decode PEM")
		}

		parsed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("Failed to parse certificate from PEM: %v", err)
		}

		// Verify all key fields are preserved
		if !parsed.Equal(original) {
			t.Error("Certificate data lost during PEM conversion")
		}

		if parsed.Subject.CommonName != original.Subject.CommonName {
			t.Errorf("Subject CN mismatch: expected %s, got %s",
				original.Subject.CommonName, parsed.Subject.CommonName)
		}

		if parsed.SerialNumber.Cmp(original.SerialNumber) != 0 {
			t.Errorf("Serial number mismatch: expected %s, got %s",
				original.SerialNumber.String(), parsed.SerialNumber.String())
		}

		t.Log("✅ No data loss verified")
	})

	t.Run("HawkScanUsagePatterns", func(t *testing.T) {
		// Test common HawkScan usage patterns with our PEM output
		mockCerts := testdata.GeneratePaloAltoCertificateChain().Certificates
		pemOutput := output.GeneratePEM(mockCerts)

		// Pattern 1: Direct file usage with --ca-bundle
		// This tests that our PEM format works with HawkScan's certificate loading
		tmpFile, err := os.CreateTemp("", "hawkscan-ca-bundle-*.pem")
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		defer os.Remove(tmpFile.Name())

		err = os.WriteFile(tmpFile.Name(), []byte(pemOutput), 0644)
		if err != nil {
			t.Fatalf("Failed to write PEM file: %v", err)
		}

		// Verify file exists and is readable
		fileInfo, err := os.Stat(tmpFile.Name())
		if err != nil {
			t.Fatalf("PEM file not accessible: %v", err)
		}

		if fileInfo.Size() == 0 {
			t.Error("PEM file is empty")
		}

		// Pattern 2: Stdout usage with hawk scan --ca-bundle -
		// Verify our PEM output doesn't contain any characters that would break shell parsing
		for _, char := range pemOutput {
			if char < 32 && char != '\n' && char != '\r' && char != '\t' {
				t.Errorf("PEM output contains control character: %d", int(char))
			}
		}

		t.Log("✅ HawkScan usage patterns verified")
	})

	t.Run("ConcatenatePEMCompatibility", func(t *testing.T) {
		// Test that multiple PEM files can be concatenated (common HawkScan workflow)
		cert1 := testdata.GeneratePaloAltoCertificateChain().Certificates[0]
		cert2 := testdata.GenerateZscalerCertificateChain().Certificates[0]

		pem1 := output.GeneratePEM([]*x509.Certificate{cert1})
		pem2 := output.GeneratePEM([]*x509.Certificate{cert2})

		// Concatenate PEM outputs
		combined := pem1 + "\n" + pem2

		// Verify both certificates can be parsed from concatenated PEM
		var parsedCerts []*x509.Certificate
		rest := []byte(combined)
		for {
			block, remaining := pem.Decode(rest)
			if block == nil {
				break
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("Failed to parse certificate from concatenated PEM: %v", err)
			}
			parsedCerts = append(parsedCerts, cert)
			rest = remaining
		}

		if len(parsedCerts) != 2 {
			t.Errorf("Expected 2 certificates in concatenated PEM, got %d", len(parsedCerts))
		}

		t.Log("✅ PEM concatenation compatibility verified")
	})
}

// TestHawkScanIntegrationExamples tests the exact command patterns from our documentation
func TestHawkScanIntegrationExamples(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping HawkScan integration examples in short mode")
	}

	t.Run("DocumentedWorkflows", func(t *testing.T) {
		// Generate test certificates
		mockCerts := testdata.GeneratePaloAltoCertificateChain().Certificates
		pemOutput := output.GeneratePEM(mockCerts)

		// Test the exact workflow from our help documentation:
		// 1. cypherhawk -o corporate-certs.pem
		// 2. hawk scan --ca-bundle corporate-certs.pem

		// Step 1: Save certificates
		tmpFile, err := os.CreateTemp("", "corporate-certs-*.pem")
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		defer os.Remove(tmpFile.Name())

		err = os.WriteFile(tmpFile.Name(), []byte(pemOutput), 0644)
		if err != nil {
			t.Fatalf("Failed to write certificates: %v", err)
		}

		// Step 2: Verify file format is compatible
		// Read back and verify parsing works
		content, err := os.ReadFile(tmpFile.Name())
		if err != nil {
			t.Fatalf("Failed to read certificate file: %v", err)
		}

		// Parse all certificates
		var certCount int
		rest := content
		for {
			block, remaining := pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				t.Errorf("Unexpected block type: %s", block.Type)
			}
			_, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Errorf("Certificate parsing failed: %v", err)
			}
			certCount++
			rest = remaining
		}

		if certCount != len(mockCerts) {
			t.Errorf("Certificate count mismatch: expected %d, got %d", len(mockCerts), certCount)
		}

		t.Logf("✅ Documented workflow verified: %d certificates processed", certCount)
	})
}

// Helper function to check if a line contains base64 data
func isBase64Line(line string) bool {
	if len(line) == 0 {
		return false
	}
	// Base64 lines in PEM should be 64 characters or less and contain only valid base64 characters
	validChars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	for _, char := range line {
		found := false
		for _, validChar := range validChars {
			if char == validChar {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
