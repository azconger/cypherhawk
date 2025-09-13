package integration_test

import (
	"crypto/x509"
	"testing"

	"github.com/kaakaww/cypherhawk/internal/detection"
	"github.com/kaakaww/cypherhawk/test/testdata"
)

// TestDPIDetectionWithoutNetwork tests core DPI detection without network dependencies
func TestDPIDetectionWithoutNetwork(t *testing.T) {
	// Create a minimal mock Mozilla CA bundle (empty for testing)
	mockMozillaCAs := x509.NewCertPool()

	// Test DPI vendor detection with each mock certificate chain
	testCases := []struct {
		name              string
		generateChain     func() *testdata.MockDPICertificates
		expectedVendor    string
		expectedDetection bool
	}{
		{
			name:              "Palo Alto Networks",
			generateChain:     testdata.GeneratePaloAltoCertificateChain,
			expectedVendor:    "Palo Alto Networks",
			expectedDetection: true,
		},
		{
			name:              "Zscaler",
			generateChain:     testdata.GenerateZscalerCertificateChain,
			expectedVendor:    "Zscaler",
			expectedDetection: true,
		},
		{
			name:              "Netskope",
			generateChain:     testdata.GenerateNetskopeCertificateChain,
			expectedVendor:    "Netskope",
			expectedDetection: true,
		},
		{
			name:              "Squid Proxy",
			generateChain:     testdata.GenerateSquidProxyCertificateChain,
			expectedVendor:    "Squid Proxy",
			expectedDetection: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate the mock certificate chain
			mockChain := tc.generateChain()

			// Analyze the certificate chain
			result := detection.AnalyzeCertificateChain("https://test.example.com", mockChain.Certificates, mockMozillaCAs)

			// Verify DPI detection
			if result.IsCorporateDPI != tc.expectedDetection {
				t.Errorf("Expected IsCorporateDPI=%v, got %v", tc.expectedDetection, result.IsCorporateDPI)
			}

			if tc.expectedDetection && result.BestMatch != nil {
				if result.BestMatch.Vendor != tc.expectedVendor {
					t.Errorf("Expected vendor %s, got %s", tc.expectedVendor, result.BestMatch.Vendor)
				}

				t.Logf("✅ Successfully detected %s with %d%% confidence",
					result.BestMatch.Vendor, result.BestMatch.Confidence)
				t.Logf("   Indicators: %v", result.BestMatch.Indicators)
			}

			// Verify certificates were identified as unknown (since we have no Mozilla CAs)
			if len(result.UnknownCAs) == 0 {
				t.Error("Expected unknown CAs to be found but got none")
			}
		})
	}
}

// TestCertificateChainGeneration verifies our mock certificate generation works
func TestCertificateChainGeneration(t *testing.T) {
	generators := []struct {
		name     string
		generate func() *testdata.MockDPICertificates
	}{
		{"Palo Alto", testdata.GeneratePaloAltoCertificateChain},
		{"Zscaler", testdata.GenerateZscalerCertificateChain},
		{"Netskope", testdata.GenerateNetskopeCertificateChain},
		{"Generic Corporate", testdata.GenerateGenericCorporateCertificateChain},
		{"Squid Proxy", testdata.GenerateSquidProxyCertificateChain},
		{"Legitimate Google", testdata.GenerateLegitimateGoogleChain},
	}

	for _, gen := range generators {
		t.Run(gen.name, func(t *testing.T) {
			chain := gen.generate()

			// Basic validation
			if chain == nil {
				t.Fatal("Generated chain is nil")
			}

			if len(chain.Certificates) == 0 {
				t.Fatal("Generated chain has no certificates")
			}

			if chain.Vendor == "" {
				t.Error("Generated chain has empty vendor")
			}

			// Verify certificate properties
			for i, cert := range chain.Certificates {
				if cert == nil {
					t.Errorf("Certificate %d is nil", i)
					continue
				}

				if cert.Subject.CommonName == "" && len(cert.Subject.Organization) == 0 {
					t.Errorf("Certificate %d has no subject information", i)
				}

				if cert.NotAfter.Before(cert.NotBefore) {
					t.Errorf("Certificate %d has invalid validity period", i)
				}
			}

			t.Logf("✅ %s chain generated successfully: %d certificates, vendor=%s",
				gen.name, len(chain.Certificates), chain.Vendor)
		})
	}
}
