package output

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
)

// ContainsCertificate checks if a certificate is already in the slice (deduplication)
func ContainsCertificate(certs []*x509.Certificate, target *x509.Certificate) bool {
	for _, cert := range certs {
		if cert.Equal(target) {
			return true
		}
	}
	return false
}

// GeneratePEM converts certificates to PEM format optimized for HawkScan compatibility
func GeneratePEM(certs []*x509.Certificate) string {
	var output strings.Builder

	// HawkScan-compatible header with clear usage instructions
	output.WriteString("# CypherHawk - Corporate DPI/MitM CA Certificates\n")
	output.WriteString("# Generated for HawkScan integration\n")
	output.WriteString("#\n")
	output.WriteString("# Usage with HawkScan:\n")
	output.WriteString("#   hawk scan --ca-bundle this-file.pem\n")
	output.WriteString("#\n")
	output.WriteString("# These CA certificates are NOT in Mozilla's trusted CA bundle but were\n")
	output.WriteString("# found in TLS connections. This indicates corporate DPI/proxy infrastructure.\n")
	output.WriteString("# They may be trusted by your OS but HawkScan needs them explicitly.\n")
	output.WriteString("#\n")

	if len(certs) == 0 {
		output.WriteString("# No corporate/DPI CA certificates detected\n")
		output.WriteString("# All certificates validate against Mozilla's CA bundle\n")
		return output.String()
	}

	output.WriteString(fmt.Sprintf("# Certificate Count: %d\n", len(certs)))
	output.WriteString("#\n\n")

	// Process certificates in optimal order for trust chain validation
	// HawkScan expects certificates in order: leaf -> intermediate -> root
	orderedCerts := orderCertificatesForTrustChain(certs)

	for i, cert := range orderedCerts {
		// Enhanced certificate metadata for better traceability
		output.WriteString(fmt.Sprintf("# === Certificate %d of %d ===\n", i+1, len(orderedCerts)))
		output.WriteString(fmt.Sprintf("# Subject CN: %s\n", safeCertificateField(cert.Subject.CommonName)))
		output.WriteString(fmt.Sprintf("# Issuer CN:  %s\n", safeCertificateField(cert.Issuer.CommonName)))
		output.WriteString(fmt.Sprintf("# Serial:     %s\n", cert.SerialNumber.String()))

		// Add certificate validity information for debugging
		output.WriteString(fmt.Sprintf("# Valid From: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05 UTC")))
		output.WriteString(fmt.Sprintf("# Valid To:   %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 UTC")))

		// Add key algorithm and size for security analysis
		keyInfo := getKeyInfo(cert)
		if keyInfo != "" {
			output.WriteString(fmt.Sprintf("# Key Info:   %s\n", keyInfo))
		}

		output.WriteString("#\n")

		// Generate PEM-encoded certificate with proper formatting
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}

		pemBytes := pem.EncodeToMemory(pemBlock)
		if pemBytes == nil {
			// Fallback in case of encoding failure
			output.WriteString(fmt.Sprintf("# ERROR: Failed to encode certificate %d\n", i+1))
			continue
		}

		// Ensure consistent line endings and formatting
		pemString := string(pemBytes)
		pemString = strings.ReplaceAll(pemString, "\r\n", "\n") // Normalize line endings
		pemString = strings.TrimRight(pemString, "\n")          // Remove trailing newlines

		output.WriteString(pemString)
		output.WriteString("\n\n")
	}

	// Add footer with integration notes
	output.WriteString("# End of CypherHawk CA certificates\n")
	output.WriteString("# For JKS conversion: keytool -importcert -noprompt -file this-file.pem -keystore corporate.jks -storepass changeit -alias corporate-ca\n")

	return output.String()
}

// safeCertificateField sanitizes certificate fields to prevent issues with special characters
func safeCertificateField(field string) string {
	if field == "" {
		return "(empty)"
	}

	// Replace any problematic characters that might break PEM parsing or display
	safe := strings.ReplaceAll(field, "\n", " ")
	safe = strings.ReplaceAll(safe, "\r", " ")
	safe = strings.ReplaceAll(safe, "\t", " ")

	// Truncate very long fields to keep output readable
	if len(safe) > 80 {
		safe = safe[:77] + "..."
	}

	return safe
}

// getKeyInfo extracts readable key algorithm and size information from a certificate
func getKeyInfo(cert *x509.Certificate) string {
	if cert.PublicKey == nil {
		return "Unknown key type"
	}

	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d bits", key.Size()*8)
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %d bits", key.Curve.Params().BitSize)
	default:
		return fmt.Sprintf("%T", key)
	}
}

// orderCertificatesForTrustChain orders certificates optimally for trust chain validation
// HawkScan and Java applications typically expect: leaf -> intermediate -> root
func orderCertificatesForTrustChain(certs []*x509.Certificate) []*x509.Certificate {
	if len(certs) <= 1 {
		return certs
	}

	// Create a copy to avoid modifying the original slice
	ordered := make([]*x509.Certificate, len(certs))
	copy(ordered, certs)

	// Sort certificates by their role in the chain
	// Priority: 1. Leaf certificates (issued to end entities)
	//          2. Intermediate CAs (can sign but are not self-signed)
	//          3. Root CAs (self-signed)
	sort.Slice(ordered, func(i, j int) bool {
		certI := ordered[i]
		certJ := ordered[j]

		// Calculate chain position scores (lower = earlier in chain)
		scoreI := calculateChainScore(certI)
		scoreJ := calculateChainScore(certJ)

		if scoreI != scoreJ {
			return scoreI < scoreJ
		}

		// If scores are equal, sort by subject name for consistency
		return certI.Subject.CommonName < certJ.Subject.CommonName
	})

	return ordered
}

// calculateChainScore assigns a score based on certificate type for chain ordering
func calculateChainScore(cert *x509.Certificate) int {
	// Self-signed certificates (roots) go last
	if cert.Subject.String() == cert.Issuer.String() {
		return 100
	}

	// Certificates with CA:TRUE but not self-signed (intermediates) go in middle
	if cert.IsCA {
		return 50
	}

	// End-entity certificates (leaves) go first
	return 10
}
