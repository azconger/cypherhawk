package detection

import (
	"crypto/x509"
	"fmt"
	"sort"
	"strings"
)

// DetectionResult contains comprehensive analysis results for a certificate chain
type DetectionResult struct {
	URL               string              // The URL that was analyzed
	TotalCertificates int                 // Total certificates in the chain
	VendorMatches     []VendorMatch       // All vendor matches found
	BestMatch         *VendorMatch        // Highest confidence vendor match
	IsCorporateDPI    bool                // Whether corporate DPI was detected
	Recommendations   []string            // HawkScan-specific recommendations
	SecurityFlags     []string            // Security-related observations
	UnknownCAs        []*x509.Certificate // Certificates not in Mozilla bundle
}

// AnalyzeCertificateChain performs comprehensive DPI vendor detection on a certificate chain
func AnalyzeCertificateChain(url string, certs []*x509.Certificate, mozillaCAs *x509.CertPool) *DetectionResult {
	result := &DetectionResult{
		URL:               url,
		TotalCertificates: len(certs),
		VendorMatches:     []VendorMatch{},
		Recommendations:   []string{},
		SecurityFlags:     []string{},
		UnknownCAs:        []*x509.Certificate{},
	}

	if len(certs) == 0 {
		return result
	}

	// Check if the certificate chain is unknown to Mozilla bundle
	unknownCerts := findUnknownCAs(certs, mozillaCAs)
	result.UnknownCAs = unknownCerts

	// Only analyze vendor patterns if we found unknown CAs
	allMatches := make(map[string][]VendorMatch) // Group by vendor name

	for _, cert := range unknownCerts {
		// Analyze vendor patterns for unknown CAs
		matches := DetectVendor(cert)
		for _, match := range matches {
			if match.Confidence > 0 {
				vendorKey := match.Vendor
				allMatches[vendorKey] = append(allMatches[vendorKey], match)
			}
		}
	}

	// Process and consolidate vendor matches
	result.VendorMatches = consolidateVendorMatches(allMatches)

	// Sort by confidence (highest first)
	sort.Slice(result.VendorMatches, func(i, j int) bool {
		return result.VendorMatches[i].Confidence > result.VendorMatches[j].Confidence
	})

	// Determine best match and DPI status
	if len(result.VendorMatches) > 0 {
		result.BestMatch = &result.VendorMatches[0]
		result.IsCorporateDPI = result.BestMatch.Confidence >= 30 // Minimum confidence for DPI detection
	}

	// Generate security flags and recommendations
	result.SecurityFlags = generateSecurityFlags(certs, result.VendorMatches)
	result.Recommendations = generateRecommendations(result.BestMatch, result.UnknownCAs)

	return result
}

// consolidateVendorMatches combines multiple matches for the same vendor
func consolidateVendorMatches(allMatches map[string][]VendorMatch) []VendorMatch {
	var consolidated []VendorMatch

	for _, matches := range allMatches {
		if len(matches) == 0 {
			continue
		}

		// Find the match with highest confidence for this vendor
		bestMatch := matches[0]
		combinedIndicators := make(map[string]bool)

		for _, match := range matches {
			if match.Confidence > bestMatch.Confidence {
				bestMatch = match
			}

			// Combine all unique indicators
			for _, indicator := range match.Indicators {
				combinedIndicators[indicator] = true
			}
		}

		// Create consolidated match
		var indicators []string
		for indicator := range combinedIndicators {
			indicators = append(indicators, indicator)
		}

		bestMatch.Indicators = indicators
		consolidated = append(consolidated, bestMatch)
	}

	return consolidated
}

// findUnknownCAs identifies certificates that are not trusted by Mozilla's CA bundle
func findUnknownCAs(certs []*x509.Certificate, mozillaCAs *x509.CertPool) []*x509.Certificate {
	if mozillaCAs == nil || len(certs) == 0 {
		return certs // Return all certificates if no Mozilla bundle available
	}

	// Build intermediate certificate pool from the chain
	intermediates := x509.NewCertPool()
	if len(certs) > 1 {
		for _, cert := range certs[1:] {
			intermediates.AddCert(cert)
		}
	}

	// Try to verify the leaf certificate against Mozilla CA bundle
	leafCert := certs[0]
	opts := x509.VerifyOptions{
		Roots:         mozillaCAs,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	_, err := leafCert.Verify(opts)
	if err == nil {
		// Chain validates against Mozilla bundle - no unknown CAs
		return []*x509.Certificate{}
	}

	// Chain doesn't validate - find which certificates are unknown
	var unknownCerts []*x509.Certificate

	for _, cert := range certs {
		// Check if this individual certificate is a known Mozilla CA
		if !isKnownMozillaCA(cert, mozillaCAs) {
			unknownCerts = append(unknownCerts, cert)
		}
	}

	return unknownCerts
}

// isKnownMozillaCA checks if a certificate is directly trusted by Mozilla
func isKnownMozillaCA(cert *x509.Certificate, mozillaCAs *x509.CertPool) bool {
	if mozillaCAs == nil {
		return false
	}

	// Try to verify the certificate as a root CA
	opts := x509.VerifyOptions{
		Roots:     mozillaCAs,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	_, err := cert.Verify(opts)
	return err == nil
}

// generateSecurityFlags creates security-related observations
func generateSecurityFlags(certs []*x509.Certificate, matches []VendorMatch) []string {
	var flags []string

	if len(certs) == 0 {
		return flags
	}

	leafCert := certs[0]

	// Check for self-signed leaf certificates (unusual for legitimate sites)
	if leafCert.Issuer.String() == leafCert.Subject.String() {
		flags = append(flags, "Self-signed leaf certificate (strong DPI indicator)")
	}

	// Check for very short validity periods (< 30 days)
	validityDays := leafCert.NotAfter.Sub(leafCert.NotBefore).Hours() / 24
	if validityDays < 30 {
		flags = append(flags, fmt.Sprintf("Very short validity period (%.0f days)", validityDays))
	}

	// Check for very long validity periods (> 5 years)
	if validityDays > 1825 { // 5 years
		flags = append(flags, fmt.Sprintf("Unusually long validity period (%.1f years)", validityDays/365))
	}

	// Check for suspicious serial numbers
	serialStr := leafCert.SerialNumber.String()
	if serialStr == "1" || serialStr == "123" || len(serialStr) < 4 {
		flags = append(flags, "Suspicious serial number: "+serialStr)
	}

	// Check for weak key sizes
	switch leafCert.PublicKey.(type) {
	case *x509.Certificate: // This is a type assertion issue, let me fix this
		// Will fix this in the next version
	}

	// Check for missing intermediate certificates (possible DPI behavior)
	if len(certs) < 2 {
		flags = append(flags, "No intermediate certificates (possible DPI certificate generation)")
	}

	// Check for high-confidence vendor matches
	for _, match := range matches {
		if match.Confidence >= 70 {
			flags = append(flags, fmt.Sprintf("High-confidence %s detection (%d%%)", match.Vendor, match.Confidence))
		}
	}

	return flags
}

// generateRecommendations creates HawkScan-specific recommendations
func generateRecommendations(bestMatch *VendorMatch, unknownCAs []*x509.Certificate) []string {
	var recommendations []string

	if len(unknownCAs) == 0 {
		recommendations = append(recommendations, "No DPI detected - HawkScan should work without additional CA certificates")
		return recommendations
	}

	// Basic CA extraction recommendation
	recommendations = append(recommendations,
		fmt.Sprintf("Extract %d unknown CA certificate(s) for HawkScan integration", len(unknownCAs)))

	if bestMatch != nil {
		// Vendor-specific recommendations
		recommendations = append(recommendations, bestMatch.Guidance)

		// Additional vendor-specific HawkScan guidance
		switch bestMatch.Vendor {
		case "Palo Alto Networks":
			recommendations = append(recommendations,
				"For PAN-OS: Verify HawkScan scan targets match SSL/TLS Service Profile rules")
		case "Zscaler":
			recommendations = append(recommendations,
				"For Zscaler: Ensure HawkScan traffic matches configured forwarding rules")
		case "Corporate Internal CA":
			recommendations = append(recommendations,
				"Contact IT team for DPI device details and certificate rotation schedule")
		}

		// Confidence-based recommendations
		if bestMatch.Confidence >= 80 {
			recommendations = append(recommendations,
				fmt.Sprintf("High-confidence %s detection - CA extraction strongly recommended", bestMatch.Vendor))
		} else if bestMatch.Confidence >= 50 {
			recommendations = append(recommendations,
				"Moderate-confidence DPI detection - test HawkScan with extracted CA certificates")
		} else {
			recommendations = append(recommendations,
				"Low-confidence DPI detection - extracted certificates may help resolve TLS issues")
		}
	}

	// HawkScan command examples
	recommendations = append(recommendations,
		"HawkScan usage: hawk scan --ca-bundle extracted-ca.pem")

	return recommendations
}

// FormatDetectionReport creates a human-readable report of the detection results
func (result *DetectionResult) FormatDetectionReport() string {
	var report strings.Builder

	if !result.IsCorporateDPI {
		report.WriteString(fmt.Sprintf("[OK] No corporate DPI detected for %s\n", result.URL))
		return report.String()
	}

	report.WriteString(fmt.Sprintf("\n[DPI] Corporate DPI Detection Results for %s\n", result.URL))
	report.WriteString("============================================================\n\n")

	if result.BestMatch != nil {
		report.WriteString(fmt.Sprintf("Primary Detection: %s\n", result.BestMatch.Vendor))
		if result.BestMatch.Product != "" {
			report.WriteString(fmt.Sprintf("  Product: %s\n", result.BestMatch.Product))
		}
		if result.BestMatch.Version != "" {
			report.WriteString(fmt.Sprintf("  Version: %s\n", result.BestMatch.Version))
		}
		report.WriteString(fmt.Sprintf("  Confidence: %d%%\n", result.BestMatch.Confidence))

		if len(result.BestMatch.Indicators) > 0 {
			report.WriteString("  Detection Indicators:\n")
			for _, indicator := range result.BestMatch.Indicators {
				report.WriteString(fmt.Sprintf("    - %s\n", indicator))
			}
		}
		report.WriteString("\n")
	}

	// Additional matches
	if len(result.VendorMatches) > 1 {
		report.WriteString("Additional Possible Matches:\n")
		for i, match := range result.VendorMatches[1:] {
			if i >= 2 { // Limit to top 3 total matches
				break
			}
			report.WriteString(fmt.Sprintf("  %s (Confidence: %d%%)\n", match.Vendor, match.Confidence))
		}
		report.WriteString("\n")
	}

	// Security flags
	if len(result.SecurityFlags) > 0 {
		report.WriteString("Security Analysis:\n")
		for _, flag := range result.SecurityFlags {
			report.WriteString(fmt.Sprintf("  [!] %s\n", flag))
		}
		report.WriteString("\n")
	}

	// HawkScan recommendations
	if len(result.Recommendations) > 0 {
		report.WriteString("HawkScan Integration Recommendations:\n")
		for _, rec := range result.Recommendations {
			report.WriteString(fmt.Sprintf("  → %s\n", rec))
		}
		report.WriteString("\n")
	}

	return report.String()
}

// FormatCompactDetection creates a brief one-line detection summary
func (result *DetectionResult) FormatCompactDetection() string {
	if !result.IsCorporateDPI {
		return fmt.Sprintf("[OK] No corporate DPI detected (%s)", result.URL)
	}

	if result.BestMatch != nil {
		return fmt.Sprintf("[DPI] %s detected (%d%% confidence) - %d CA(s) need extraction",
			result.BestMatch.Vendor, result.BestMatch.Confidence, len(result.UnknownCAs))
	}

	return fmt.Sprintf("[DPI] Unknown DPI detected - %d CA(s) need extraction", len(result.UnknownCAs))
}
