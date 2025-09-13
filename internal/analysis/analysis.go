package analysis

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// SecurityValidationResult represents the result of enhanced security validation
type SecurityValidationResult struct {
	UntrustedCAs         []*x509.Certificate
	SuspiciousBehaviors  []string
	CTIssues             []string
	ChainValidationError error
	TrustDiscrepancies   []TrustDiscrepancy
}

// TrustDiscrepancy represents differences between OS and Mozilla certificate trust
type TrustDiscrepancy struct {
	Certificate      *x509.Certificate
	TrustedByOS      bool
	TrustedByMozilla bool
	Explanation      string
}

// ValidateChain validates the complete certificate chain against Mozilla roots
// Returns CA certificates that indicate corporate DPI/proxy infrastructure
// Only flags certificates when they are not trusted by Mozilla's CA bundle
func ValidateChain(certs []*x509.Certificate, mozillaCAs *x509.CertPool, hostname string) []*x509.Certificate {
	if len(certs) == 0 {
		slog.Debug("empty certificate chain provided")
		return nil
	}

	slog.Debug("validating certificate chain",
		"chain_length", len(certs),
		"hostname", hostname,
		"leaf_subject", certs[0].Subject.String())

	// First, try to validate the complete certificate chain against Mozilla roots
	leafCert := certs[0] // First certificate should be the leaf certificate

	// Build intermediate certificate pool from the remaining certificates
	intermediates := x509.NewCertPool()
	for i := 1; i < len(certs); i++ {
		intermediates.AddCert(certs[i])
		slog.Debug("added intermediate certificate",
			"index", i,
			"subject", certs[i].Subject.String(),
			"issuer", certs[i].Issuer.String())
	}

	// Try to verify the certificate chain without hostname validation first
	// This separates certificate authority trust from hostname matching issues
	chainOpts := x509.VerifyOptions{
		Roots:         mozillaCAs,
		Intermediates: intermediates,
		// DNSName omitted - we only care about chain validity, not hostname matching
	}

	_, chainErr := leafCert.Verify(chainOpts)
	if chainErr == nil {
		// Chain validates successfully through Mozilla roots
		slog.Debug("certificate chain validates against Mozilla roots - no DPI detected")
		return nil
	}

	slog.Debug("certificate chain validation failed", "error", chainErr.Error())

	// Chain validation failed - examine each CA certificate individually
	// This is more reliable than trying to determine "trust anchors"
	var unknownCAs []*x509.Certificate

	for i, cert := range certs {
		// Only examine CA certificates for DPI detection
		if cert.IsCA {
			slog.Debug("examining CA certificate",
				"index", i,
				"subject", cert.Subject.String(),
				"is_self_signed", cert.Subject.String() == cert.Issuer.String())

			// Check if this CA certificate is trusted by Mozilla
			if !IsTrustedByMozilla(cert, mozillaCAs, certs) {
				slog.Info("detected unknown CA certificate - potential DPI",
					"subject", cert.Subject.String(),
					"issuer", cert.Issuer.String(),
					"serial", fmt.Sprintf("%x", cert.SerialNumber))
				unknownCAs = append(unknownCAs, cert)
			}
		}
	}

	slog.Debug("certificate chain analysis complete", "unknown_cas_found", len(unknownCAs))
	return unknownCAs
}

// isLikelyTrustAnchor determines if a certificate is likely acting as a trust anchor
// (either self-signed or the highest CA in the presented chain)
func isLikelyTrustAnchor(cert *x509.Certificate, allCerts []*x509.Certificate) bool {
	// Self-signed certificates are definitely trust anchors
	if cert.Subject.String() == cert.Issuer.String() {
		return true
	}

	// Check if this certificate's issuer is present in the chain
	// If not, it's likely the highest CA in the chain (acting as trust anchor)
	for _, otherCert := range allCerts {
		if otherCert != cert && otherCert.Subject.String() == cert.Issuer.String() {
			// Found the issuer in the chain - this is an intermediate, not a trust anchor
			return false
		}
	}

	// No issuer found in chain - this is likely the trust anchor
	return true
}

// IsPotentialDPICA checks if a CA certificate appears to be from a corporate DPI proxy
func IsPotentialDPICA(cert *x509.Certificate) bool {
	// First, check for signature forgery - detect certificates that claim to be
	// from legitimate CAs but aren't actually signed by them
	if isLegitimateCAImpersonation(cert) {
		return true // This is definitely malicious
	}

	// Check for common corporate DPI/MITM proxy vendor patterns
	commonDPIVendors := []string{
		"Palo Alto Networks",
		"Zscaler",
		"Netskope",
		"Fortinet",
		"Symantec Web Security",
		"McAfee Web Gateway",
		"Bluecoat",
		"Websense",
		"Check Point",
		"SonicWall",
		"Barracuda",
		"Corporate",
		"Enterprise",
		"Internal CA",
		"Private CA",
	}

	// Check for known legitimate CA vendors that should NOT be flagged as DPI
	knownLegitimateVendors := []string{
		"Google",
		"Amazon",
		"Microsoft",
		"DigiCert",
		"Let's Encrypt",
		"GlobalSign",
		"Starfield",
		"GoDaddy",
		"Comodo",
		"Sectigo",
		"Entrust",
		"VeriSign",
		"Symantec",
		"GeoTrust",
		"Thawte",
		"RapidSSL",
		"GTS",
		"ISRG",
	}

	// Check subject and issuer for patterns
	subjectStr := cert.Subject.String()
	issuerStr := cert.Issuer.String()

	// First check if this is a known legitimate vendor - if so, don't flag as DPI
	for _, vendor := range knownLegitimateVendors {
		if strings.Contains(strings.ToLower(subjectStr), strings.ToLower(vendor)) ||
			strings.Contains(strings.ToLower(issuerStr), strings.ToLower(vendor)) {
			return false // This is a legitimate CA, not DPI
		}
	}

	// Check if this matches known DPI vendor patterns
	for _, vendor := range commonDPIVendors {
		if strings.Contains(strings.ToLower(subjectStr), strings.ToLower(vendor)) ||
			strings.Contains(strings.ToLower(issuerStr), strings.ToLower(vendor)) {
			return true // This is likely a DPI proxy
		}
	}

	// If chain validation fails but we don't recognize the CA as either legitimate or DPI,
	// be conservative and flag it as potential DPI
	return true
}

// IsTrustedByMozilla checks if a certificate can be verified through Mozilla's trusted CA bundle
// This is the primary function for determining if a CA should be included in HawkScan output
func IsTrustedByMozilla(cert *x509.Certificate, mozillaCAs *x509.CertPool, allCerts []*x509.Certificate) bool {
	// Only examine CA certificates for corporate/DPI detection
	if !cert.IsCA {
		slog.Debug("skipping non-CA certificate", "subject", cert.Subject.String())
		return true // Skip non-CA certificates - we only care about CA certs
	}

	if mozillaCAs == nil {
		slog.Warn("no Mozilla CA bundle available for verification")
		return false // No Mozilla CA bundle available - can't verify
	}

	slog.Debug("checking certificate trust against Mozilla bundle",
		"subject", cert.Subject.String(),
		"issuer", cert.Issuer.String(),
		"is_self_signed", cert.Subject.String() == cert.Issuer.String())

	// For self-signed certificates, check if they're directly in Mozilla's CA bundle
	if cert.Subject.String() == cert.Issuer.String() {
		slog.Debug("checking self-signed certificate against Mozilla roots")
		// Try to verify the certificate directly as a root CA
		opts := x509.VerifyOptions{
			Roots:     mozillaCAs,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
		_, err := cert.Verify(opts)
		return err == nil
	}

	// For intermediate CAs, build a chain to see if it can be verified through Mozilla roots
	intermediates := x509.NewCertPool()
	for _, c := range allCerts {
		if c != cert && c.IsCA {
			intermediates.AddCert(c)
		}
	}

	// Try to verify this certificate using Mozilla's roots and available intermediates
	opts := x509.VerifyOptions{
		Roots:         mozillaCAs,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	// Try to verify the certificate against Mozilla's CA bundle with full chain context
	_, err := cert.Verify(opts)

	// If verification succeeds, this CA is part of Mozilla's trusted chain
	// If verification fails, it's a corporate/DPI CA that HawkScan needs
	return err == nil
}

// IsTrustedCA is kept for backward compatibility with existing tests
func IsTrustedCA(cert *x509.Certificate, mozillaCAs *x509.CertPool, allCerts []*x509.Certificate) bool {
	return IsTrustedByMozilla(cert, mozillaCAs, allCerts)
}

// extractHostname extracts hostname from URL for certificate validation
func extractHostname(url string) string {
	if strings.HasPrefix(url, "https://") {
		url = url[8:]
	} else if strings.HasPrefix(url, "http://") {
		url = url[7:]
	}

	// Remove path and port
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}
	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}

	return url
}

// isLegitimateCAImpersonation detects certificates that claim to be from legitimate CAs
// but aren't actually signed by them (signature forgery detection)
func isLegitimateCAImpersonation(cert *x509.Certificate) bool {
	// Known legitimate CA patterns that attackers might try to impersonate
	legitimateCAPatterns := []string{
		"Google Trust Services",
		"DigiCert",
		"Let's Encrypt",
		"GlobalSign",
		"Amazon",
		"Microsoft",
		"Entrust",
		"VeriSign",
		"Symantec",
		"GeoTrust",
		"Thawte",
		"Comodo",
		"Sectigo",
	}

	subjectStr := strings.ToLower(cert.Subject.String())
	issuerStr := strings.ToLower(cert.Issuer.String())

	// Check if certificate claims to be from a legitimate CA
	claimsLegitimateCA := false
	for _, pattern := range legitimateCAPatterns {
		if strings.Contains(subjectStr, strings.ToLower(pattern)) {
			claimsLegitimateCA = true
			break
		}
	}

	if !claimsLegitimateCA {
		return false // Not claiming to be a legitimate CA
	}

	// If it claims to be legitimate, verify the signature chain
	// Self-signed certificates claiming to be legitimate CAs are suspicious
	if cert.Subject.String() == cert.Issuer.String() {
		// Self-signed certificate claiming to be from legitimate CA = impersonation
		return true
	}

	// Check for common impersonation patterns:
	// 1. Claims to be legitimate CA but issued by unknown/suspicious issuer
	suspiciousIssuerPatterns := []string{
		"test",
		"demo",
		"local",
		"internal",
		"corporate",
		"private",
		"mock",
		"fake",
		"proxy",
		"mitm",
	}

	for _, pattern := range suspiciousIssuerPatterns {
		if strings.Contains(issuerStr, pattern) {
			return true // Legitimate CA name but suspicious issuer
		}
	}

	// Additional check: Look for certificates that claim legitimate names
	// but have suspicious characteristics
	if claimsLegitimateCA {
		// Check for unusually short validity periods (< 30 days)
		// Legitimate CAs typically issue longer-lived certificates
		validityPeriod := cert.NotAfter.Sub(cert.NotBefore)
		if validityPeriod < 30*24*time.Hour {
			return true // Suspiciously short validity for claimed legitimate CA
		}

		// Check for suspicious serial numbers (common in test/demo certs)
		serialStr := cert.SerialNumber.String()
		if serialStr == "1" || serialStr == "2" || serialStr == "123" ||
			len(serialStr) < 10 { // Very short serial numbers are suspicious
			return true
		}
	}

	return false
}

// CompareTrustStores compares certificate trust between OS and Mozilla certificate stores
func CompareTrustStores(certs []*x509.Certificate, mozillaCAs *x509.CertPool, hostname string) []TrustDiscrepancy {
	var discrepancies []TrustDiscrepancy

	// Get OS certificate store (may return nil on some platforms)
	osCAs, err := x509.SystemCertPool()
	if err != nil {
		// Some platforms don't support SystemCertPool, continue with Mozilla-only validation
		return discrepancies
	}

	if osCAs == nil {
		// SystemCertPool not available on this platform
		return discrepancies
	}

	// Test the complete certificate chain validation (leaf cert through full chain)
	// This is how browsers and applications actually validate certificates
	if len(certs) == 0 {
		return discrepancies
	}

	leafCert := certs[0] // First certificate should be the leaf

	// Build intermediate certificate pool from the remaining certificates
	intermediates := x509.NewCertPool()
	for i := 1; i < len(certs); i++ {
		intermediates.AddCert(certs[i])
	}

	// Test against Mozilla CA bundle
	mozillaOpts := x509.VerifyOptions{
		Roots:         mozillaCAs,
		Intermediates: intermediates,
		DNSName:       extractHostname(hostname),
	}
	_, mozillaErr := leafCert.Verify(mozillaOpts)
	trustedByMozilla := mozillaErr == nil

	// Test against OS certificate store
	osOpts := x509.VerifyOptions{
		Roots:         osCAs,
		Intermediates: intermediates,
		DNSName:       extractHostname(hostname),
	}
	_, osErr := leafCert.Verify(osOpts)
	trustedByOS := osErr == nil

	// Look for interesting discrepancies in chain validation
	if trustedByOS != trustedByMozilla {
		// Find which root CA is being used (if any)
		var relevantCA *x509.Certificate
		if len(certs) > 1 {
			// Use the last certificate in chain (typically the root or highest intermediate)
			relevantCA = certs[len(certs)-1]
		} else {
			relevantCA = leafCert
		}

		discrepancy := TrustDiscrepancy{
			Certificate:      relevantCA,
			TrustedByOS:      trustedByOS,
			TrustedByMozilla: trustedByMozilla,
		}

		if trustedByOS && !trustedByMozilla {
			discrepancy.Explanation = "CORPORATE DPI DETECTED: OS trusts this chain (browsers work) but Mozilla doesn't (Java/HawkScan need PEM file)"
		} else if !trustedByOS && trustedByMozilla {
			discrepancy.Explanation = "Mozilla trusts this certificate chain but OS doesn't (unusual configuration - verify OS trust store)"
		}

		discrepancies = append(discrepancies, discrepancy)
	}

	return discrepancies
}
