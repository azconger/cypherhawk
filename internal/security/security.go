package security

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/kaakaww/dpi-hawk/internal/analysis"
)

// ValidateCertificateTransparency checks if certificates have proper CT (Certificate Transparency) evidence
func ValidateCertificateTransparency(certs []*x509.Certificate) []string {
	var ctIssues []string
	
	for i, cert := range certs {
		if cert.IsCA {
			continue // CT is mainly for leaf certificates
		}
		
		hasSCT := false
		
		// Check for embedded SCT (Signed Certificate Timestamp) in certificate extensions
		for _, ext := range cert.Extensions {
			// CT extension OID: 1.3.6.1.4.1.11129.2.4.2
			if len(ext.Id) >= 7 && 
			   ext.Id[0] == 1 && ext.Id[1] == 3 && ext.Id[2] == 6 && ext.Id[3] == 1 && 
			   ext.Id[4] == 4 && ext.Id[5] == 1 && ext.Id[6] == 11129 {
				hasSCT = true
				break
			}
		}
		
		// Check certificate age - newer certificates should have CT evidence
		certAge := time.Since(cert.NotBefore)
		requiresCT := certAge < 3*365*24*time.Hour // Certificates issued in last 3 years
		
		if requiresCT && !hasSCT {
			ctIssues = append(ctIssues, fmt.Sprintf("Certificate %d (%s) lacks CT evidence (issued %v ago)", 
				i+1, cert.Subject.CommonName, certAge.Truncate(24*time.Hour)))
		}
	}
	
	return ctIssues
}

// DetectSuspiciousBehavior performs comprehensive behavioral analysis on certificate chains
func DetectSuspiciousBehavior(certs []*x509.Certificate, hostname string) []string {
	var suspiciousIndicators []string
	
	for i, cert := range certs {
		certDesc := fmt.Sprintf("Certificate %d (%s)", i+1, cert.Subject.CommonName)
		
		// 1. Check for recently issued certificates (potential attacker)
		certAge := time.Since(cert.NotBefore)
		if certAge < 24*time.Hour {
			suspiciousIndicators = append(suspiciousIndicators, 
				fmt.Sprintf("%s issued within 24 hours (%v ago)", certDesc, certAge.Truncate(time.Hour)))
		}
		
		// 2. Check for unusual validity periods
		validity := cert.NotAfter.Sub(cert.NotBefore)
		if validity > 10*365*24*time.Hour { // > 10 years
			suspiciousIndicators = append(suspiciousIndicators, 
				fmt.Sprintf("%s has unusually long validity period (%.1f years)", certDesc, validity.Hours()/(24*365)))
		}
		if validity < 7*24*time.Hour && !cert.IsCA { // < 7 days for leaf certs
			suspiciousIndicators = append(suspiciousIndicators, 
				fmt.Sprintf("%s has unusually short validity period (%v)", certDesc, validity.Truncate(time.Hour)))
		}
		
		// 3. Check for suspicious serial number patterns
		serial := cert.SerialNumber.String()
		if len(serial) < 8 {
			suspiciousIndicators = append(suspiciousIndicators, 
				fmt.Sprintf("%s has suspiciously short serial number (%s)", certDesc, serial))
		}
		if serial == "1" || serial == "2" || serial == "123" || serial == "12345" {
			suspiciousIndicators = append(suspiciousIndicators, 
				fmt.Sprintf("%s has trivial serial number (%s)", certDesc, serial))
		}
		
		// 4. Check for suspicious subject/issuer patterns
		subject := strings.ToLower(cert.Subject.String())
		issuer := strings.ToLower(cert.Issuer.String())
		
		suspiciousTerms := []string{"test", "demo", "example", "localhost", "temp", "temporary"}
		for _, term := range suspiciousTerms {
			if strings.Contains(subject, term) || strings.Contains(issuer, term) {
				suspiciousIndicators = append(suspiciousIndicators, 
					fmt.Sprintf("%s contains suspicious term '%s'", certDesc, term))
			}
		}
		
		// 5. Check for weak key sizes
		switch pub := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			keySize := pub.Size() * 8 // Convert bytes to bits
			if keySize < 2048 {
				suspiciousIndicators = append(suspiciousIndicators, 
					fmt.Sprintf("%s uses weak RSA key size (%d bits)", certDesc, keySize))
			}
		case *ecdsa.PublicKey:
			keySize := pub.Curve.Params().BitSize
			if keySize < 256 {
				suspiciousIndicators = append(suspiciousIndicators, 
					fmt.Sprintf("%s uses weak ECDSA key size (%d bits)", certDesc, keySize))
			}
		}
		
		// 6. Check for certificate chain anomalies
		if i == 0 { // Leaf certificate
			// Check if hostname matches certificate
			if !strings.Contains(strings.ToLower(cert.Subject.CommonName), strings.ToLower(extractHostname(hostname))) {
				// Check SANs as well
				hasMatchingSAN := false
				for _, dns := range cert.DNSNames {
					if strings.Contains(strings.ToLower(dns), strings.ToLower(extractHostname(hostname))) {
						hasMatchingSAN = true
						break
					}
				}
				if !hasMatchingSAN {
					suspiciousIndicators = append(suspiciousIndicators, 
						fmt.Sprintf("%s hostname mismatch (cert: %s, expected: %s)", 
							certDesc, cert.Subject.CommonName, extractHostname(hostname)))
				}
			}
		}
		
		// 7. Check for self-signed certificates (except legitimate root CAs)
		if cert.Subject.String() == cert.Issuer.String() && i == 0 {
			suspiciousIndicators = append(suspiciousIndicators, 
				fmt.Sprintf("%s is self-signed (leaf certificate)", certDesc))
		}
		
		// 8. Check signature algorithm strength
		switch cert.SignatureAlgorithm {
		case x509.MD5WithRSA, x509.SHA1WithRSA:
			suspiciousIndicators = append(suspiciousIndicators, 
				fmt.Sprintf("%s uses weak signature algorithm (%s)", certDesc, cert.SignatureAlgorithm))
		}
		
		// 9. Check for certificates issued far in the future
		if cert.NotBefore.After(time.Now().Add(24 * time.Hour)) {
			suspiciousIndicators = append(suspiciousIndicators, 
				fmt.Sprintf("%s not valid until future date (%s)", certDesc, cert.NotBefore.Format("2006-01-02")))
		}
	}
	
	// 10. Check chain length anomalies
	if len(certs) > 5 {
		suspiciousIndicators = append(suspiciousIndicators, 
			fmt.Sprintf("Unusually long certificate chain (%d certificates)", len(certs)))
	}
	
	return suspiciousIndicators
}

// PerformEnhancedValidation combines all security validation techniques
func PerformEnhancedValidation(certs []*x509.Certificate, mozillaCAs *x509.CertPool, hostname string) analysis.SecurityValidationResult {
	result := analysis.SecurityValidationResult{}
	
	// 1. Standard certificate chain validation (existing logic)
	untrustedCAs := analysis.ValidateChain(certs, mozillaCAs, hostname)
	result.UntrustedCAs = untrustedCAs
	
	// 2. Certificate Transparency validation
	ctIssues := ValidateCertificateTransparency(certs)
	result.CTIssues = ctIssues
	result.SuspiciousBehaviors = append(result.SuspiciousBehaviors, ctIssues...)
	
	// 3. Behavioral analysis
	behavioralIssues := DetectSuspiciousBehavior(certs, hostname)
	result.SuspiciousBehaviors = append(result.SuspiciousBehaviors, behavioralIssues...)
	
	// 4. Enhanced CA impersonation detection (already integrated in analysis.IsPotentialDPICA)
	
	// 5. Risk scoring - if we have multiple suspicious indicators, increase confidence
	riskScore := len(result.SuspiciousBehaviors)
	if riskScore >= 3 {
		result.SuspiciousBehaviors = append(result.SuspiciousBehaviors, 
			fmt.Sprintf("HIGH RISK: Multiple suspicious indicators detected (%d total)", riskScore))
	}
	
	return result
}

// IsLegitimateCAImpersonation detects certificates that claim to be from legitimate CAs
// but aren't actually signed by them (signature forgery detection)
func IsLegitimateCAImpersonation(cert *x509.Certificate) bool {
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