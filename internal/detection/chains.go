package detection

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

// ChainAnalysis contains analysis of certificate chain structure patterns
type ChainAnalysis struct {
	ChainLength          int
	HasSelfSignedLeaf    bool
	HasMissingIntermediates bool
	SuspiciousPatterns   []string
	VendorIndicators     []string
	StructureScore       int // 0-100 score for how suspicious the chain structure is
}

// AnalyzeChainStructure examines certificate chain for DPI-specific patterns
func AnalyzeChainStructure(certs []*x509.Certificate) *ChainAnalysis {
	analysis := &ChainAnalysis{
		ChainLength:        len(certs),
		SuspiciousPatterns: []string{},
		VendorIndicators:   []string{},
	}
	
	if len(certs) == 0 {
		return analysis
	}
	
	leafCert := certs[0]
	
	// Check for self-signed leaf certificate
	if leafCert.Issuer.String() == leafCert.Subject.String() {
		analysis.HasSelfSignedLeaf = true
		analysis.SuspiciousPatterns = append(analysis.SuspiciousPatterns, 
			"Self-signed leaf certificate (strong DPI indicator)")
		analysis.StructureScore += 40
	}
	
	// Analyze chain length patterns
	analysis.analyzeChainLength(certs)
	
	// Look for missing intermediate certificates
	analysis.detectMissingIntermediates(certs)
	
	// Check for vendor-specific chain structures
	analysis.detectVendorChainPatterns(certs)
	
	// Analyze certificate relationships
	analysis.analyzeCertificateRelationships(certs)
	
	// Check for temporal anomalies (certificates issued at suspicious times)
	analysis.analyzeTemporalPatterns(certs)
	
	return analysis
}

// analyzeChainLength examines if the chain length is suspicious
func (analysis *ChainAnalysis) analyzeChainLength(certs []*x509.Certificate) {
	chainLen := len(certs)
	
	switch chainLen {
	case 1:
		analysis.SuspiciousPatterns = append(analysis.SuspiciousPatterns,
			"Single certificate chain (possible DPI certificate generation)")
		analysis.StructureScore += 30
		
	case 2:
		// Two-cert chains are common in DPI environments (leaf + self-signed root)
		if len(certs) >= 2 && certs[1].Issuer.String() == certs[1].Subject.String() {
			analysis.SuspiciousPatterns = append(analysis.SuspiciousPatterns,
				"Two-certificate chain with self-signed root (common DPI pattern)")
			analysis.StructureScore += 25
		}
		
	case 3:
		// Three certificates is normal for many legitimate sites, but check the structure
		analysis.VendorIndicators = append(analysis.VendorIndicators,
			"Three-certificate chain (typical for legitimate sites)")
		
	default:
		if chainLen > 4 {
			analysis.SuspiciousPatterns = append(analysis.SuspiciousPatterns,
				fmt.Sprintf("Unusually long certificate chain (%d certificates)", chainLen))
			analysis.StructureScore += 15
		}
	}
}

// detectMissingIntermediates checks for gaps in the certificate chain
func (analysis *ChainAnalysis) detectMissingIntermediates(certs []*x509.Certificate) {
	if len(certs) < 2 {
		analysis.HasMissingIntermediates = true
		return
	}
	
	// Check if each certificate properly chains to the next
	for i := 0; i < len(certs)-1; i++ {
		current := certs[i]
		next := certs[i+1]
		
		// The current certificate should be issued by the next certificate
		if current.Issuer.String() != next.Subject.String() {
			analysis.HasMissingIntermediates = true
			analysis.SuspiciousPatterns = append(analysis.SuspiciousPatterns,
				fmt.Sprintf("Chain gap between certificate %d and %d", i+1, i+2))
			analysis.StructureScore += 20
		}
	}
}

// detectVendorChainPatterns looks for vendor-specific certificate chain structures
func (analysis *ChainAnalysis) detectVendorChainPatterns(certs []*x509.Certificate) {
	if len(certs) == 0 {
		return
	}
	
	leafCert := certs[0]
	leafSubject := strings.ToLower(leafCert.Subject.String())
	leafIssuer := strings.ToLower(leafCert.Issuer.String())
	
	// Palo Alto specific patterns
	if strings.Contains(leafSubject, "palo alto") || strings.Contains(leafIssuer, "palo alto") {
		analysis.VendorIndicators = append(analysis.VendorIndicators,
			"Palo Alto Networks certificate pattern detected")
		
		// PAN-OS often uses specific validity periods
		validityDays := leafCert.NotAfter.Sub(leafCert.NotBefore).Hours() / 24
		if validityDays >= 364 && validityDays <= 366 {
			analysis.VendorIndicators = append(analysis.VendorIndicators,
				"PAN-OS typical 1-year validity period")
		}
	}
	
	// Zscaler specific patterns
	if strings.Contains(leafSubject, "zscaler") || strings.Contains(leafIssuer, "zscaler") {
		analysis.VendorIndicators = append(analysis.VendorIndicators,
			"Zscaler certificate pattern detected")
		
		// Zscaler often uses 90-day rotation
		validityDays := leafCert.NotAfter.Sub(leafCert.NotBefore).Hours() / 24
		if validityDays >= 85 && validityDays <= 95 {
			analysis.VendorIndicators = append(analysis.VendorIndicators,
				"Zscaler typical 90-day rotation period")
		}
	}
	
	// Check for generic corporate patterns
	corporateTerms := []string{"corporate", "company", "internal", "proxy", "gateway", "firewall"}
	for _, term := range corporateTerms {
		if strings.Contains(leafSubject, term) || strings.Contains(leafIssuer, term) {
			analysis.VendorIndicators = append(analysis.VendorIndicators,
				fmt.Sprintf("Corporate infrastructure term detected: %s", term))
			analysis.StructureScore += 10
		}
	}
}

// analyzeCertificateRelationships examines how certificates relate to each other
func (analysis *ChainAnalysis) analyzeCertificateRelationships(certs []*x509.Certificate) {
	if len(certs) < 2 {
		return
	}
	
	// Look for certificates issued by the same CA with identical properties
	for i := 0; i < len(certs); i++ {
		for j := i + 1; j < len(certs); j++ {
			cert1, cert2 := certs[i], certs[j]
			
			// Same issuer and subject (duplicate certificates)
			if cert1.Issuer.String() == cert2.Issuer.String() && 
			   cert1.Subject.String() == cert2.Subject.String() {
				analysis.SuspiciousPatterns = append(analysis.SuspiciousPatterns,
					"Duplicate certificates in chain")
				analysis.StructureScore += 25
			}
			
			// Check for certificates issued at nearly the same time (batch generation)
			timeDiff := cert1.NotBefore.Sub(cert2.NotBefore)
			if timeDiff < 0 {
				timeDiff = -timeDiff
			}
			
			if timeDiff < time.Hour {
				analysis.SuspiciousPatterns = append(analysis.SuspiciousPatterns,
					"Certificates issued within same hour (possible batch generation)")
				analysis.StructureScore += 15
			}
		}
	}
}

// analyzeTemporalPatterns examines certificate issuance timing for suspicious patterns
func (analysis *ChainAnalysis) analyzeTemporalPatterns(certs []*x509.Certificate) {
	now := time.Now()
	
	for i, cert := range certs {
		// Very recently issued certificates (< 24 hours)
		if cert.NotBefore.After(now.Add(-24 * time.Hour)) {
			analysis.SuspiciousPatterns = append(analysis.SuspiciousPatterns,
				fmt.Sprintf("Certificate %d issued very recently (< 24 hours)", i+1))
			analysis.StructureScore += 20
		}
		
		// Future-dated certificates
		if cert.NotBefore.After(now) {
			analysis.SuspiciousPatterns = append(analysis.SuspiciousPatterns,
				fmt.Sprintf("Certificate %d is future-dated", i+1))
			analysis.StructureScore += 30
		}
		
		// Check for weekend issuance (less common for legitimate CAs)
		weekday := cert.NotBefore.Weekday()
		if weekday == time.Saturday || weekday == time.Sunday {
			// This is actually pretty common, so low score
			analysis.VendorIndicators = append(analysis.VendorIndicators,
				fmt.Sprintf("Certificate %d issued on weekend", i+1))
		}
	}
}

// AnalyzeCertificateProperties examines individual certificate properties for DPI indicators
func AnalyzeCertificateProperties(cert *x509.Certificate) []string {
	var indicators []string
	
	// Check key size and algorithm
	switch pubKey := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		keySize := pubKey.N.BitLen()
		if keySize < 2048 {
			indicators = append(indicators, fmt.Sprintf("Weak RSA key size: %d bits", keySize))
		}
		
	// Note: We'd add more key types here (ECDSA, etc.) but keeping it simple for now
	}
	
	// Check for suspicious serial numbers
	serialStr := cert.SerialNumber.String()
	if len(serialStr) <= 3 {
		indicators = append(indicators, "Suspiciously short serial number: "+serialStr)
	}
	
	// Common DPI serial number patterns
	commonDPISerials := []string{"1", "123", "1000", "0"}
	for _, pattern := range commonDPISerials {
		if serialStr == pattern {
			indicators = append(indicators, "Common DPI serial number pattern: "+pattern)
			break
		}
	}
	
	// Check signature algorithm
	sigAlgo := cert.SignatureAlgorithm.String()
	if strings.Contains(strings.ToLower(sigAlgo), "md5") {
		indicators = append(indicators, "Weak signature algorithm: MD5")
	}
	if strings.Contains(strings.ToLower(sigAlgo), "sha1") {
		indicators = append(indicators, "Legacy signature algorithm: SHA1")
	}
	
	// Check for missing or unusual extensions
	if !cert.BasicConstraintsValid {
		indicators = append(indicators, "Missing BasicConstraints extension")
	}
	
	// Check subject alternative names for suspicious patterns
	if len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 {
		indicators = append(indicators, "No Subject Alternative Names (SAN)")
	}
	
	// Look for wildcard certificates (common in DPI)
	for _, dnsName := range cert.DNSNames {
		if strings.HasPrefix(dnsName, "*.") {
			indicators = append(indicators, "Wildcard certificate: "+dnsName)
		}
	}
	
	return indicators
}

// GetStructureSeverity converts structure score to severity level
func (analysis *ChainAnalysis) GetStructureSeverity() string {
	switch {
	case analysis.StructureScore >= 70:
		return "HIGH - Strong DPI indicators"
	case analysis.StructureScore >= 40:
		return "MEDIUM - Possible DPI characteristics"
	case analysis.StructureScore >= 20:
		return "LOW - Some suspicious patterns"
	default:
		return "MINIMAL - Mostly normal structure"
	}
}