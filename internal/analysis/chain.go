package analysis

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// ChainAnalysis provides detailed analysis of a certificate chain
type ChainAnalysis struct {
	Endpoint           string
	Certificates       []CertificateInfo
	Summary            ChainSummary
	DPIClues           []string
	MitMClues          []string
	Anomalies          []string
	TrustDiscrepancies []TrustDiscrepancy
}

// CertificateInfo contains details about a single certificate
type CertificateInfo struct {
	Position     int    // 1-based position in chain
	Type         string // "Leaf", "Intermediate", "Root"
	Subject      string
	Issuer       string
	SerialNumber string
	NotBefore    time.Time
	NotAfter     time.Time
	KeyInfo      KeyInfo
	SignatureAlg string
	IsTrusted    bool
	IsCA         bool
	Issues       []string
}

// ChainSummary provides overview of the certificate chain
type ChainSummary struct {
	TotalCerts      int
	LeafCerts       int
	Intermediate    int
	RootCerts       int
	TrustedChain    bool
	SuspiciousCount int
}

// AnalyzeCertificateChain performs comprehensive analysis of a certificate chain
func AnalyzeCertificateChain(endpoint string, certs []*x509.Certificate, mozillaCAs *x509.CertPool) *ChainAnalysis {
	analysis := &ChainAnalysis{
		Endpoint:     endpoint,
		Certificates: make([]CertificateInfo, len(certs)),
		Summary: ChainSummary{
			TotalCerts: len(certs),
		},
	}

	// Analyze each certificate
	for i, cert := range certs {
		certInfo := analyzeCertificate(cert, i+1, certs, mozillaCAs)
		analysis.Certificates[i] = certInfo

		// Update summary counts
		switch certInfo.Type {
		case "Leaf":
			analysis.Summary.LeafCerts++
		case "Intermediate":
			analysis.Summary.Intermediate++
		case "Root":
			analysis.Summary.RootCerts++
		}

		if len(certInfo.Issues) > 0 {
			analysis.Summary.SuspiciousCount++
		}
	}

	// Check overall chain trust
	analysis.Summary.TrustedChain = hasValidTrustPath(certs, mozillaCAs)

	// Detect DPI/MitM clues
	analysis.DPIClues = detectDPIClues(certs, endpoint)
	analysis.MitMClues = detectMitMClues(certs, endpoint)
	analysis.Anomalies = detectChainAnomalies(certs)

	// Compare trust stores (OS vs Mozilla)
	analysis.TrustDiscrepancies = CompareTrustStores(certs, mozillaCAs, endpoint)

	return analysis
}

// analyzeCertificate analyzes a single certificate
func analyzeCertificate(cert *x509.Certificate, position int, chain []*x509.Certificate, mozillaCAs *x509.CertPool) CertificateInfo {
	info := CertificateInfo{
		Position:     position,
		Subject:      cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		IsCA:         cert.IsCA,
		SignatureAlg: cert.SignatureAlgorithm.String(),
	}

	// Determine certificate type
	if position == 1 {
		info.Type = "Leaf"
	} else if cert.IsCA {
		if isRootCertificate(cert, position, len(chain)) {
			info.Type = "Root"
		} else {
			info.Type = "Intermediate"
		}
	} else {
		info.Type = "Unknown"
	}

	// Get key information
	info.KeyInfo = getKeyInfo(cert)

	// Check if trusted - for display purposes, base this on the overall chain trust
	// Individual intermediate CAs don't need to be independently trusted
	info.IsTrusted = hasValidTrustPath(chain, mozillaCAs)

	// Detect issues
	info.Issues = detectCertificateIssues(cert, chain)

	return info
}

// detectDPIClues identifies signs of corporate DPI
func detectDPIClues(certs []*x509.Certificate, endpoint string) []string {
	var clues []string

	for _, cert := range certs {
		if !cert.IsCA {
			continue
		}

		// Check for DPI vendor patterns
		subject := strings.ToLower(cert.Subject.String())
		issuer := strings.ToLower(cert.Issuer.String())

		dpiVendors := []string{
			"palo alto", "zscaler", "netskope", "forcepoint", "cisco", "bluecoat",
			"mcafee", "symantec proxy", "websense", "checkpoint", "fortinet",
			"sophos", "barracuda", "iboss", "lightspeed", "contentkeeper",
		}

		for _, vendor := range dpiVendors {
			if strings.Contains(subject, vendor) || strings.Contains(issuer, vendor) {
				clues = append(clues, fmt.Sprintf("DPI vendor detected: %s in certificate", vendor))
			}
		}

		// Check for corporate DPI patterns
		corporateTerms := []string{
			"corporate", "enterprise", "firewall", "proxy", "inspection",
			"security", "gateway", "filter", "protection", "monitor",
		}

		for _, term := range corporateTerms {
			if strings.Contains(subject, term) || strings.Contains(issuer, term) {
				clues = append(clues, fmt.Sprintf("Corporate DPI term: '%s' found", term))
			}
		}

		// Check for self-signed corporate CAs
		if isSelfSigned(cert) && !IsTrustedCA(cert, nil, certs) {
			clues = append(clues, "Unknown self-signed CA (likely corporate DPI)")
		}
	}

	return clues
}

// detectMitMClues identifies signs of malicious MitM
func detectMitMClues(certs []*x509.Certificate, endpoint string) []string {
	var clues []string

	// Check for CA impersonation
	for _, cert := range certs {
		if cert.IsCA && isCAImpersonation(cert) {
			clues = append(clues, fmt.Sprintf("CA impersonation detected: %s", cert.Subject.CommonName))
		}
	}

	// Check for high-risk behaviors
	highRiskIndicators := 0
	for _, cert := range certs {
		if containsWeakSignature(cert) {
			highRiskIndicators++
		}
		if hasTrivialSerial(cert) {
			highRiskIndicators++
		}
		if containsSuspiciousTerms(cert) {
			highRiskIndicators++
		}
	}

	if highRiskIndicators >= 3 {
		clues = append(clues, fmt.Sprintf("HIGH RISK: %d suspicious behaviors detected", highRiskIndicators))
	}

	// Check for timing anomalies
	for _, cert := range certs {
		if time.Since(cert.NotBefore) < 24*time.Hour {
			clues = append(clues, "Recently issued certificate (potential attack)")
		}

		validity := cert.NotAfter.Sub(cert.NotBefore)
		if validity < 7*24*time.Hour {
			clues = append(clues, "Unusually short certificate validity period")
		}
	}

	return clues
}

// Helper functions for MitM detection

func isCAImpersonation(cert *x509.Certificate) bool {
	subject := strings.ToLower(cert.Subject.String())

	// Known legitimate CA names that shouldn't appear in corporate DPI
	legitimateCAs := []string{
		"google trust services", "digicert", "let's encrypt", "comodo",
		"symantec", "globalsign", "entrust", "geotrust", "thawte",
		"godaddy", "rapidssl", "starfield", "amazon", "microsoft",
	}

	for _, ca := range legitimateCAs {
		if strings.Contains(subject, ca) {
			// Check if this is actually signed by the legitimate CA
			// If self-signed or has other suspicious characteristics, it's likely impersonation
			if isSelfSigned(cert) {
				return true
			}
		}
	}

	return false
}

func containsWeakSignature(cert *x509.Certificate) bool {
	return strings.Contains(strings.ToLower(cert.SignatureAlgorithm.String()), "sha1")
}

func hasTrivialSerial(cert *x509.Certificate) bool {
	return cert.SerialNumber.Cmp(big.NewInt(1000)) < 0
}

func containsSuspiciousTerms(cert *x509.Certificate) bool {
	subject := strings.ToLower(cert.Subject.String())
	suspiciousTerms := []string{"test", "demo", "localhost", "example", "invalid"}

	for _, term := range suspiciousTerms {
		if strings.Contains(subject, term) {
			return true
		}
	}
	return false
}

// detectChainAnomalies identifies structural problems in the certificate chain
func detectChainAnomalies(certs []*x509.Certificate) []string {
	var anomalies []string

	if len(certs) == 0 {
		return []string{"No certificates in chain"}
	}

	// Check for missing intermediate certificates
	if len(certs) == 2 && certs[1].IsCA && isSelfSigned(certs[1]) {
		// Direct leaf -> root (missing intermediates possible)
		anomalies = append(anomalies, "Potentially missing intermediate certificates")
	}

	// Check for unusual chain length
	if len(certs) > 5 {
		anomalies = append(anomalies, fmt.Sprintf("Unusually long certificate chain (%d certificates)", len(certs)))
	}

	// Check for multiple leaf certificates
	leafCount := 0
	for _, cert := range certs {
		if !cert.IsCA {
			leafCount++
		}
	}
	if leafCount > 1 {
		anomalies = append(anomalies, fmt.Sprintf("Multiple leaf certificates found (%d)", leafCount))
	}

	// Check for broken chain order
	for i := 0; i < len(certs)-1; i++ {
		if !isSignedBy(certs[i], certs[i+1]) {
			anomalies = append(anomalies, fmt.Sprintf("Broken chain: cert %d not signed by cert %d", i+1, i+2))
		}
	}

	return anomalies
}

// detectCertificateIssues finds problems with individual certificates
func detectCertificateIssues(cert *x509.Certificate, chain []*x509.Certificate) []string {
	var issues []string

	// Check expiration
	if time.Now().After(cert.NotAfter) {
		issues = append(issues, "Certificate expired")
	} else if time.Until(cert.NotAfter) < 30*24*time.Hour {
		issues = append(issues, "Certificate expires soon")
	}

	// Check key strength using proper algorithm-specific logic
	keyInfo := getKeyInfo(cert)
	if keyInfo.IsWeak {
		if keyInfo.Algorithm == "ECDSA" {
			issues = append(issues, fmt.Sprintf("Weak %s key (%d-bit curve, ~%d-bit RSA equivalent)", keyInfo.Algorithm, keyInfo.Size, keyInfo.Equivalent))
		} else {
			issues = append(issues, fmt.Sprintf("Weak %s key size (%d bits)", keyInfo.Algorithm, keyInfo.Size))
		}
	}

	// Check signature algorithm
	if strings.Contains(strings.ToLower(cert.SignatureAlgorithm.String()), "sha1") {
		issues = append(issues, "Weak signature algorithm (SHA1)")
	}

	// Check serial number
	if cert.SerialNumber.Cmp(big.NewInt(1000)) < 0 {
		issues = append(issues, "Suspiciously simple serial number")
	}

	// Check for suspicious terms
	suspiciousTerms := []string{"test", "demo", "localhost", "example", "invalid"}
	subject := strings.ToLower(cert.Subject.String())
	for _, term := range suspiciousTerms {
		if strings.Contains(subject, term) {
			issues = append(issues, fmt.Sprintf("Suspicious term: %s", term))
		}
	}

	return issues
}

// Helper functions

func hasValidTrustPath(certs []*x509.Certificate, mozillaCAs *x509.CertPool) bool {
	if len(certs) == 0 {
		return false
	}

	for _, cert := range certs {
		if cert.IsCA && IsTrustedCA(cert, mozillaCAs, certs) {
			return true
		}
	}
	return false
}

func isSelfSigned(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String()
}

// isRootCertificate determines if a certificate is a root certificate using multiple heuristics
func isRootCertificate(cert *x509.Certificate, position int, chainLength int) bool {
	// 1. Traditional self-signed check
	if isSelfSigned(cert) {
		return true
	}

	// 2. If it's the last certificate in the chain and has no issuer name, likely a root
	if position == chainLength && cert.Issuer.CommonName == "" {
		return true
	}

	// 3. If it's the last certificate in the chain and the issuer doesn't match any other cert in chain
	// (This handles cross-signed roots where Subject != Issuer but it's still functionally a root)
	if position == chainLength {
		return true
	}

	// 4. Check if the certificate can verify itself (cryptographic self-signature)
	if cert.CheckSignatureFrom(cert) == nil {
		return true
	}

	return false
}

func isSignedBy(child, parent *x509.Certificate) bool {
	return child.CheckSignatureFrom(parent) == nil
}

// KeyInfo contains information about a certificate's public key
type KeyInfo struct {
	Algorithm  string
	Size       int
	Equivalent int // RSA-equivalent security level
	IsWeak     bool
}

func getKeyInfo(cert *x509.Certificate) KeyInfo {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		size := key.N.BitLen()
		return KeyInfo{
			Algorithm:  "RSA",
			Size:       size,
			Equivalent: size, // RSA size is the security level
			IsWeak:     size < 2048,
		}
	case *ecdsa.PublicKey:
		curveSize := key.Curve.Params().BitSize
		var equivalent int
		var isWeak bool

		// ECDSA to RSA equivalent security levels
		switch curveSize {
		case 256: // P-256
			equivalent = 3072
			isWeak = false
		case 384: // P-384
			equivalent = 7680
			isWeak = false
		case 224: // P-224 (weak)
			equivalent = 2048
			isWeak = true
		default:
			equivalent = curveSize * 12 // Rough approximation
			isWeak = curveSize < 256
		}

		return KeyInfo{
			Algorithm:  "ECDSA",
			Size:       curveSize,
			Equivalent: equivalent,
			IsWeak:     isWeak,
		}
	default:
		return KeyInfo{
			Algorithm:  "Unknown",
			Size:       0,
			Equivalent: 0,
			IsWeak:     true,
		}
	}
}

// Legacy function for backward compatibility
func getKeySize(cert *x509.Certificate) int {
	return getKeyInfo(cert).Size
}

// DisplayChainAnalysis returns a formatted string representation of the chain analysis
func (analysis *ChainAnalysis) DisplayChainAnalysis() string {
	var output strings.Builder

	// Header
	output.WriteString(fmt.Sprintf("Certificate Chain Analysis for %s\n", analysis.Endpoint))
	output.WriteString(strings.Repeat("=", 60) + "\n\n")

	// Summary
	output.WriteString("Chain Summary:\n")
	output.WriteString(fmt.Sprintf("  Total certificates: %d\n", analysis.Summary.TotalCerts))
	output.WriteString(fmt.Sprintf("  Chain structure: %d leaf + %d intermediate + %d root\n",
		analysis.Summary.LeafCerts, analysis.Summary.Intermediate, analysis.Summary.RootCerts))

	if analysis.Summary.TrustedChain {
		output.WriteString("  Trust status: [OK] Trusted chain\n")
	} else {
		output.WriteString("  Trust status: [!] Untrusted chain\n")
	}

	if analysis.Summary.SuspiciousCount > 0 {
		output.WriteString(fmt.Sprintf("  Security issues: [!] %d certificates with issues\n", analysis.Summary.SuspiciousCount))
	} else {
		output.WriteString("  Security issues: [OK] No major issues detected\n")
	}
	output.WriteString("\n")

	// Certificate details
	output.WriteString("Certificate Chain:\n")
	for _, cert := range analysis.Certificates {
		output.WriteString(formatCertificate(cert))
	}

	// DPI clues
	if len(analysis.DPIClues) > 0 {
		output.WriteString("\nCorporate DPI Indicators:\n")
		for _, clue := range analysis.DPIClues {
			output.WriteString(fmt.Sprintf("  [DPI] %s\n", clue))
		}
	}

	// MitM clues
	if len(analysis.MitMClues) > 0 {
		output.WriteString("\nMalicious MitM Indicators:\n")
		for _, clue := range analysis.MitMClues {
			output.WriteString(fmt.Sprintf("  [ALERT] %s\n", clue))
		}
	}

	// Anomalies
	if len(analysis.Anomalies) > 0 {
		output.WriteString("\nChain Anomalies:\n")
		for _, anomaly := range analysis.Anomalies {
			output.WriteString(fmt.Sprintf("  [!] %s\n", anomaly))
		}
	}

	// Trust Store Discrepancies (the key diagnostic information)
	if len(analysis.TrustDiscrepancies) > 0 {
		output.WriteString("\nTrust Store Analysis:\n")
		for _, discrepancy := range analysis.TrustDiscrepancies {
			osStatus := "[NO]"
			if discrepancy.TrustedByOS {
				osStatus = "[YES]"
			}
			mozillaStatus := "[NO]"
			if discrepancy.TrustedByMozilla {
				mozillaStatus = "[YES]"
			}

			output.WriteString(fmt.Sprintf("  [CERT] %s\n", discrepancy.Certificate.Subject.CommonName))
			output.WriteString(fmt.Sprintf("         OS Trust Store: %s  |  Mozilla Trust Store: %s\n", osStatus, mozillaStatus))
			output.WriteString(fmt.Sprintf("         Note: %s\n", discrepancy.Explanation))
		}
	}

	return output.String()
}

// formatCertificate formats a single certificate for display
func formatCertificate(cert CertificateInfo) string {
	var output strings.Builder

	// Certificate header with type and trust status
	trustIndicator := "[OK]"
	if !cert.IsTrusted {
		trustIndicator = "[!]"
	}

	output.WriteString(fmt.Sprintf("  [%d] %s %s Certificate - %s\n",
		cert.Position, trustIndicator, cert.Type, cert.Subject))

	// Basic details
	if cert.Subject != cert.Issuer {
		output.WriteString(fmt.Sprintf("      Issued by: %s\n", cert.Issuer))
	} else {
		output.WriteString("      Issued by: Self-signed\n")
	}

	// Validity period
	validity := cert.NotAfter.Sub(cert.NotBefore)
	output.WriteString(fmt.Sprintf("      Valid: %s to %s (%.1f days)\n",
		cert.NotBefore.Format("2006-01-02"),
		cert.NotAfter.Format("2006-01-02"),
		validity.Hours()/24))

	// Technical details with improved key information
	var keyDescription string
	if cert.KeyInfo.Algorithm == "ECDSA" {
		keyDescription = fmt.Sprintf("%s P-%d (~%d-bit security)", cert.KeyInfo.Algorithm, cert.KeyInfo.Size, cert.KeyInfo.Equivalent)
	} else if cert.KeyInfo.Size > 0 {
		keyDescription = fmt.Sprintf("%s %d-bit", cert.KeyInfo.Algorithm, cert.KeyInfo.Size)
	} else {
		keyDescription = cert.KeyInfo.Algorithm
	}

	output.WriteString(fmt.Sprintf("      Key: %s, Signature: %s, Serial: %s\n",
		keyDescription, cert.SignatureAlg, truncateSerial(cert.SerialNumber)))

	// Issues
	if len(cert.Issues) > 0 {
		output.WriteString("      Issues:\n")
		for _, issue := range cert.Issues {
			output.WriteString(fmt.Sprintf("        • %s\n", issue))
		}
	}

	output.WriteString("\n")
	return output.String()
}

// truncateSerial truncates long serial numbers for display
func truncateSerial(serial string) string {
	if len(serial) > 16 {
		return serial[:8] + "..." + serial[len(serial)-8:]
	}
	return serial
}
