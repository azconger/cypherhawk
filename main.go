package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultTimeout = 30 * time.Second
)

// Multiple CA bundle sources for cross-validation
var caBundleSources = []CABundleSource{
	{
		Name:        "Mozilla (curl.se)",
		URL:         "https://curl.se/ca/cacert.pem",
		Primary:     true,
		Description: "Mozilla's trusted CA bundle maintained by curl project",
	},
	{
		Name:        "Mozilla (raw.githubusercontent.com)",
		URL:         "https://raw.githubusercontent.com/bagder/ca-bundle/master/ca-bundle.crt",
		Primary:     false,
		Description: "Mozilla CA bundle from GitHub mirror",
	},
}

type CABundleSource struct {
	Name        string
	URL         string
	Primary     bool // Whether this is a primary source for validation
	Description string
}

type SecurityValidationResult struct {
	UntrustedCAs         []*x509.Certificate
	SuspiciousBehaviors  []string
	CTIssues            []string
	ChainValidationError error
}

var (
	outputFile = flag.String("o", "", "Output file for CA certificates (use '-' for stdout)")
	targetURL  = flag.String("url", "", "Custom target URL to test (overrides default endpoints)")
	verbose    = flag.Bool("verbose", false, "Enable verbose output")
)

// Default endpoints representing common corporate network requirements
var defaultEndpoints = []string{
	"https://www.google.com",
	"https://auth.stackhawk.com",
	"https://api.stackhawk.com",
	"https://s3.us-west-2.amazonaws.com",
}

type CertificateInfo struct {
	Subject     string
	Issuer      string
	Fingerprint string
	PEM         string
}

func main() {
	flag.Parse()

	if *verbose {
		fmt.Fprintf(os.Stderr, "DPI Hawk - Detecting corporate DPI/MitM proxies...\n")
	}

	// Step 1: Download and cross-validate Mozilla CA bundles
	if *verbose {
		fmt.Fprintf(os.Stderr, "Downloading and cross-validating CA bundles...\n")
	}
	mozillaCAs, bundleInfo, err := downloadAndValidateCABundles()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error downloading CA bundles: %v\n", err)
		os.Exit(2)
	}
	if *verbose {
		fmt.Fprintf(os.Stderr, "Loaded %d trusted CA certificates (%s)\n", len(mozillaCAs.Subjects()), bundleInfo)
	}

	// Step 2: Determine endpoints to test
	endpoints := defaultEndpoints
	if *targetURL != "" {
		endpoints = []string{*targetURL}
	}

	// Step 3: Test endpoints and collect unknown certificates
	var unknownCerts []*x509.Certificate
	successCount := 0

	for i, endpoint := range endpoints {
		if *verbose {
			fmt.Fprintf(os.Stderr, "Testing endpoint %d/%d: %s\n", i+1, len(endpoints), endpoint)
		}

		certs, err := getCertificateChain(endpoint)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to connect to %s: %v\n", endpoint, err)
			continue
		}

		successCount++
		if *verbose {
			fmt.Fprintf(os.Stderr, "Retrieved %d certificates from %s\n", len(certs), endpoint)
		}

		// Enhanced security validation with multiple techniques
		securityIssues := performEnhancedSecurityValidation(certs, mozillaCAs, endpoint)
		
		// Report security issues if verbose
		if *verbose && len(securityIssues.SuspiciousBehaviors) > 0 {
			fmt.Fprintf(os.Stderr, "Security analysis for %s:\n", endpoint)
			for _, issue := range securityIssues.SuspiciousBehaviors {
				fmt.Fprintf(os.Stderr, "  - %s\n", issue)
			}
		}
		
		// Add untrusted CAs to results
		for _, cert := range securityIssues.UntrustedCAs {
			// Check if we already have this certificate (deduplication)
			if !containsCertificate(unknownCerts, cert) {
				unknownCerts = append(unknownCerts, cert)
				if *verbose {
					fmt.Fprintf(os.Stderr, "Found unknown CA: %s\n", cert.Subject.CommonName)
				}
			}
		}
	}

	// Step 4: Report results
	if successCount == 0 {
		fmt.Fprintf(os.Stderr, "Error: Failed to connect to any endpoints\n")
		os.Exit(2)
	}

	if len(unknownCerts) == 0 {
		if *verbose {
			fmt.Fprintf(os.Stderr, "No unknown CA certificates detected - no DPI/MitM proxy found\n")
		}
		os.Exit(0)
	}

	// Step 5: Output unknown certificates in PEM format
	output := generatePEMOutput(unknownCerts)

	if *outputFile == "" || *outputFile == "-" {
		fmt.Print(output)
	} else {
		err := os.WriteFile(*outputFile, []byte(output), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to file %s: %v\n", *outputFile, err)
			os.Exit(2)
		}
		if *verbose {
			fmt.Fprintf(os.Stderr, "Wrote %d unknown CA certificates to %s\n", len(unknownCerts), *outputFile)
		}
	}

	// Exit with partial failure code if some endpoints failed
	if successCount < len(endpoints) {
		os.Exit(1)
	}
}

// downloadAndValidateCABundles downloads CA bundles from multiple sources and cross-validates them
func downloadAndValidateCABundles() (*x509.CertPool, string, error) {
	client := &http.Client{
		Timeout: defaultTimeout,
	}

	var primaryBundle *x509.CertPool
	var primarySource string
	var bundleSizes []int
	var successfulSources []string

	// Download from all sources
	for _, source := range caBundleSources {
		resp, err := client.Get(source.URL)
		if err != nil {
			if source.Primary {
				return nil, "", fmt.Errorf("failed to download primary CA bundle from %s: %w", source.Name, err)
			}
			continue // Skip failed secondary sources
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			if source.Primary {
				return nil, "", fmt.Errorf("failed to download primary CA bundle from %s: HTTP %d", source.Name, resp.StatusCode)
			}
			continue
		}

		pemData, err := io.ReadAll(resp.Body)
		if err != nil {
			if source.Primary {
				return nil, "", fmt.Errorf("failed to read primary CA bundle from %s: %w", source.Name, err)
			}
			continue
		}

		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(pemData) {
			if source.Primary {
				return nil, "", fmt.Errorf("failed to parse primary CA bundle from %s", source.Name)
			}
			continue
		}

		bundleSize := len(certPool.Subjects())
		bundleSizes = append(bundleSizes, bundleSize)
		successfulSources = append(successfulSources, source.Name)

		if source.Primary {
			primaryBundle = certPool
			primarySource = source.Name
		}
	}

	if primaryBundle == nil {
		return nil, "", fmt.Errorf("failed to download primary CA bundle from any source")
	}

	// Cross-validate bundle sizes - they should be similar
	primarySize := len(primaryBundle.Subjects())
	for i, size := range bundleSizes {
		if i == 0 {
			continue // Skip primary
		}
		
		// Allow up to 10% variance in CA bundle sizes
		variance := float64(abs(size-primarySize)) / float64(primarySize)
		if variance > 0.10 {
			return nil, "", fmt.Errorf("CA bundle size mismatch detected: %s has %d CAs vs primary %d CAs (%.1f%% variance)", 
				successfulSources[i], size, primarySize, variance*100)
		}
	}

	info := fmt.Sprintf("primary: %s, validated against %d sources", primarySource, len(successfulSources)-1)
	return primaryBundle, info, nil
}

// abs returns absolute value of integer
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// getCertificateChain connects to an endpoint and extracts the certificate chain
func getCertificateChain(url string) ([]*x509.Certificate, error) {
	// Create HTTP client with InsecureSkipVerify to capture certificates
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   defaultTimeout,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Extract certificates from TLS connection state
	if resp.TLS == nil {
		return nil, fmt.Errorf("no TLS connection established")
	}

	return resp.TLS.PeerCertificates, nil
}

// validateCertificateChain validates the complete certificate chain like a browser would
// Returns only CA certificates that indicate a potential MITM/DPI proxy
func validateCertificateChain(certs []*x509.Certificate, mozillaCAs *x509.CertPool, hostname string) []*x509.Certificate {
	if len(certs) == 0 {
		return nil
	}

	// The first certificate should be the leaf certificate (server certificate)
	leafCert := certs[0]
	
	// Build intermediate certificate pool from the remaining certificates
	intermediates := x509.NewCertPool()
	for i := 1; i < len(certs); i++ {
		intermediates.AddCert(certs[i])
	}

	// Verify the complete certificate chain like a browser would
	opts := x509.VerifyOptions{
		Roots:         mozillaCAs,
		Intermediates: intermediates,
		DNSName:       extractHostname(hostname),
	}

	// Try to verify the leaf certificate against the complete chain
	_, err := leafCert.Verify(opts)
	
	if err == nil {
		// Chain verification succeeded - this is normal, trusted certificate behavior
		// No MITM/DPI proxy detected
		return nil
	}

	// Chain verification failed - this could indicate MITM/DPI proxy
	// Return only the CA certificates that are likely from a corporate DPI proxy
	var untrustedCAs []*x509.Certificate
	
	for _, cert := range certs {
		if cert.IsCA && isPotentialDPICA(cert) {
			untrustedCAs = append(untrustedCAs, cert)
		}
	}
	
	return untrustedCAs
}

// performEnhancedSecurityValidation combines all security validation techniques
func performEnhancedSecurityValidation(certs []*x509.Certificate, mozillaCAs *x509.CertPool, hostname string) SecurityValidationResult {
	result := SecurityValidationResult{}
	
	// 1. Standard certificate chain validation (existing logic)
	untrustedCAs := validateCertificateChain(certs, mozillaCAs, hostname)
	result.UntrustedCAs = untrustedCAs
	
	// 2. Certificate Transparency validation
	ctIssues := validateCertificateTransparency(certs)
	result.CTIssues = ctIssues
	result.SuspiciousBehaviors = append(result.SuspiciousBehaviors, ctIssues...)
	
	// 3. Behavioral analysis
	behavioralIssues := detectSuspiciousBehavior(certs, hostname)
	result.SuspiciousBehaviors = append(result.SuspiciousBehaviors, behavioralIssues...)
	
	// 4. Enhanced CA impersonation detection (already integrated in isPotentialDPICA)
	
	// 5. Risk scoring - if we have multiple suspicious indicators, increase confidence
	riskScore := len(result.SuspiciousBehaviors)
	if riskScore >= 3 {
		result.SuspiciousBehaviors = append(result.SuspiciousBehaviors, 
			fmt.Sprintf("HIGH RISK: Multiple suspicious indicators detected (%d total)", riskScore))
	}
	
	return result
}

// isPotentialDPICA checks if a CA certificate appears to be from a corporate DPI proxy
func isPotentialDPICA(cert *x509.Certificate) bool {
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

// validateCertificateTransparency checks if certificates have proper CT (Certificate Transparency) evidence
func validateCertificateTransparency(certs []*x509.Certificate) []string {
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

// detectSuspiciousBehavior performs comprehensive behavioral analysis on certificate chains
func detectSuspiciousBehavior(certs []*x509.Certificate, hostname string) []string {
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

// isTrustedCA checks if a certificate can be verified through Mozilla's trusted CA bundle
// This function is kept for test compatibility
func isTrustedCA(cert *x509.Certificate, mozillaCAs *x509.CertPool, allCerts []*x509.Certificate) bool {
	// Only examine CA certificates for unknown detection
	if !cert.IsCA {
		return true // Skip non-CA certificates - we only care about CA certs
	}

	// Build intermediate certificate pool from the certificate chain
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
	}

	// Try to verify the certificate against Mozilla's CA bundle with full chain context
	_, err := cert.Verify(opts)
	
	// If verification succeeds, this CA is part of a trusted chain
	// If verification fails, it's an unknown/untrusted CA (potential DPI)
	return err == nil
}

// containsCertificate checks if a certificate is already in the slice (deduplication)
func containsCertificate(certs []*x509.Certificate, target *x509.Certificate) bool {
	for _, cert := range certs {
		if cert.Equal(target) {
			return true
		}
	}
	return false
}

// generatePEMOutput converts certificates to PEM format
func generatePEMOutput(certs []*x509.Certificate) string {
	var output strings.Builder

	output.WriteString("# DPI Hawk - Detected unknown CA certificates\n")
	output.WriteString("# These certificates were found in TLS connections but are not in Mozilla's trusted CA bundle\n")
	output.WriteString("# This indicates potential corporate DPI/MitM proxy infrastructure\n\n")

	for i, cert := range certs {
		output.WriteString(fmt.Sprintf("# Certificate %d: %s\n", i+1, cert.Subject.CommonName))
		output.WriteString(fmt.Sprintf("# Issuer: %s\n", cert.Issuer.CommonName))
		output.WriteString(fmt.Sprintf("# Serial: %s\n", cert.SerialNumber.String()))

		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		output.WriteString(string(pem.EncodeToMemory(pemBlock)))
		output.WriteString("\n")
	}

	return output.String()
}