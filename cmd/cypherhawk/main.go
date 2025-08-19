package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/kaakaww/cypherhawk/internal/analysis"
	"github.com/kaakaww/cypherhawk/internal/bundle"
	"github.com/kaakaww/cypherhawk/internal/detection"
	"github.com/kaakaww/cypherhawk/internal/network"
	"github.com/kaakaww/cypherhawk/internal/output"
	"github.com/kaakaww/cypherhawk/internal/security"
)

// Build-time variables (set via -ldflags)
var (
	version   = "dev"
	buildTime = "unknown"
)

var (
	outputFile   = flag.String("o", "", "Output file for CA certificates (use '-' for stdout)")
	outfileLong  = flag.String("outfile", "", "Output file for CA certificates (use '-' for stdout)")
	targetURL    = flag.String("url", "", "Custom target URL to test (assumes https:// if no protocol specified)")
	verbose      = flag.Bool("v", false, "Show detailed progress and security analysis")
	verboseLong  = flag.Bool("verbose", false, "Show detailed progress and security analysis")
	quiet        = flag.Bool("q", false, "Suppress all non-error output")
	quietLong    = flag.Bool("quiet", false, "Suppress all non-error output")
	silent       = flag.Bool("s", false, "Suppress ALL output (even errors)")
	silentLong   = flag.Bool("silent", false, "Suppress ALL output (even errors)")
	analyzeChain = flag.Bool("a", false, "Show comprehensive certificate chain analysis")
	analyzeLong  = flag.Bool("analyze", false, "Show comprehensive certificate chain analysis")
	showVersion  = flag.Bool("version", false, "Show version information")
)

// Default endpoints representing common corporate network requirements
var defaultEndpoints = []string{
	"https://www.google.com",
	"https://auth.stackhawk.com",
	"https://api.stackhawk.com",
	"https://s3.us-west-2.amazonaws.com",
}

// validateAndNormalizeURL validates the input URL and normalizes it
func validateAndNormalizeURL(inputURL string) (string, error) {
	if inputURL == "" {
		return "", fmt.Errorf("URL cannot be empty")
	}

	// Remove whitespace
	inputURL = strings.TrimSpace(inputURL)

	// Check for common invalid characters that could indicate malicious input
	if strings.ContainsAny(inputURL, "\r\n\t") {
		return "", fmt.Errorf("URL contains invalid control characters")
	}

	// First parse the input URL to check for unsupported schemes
	tempURL, tempErr := url.Parse(inputURL)
	if tempErr == nil && tempURL.Scheme != "" && tempURL.Scheme != "http" && tempURL.Scheme != "https" {
		return "", fmt.Errorf("unsupported URL scheme '%s', only http and https are supported\n"+
			"Corporate network guidance:\n"+
			"  - Use https:// for secure connections (recommended)\n"+
			"  - Use http:// only if the service doesn't support HTTPS\n"+
			"  - Most corporate environments prefer HTTPS connections", tempURL.Scheme)
	}

	// Normalize the URL by adding https:// if no protocol is specified
	normalized := normalizeURL(inputURL)

	// Parse and validate the normalized URL
	parsedURL, err := url.Parse(normalized)
	if err != nil {
		return "", fmt.Errorf("invalid URL format: %v\n"+
			"Corporate network guidance:\n"+
			"  - Ensure the URL format is correct (e.g., example.com or https://example.com)\n"+
			"  - For internal URLs, verify the hostname is correct\n"+
			"  - Check if the URL requires specific domain suffixes in your environment", err)
	}

	// Validate scheme
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return "", fmt.Errorf("unsupported URL scheme '%s', only http and https are supported\n"+
			"Corporate network guidance:\n"+
			"  - Use https:// for secure connections (recommended)\n"+
			"  - Use http:// only if the service doesn't support HTTPS\n"+
			"  - Most corporate environments prefer HTTPS connections", parsedURL.Scheme)
	}

	// Validate hostname
	if parsedURL.Hostname() == "" {
		return "", fmt.Errorf("URL must contain a valid hostname\n" +
			"Corporate network guidance:\n" +
			"  - Provide a complete hostname (e.g., internal.company.com)\n" +
			"  - For internal services, ensure you're connected to the corporate network\n" +
			"  - Check if the hostname requires VPN access")
	}

	// Check for suspicious patterns that might indicate malicious URLs
	hostname := parsedURL.Hostname()

	// Check for IP addresses (not necessarily invalid, but warn in corporate context)
	ipRegex := regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	if ipRegex.MatchString(hostname) {
		// Don't block IP addresses, but they're less common in corporate environments
		// Could add warning in verbose mode if needed
	}

	// Check for localhost/internal addresses that might not be reachable
	if isInternalAddress(hostname) {
		// This is fine, but provide guidance if connection fails
	}

	// Validate port if specified
	if parsedURL.Port() != "" {
		port := parsedURL.Port()
		// Basic port validation - ensure it's numeric
		portRegex := regexp.MustCompile(`^\d{1,5}$`)
		if !portRegex.MatchString(port) {
			return "", fmt.Errorf("invalid port number '%s'\n"+
				"Corporate network guidance:\n"+
				"  - Port must be a number between 1-65535\n"+
				"  - Common ports: 80 (HTTP), 443 (HTTPS), 8080, 8443\n"+
				"  - Check if custom ports are allowed by corporate firewall", port)
		}
	}

	return normalized, nil
}

// normalizeURL ensures the URL has a protocol prefix, defaulting to https://
func normalizeURL(inputURL string) string {
	// If the URL already has a protocol, return as-is
	if strings.HasPrefix(inputURL, "http://") || strings.HasPrefix(inputURL, "https://") {
		return inputURL
	}

	// Add https:// prefix by default
	return "https://" + inputURL
}

// isInternalAddress checks if the hostname appears to be an internal/private address
func isInternalAddress(hostname string) bool {
	// Check for common internal patterns
	internalPatterns := []string{
		"localhost",
		"127.0.0.1",
		".local",
		".internal",
		".corp",
		".corporate",
		".intranet",
	}

	lowerHost := strings.ToLower(hostname)
	for _, pattern := range internalPatterns {
		if strings.Contains(lowerHost, pattern) {
			return true
		}
	}

	// Check for private IP ranges (basic check)
	if strings.HasPrefix(hostname, "10.") ||
		strings.HasPrefix(hostname, "192.168.") ||
		strings.HasPrefix(hostname, "172.") {
		return true
	}

	return false
}

// generateDPISummary creates a comprehensive summary of DPI detection results
func generateDPISummary(results []*detection.DetectionResult) string {
	var totalUnknownCAs int
	var detectedVendors = make(map[string]*detection.VendorMatch)
	var hasHighConfidenceDetection bool
	
	// Analyze all results
	for _, result := range results {
		totalUnknownCAs += len(result.UnknownCAs)
		
		if result.BestMatch != nil {
			// Keep the highest confidence match for each vendor
			vendor := result.BestMatch.Vendor
			if existing, exists := detectedVendors[vendor]; !exists || result.BestMatch.Confidence > existing.Confidence {
				detectedVendors[vendor] = result.BestMatch
			}
			
			if result.BestMatch.Confidence >= 70 {
				hasHighConfidenceDetection = true
			}
		}
	}
	
	// Generate summary message
	if len(detectedVendors) == 0 {
		return fmt.Sprintf("[DPI] Corporate DPI detected: found %d unknown CA certificate(s)", totalUnknownCAs)
	}
	
	// Single vendor detected
	if len(detectedVendors) == 1 {
		for _, vendor := range detectedVendors {
			confidenceText := ""
			if hasHighConfidenceDetection {
				confidenceText = fmt.Sprintf(" (%d%% confidence)", vendor.Confidence)
			}
			
			return fmt.Sprintf("[DPI] %s detected%s - %d CA certificate(s) need extraction", 
				vendor.Vendor, confidenceText, totalUnknownCAs)
		}
	}
	
	// Multiple vendors detected
	var vendorNames []string
	for _, vendor := range detectedVendors {
		if vendor.Confidence >= 50 { // Only include moderate+ confidence
			vendorNames = append(vendorNames, vendor.Vendor)
		}
	}
	
	if len(vendorNames) == 0 {
		return fmt.Sprintf("[DPI] Unknown DPI vendor detected - %d CA certificate(s) need extraction", totalUnknownCAs)
	} else if len(vendorNames) == 1 {
		return fmt.Sprintf("[DPI] %s detected - %d CA certificate(s) need extraction", 
			vendorNames[0], totalUnknownCAs)
	} else {
		return fmt.Sprintf("[DPI] Multiple DPI vendors detected (%s) - %d CA certificate(s) need extraction", 
			strings.Join(vendorNames, ", "), totalUnknownCAs)
	}
}

// Helper functions for flag handling
func getOutputFile() string {
	if *outfileLong != "" {
		return *outfileLong
	}
	return *outputFile
}

func isVerbose() bool {
	return *verbose || *verboseLong
}

func isQuiet() bool {
	return *quiet || *quietLong
}

func isSilent() bool {
	return *silent || *silentLong
}

func isAnalyze() bool {
	return *analyzeChain || *analyzeLong
}

// Output functions that respect quiet/silent modes
func printInfo(format string, args ...interface{}) {
	if !isQuiet() && !isSilent() {
		fmt.Printf(format, args...)
	}
}

func printError(format string, args ...interface{}) {
	if !isSilent() {
		fmt.Fprintf(os.Stderr, format, args...)
	}
}

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("CypherHawk %s (built %s)\n", version, buildTime)
		return
	}

	if isVerbose() {
		printInfo("CypherHawk %s - Detecting corporate DPI/MitM proxies...\n", version)
	}

	// Step 1: Download and cross-validate Mozilla CA bundles
	if isVerbose() {
		printInfo("Downloading and cross-validating CA bundles...\n")
	}
	mozillaCAs, bundleInfo, err := bundle.DownloadAndValidate()
	if err != nil {
		printError("Error downloading CA bundles: %v\n", err)
		os.Exit(2)
	}
	if isVerbose() {
		printInfo("Loaded trusted CA certificates (%s)\n", bundleInfo)
	}

	// Step 2: Determine endpoints to test
	endpoints := defaultEndpoints
	if *targetURL != "" {
		validatedURL, err := validateAndNormalizeURL(*targetURL)
		if err != nil {
			printError("Invalid URL '%s': %v\n", *targetURL, err)
			os.Exit(2)
		}
		endpoints = []string{validatedURL}
		if isVerbose() {
			printInfo("Using custom target: %s\n", validatedURL)
		}
	}

	// Step 3: Test endpoints and collect unknown certificates
	var unknownCerts []*x509.Certificate
	var dpiResults []*detection.DetectionResult
	successCount := 0

	for i, endpoint := range endpoints {
		if isVerbose() {
			printInfo("Testing endpoint %d/%d: %s\n", i+1, len(endpoints), endpoint)
		}

		certs, err := network.GetCertificateChain(endpoint)
		if err != nil {
			printError("Failed to connect to %s: %v\n", endpoint, err)
			continue
		}

		successCount++
		if isVerbose() {
			printInfo("Retrieved %d certificates from %s\n", len(certs), endpoint)
		}

		// Certificate chain analysis (if requested)
		if isAnalyze() {
			chainAnalysis := analysis.AnalyzeCertificateChain(endpoint, certs, mozillaCAs)
			printInfo("%s", chainAnalysis.DisplayChainAnalysis())
			printInfo("\n") // Add spacing between endpoints
		}

		// Enhanced security validation with multiple techniques
		securityIssues := security.PerformEnhancedValidation(certs, mozillaCAs, endpoint)

		// Enhanced DPI vendor detection
		dpiResult := detection.AnalyzeCertificateChain(endpoint, certs, mozillaCAs)
		dpiResults = append(dpiResults, dpiResult)

		// Report DPI detection results if verbose
		if isVerbose() && dpiResult.IsCorporateDPI {
			printInfo("%s", dpiResult.FormatDetectionReport())
		}

		// Report security issues if verbose
		if isVerbose() && len(securityIssues.SuspiciousBehaviors) > 0 {
			printInfo("Security analysis for %s:\n", endpoint)
			for _, issue := range securityIssues.SuspiciousBehaviors {
				printInfo("  - %s\n", issue)
			}
		}

		// Report trust discrepancies if verbose (key diagnostic info for support)
		if isVerbose() && len(securityIssues.TrustDiscrepancies) > 0 {
			printInfo("Trust store analysis for %s:\n", endpoint)
			for _, discrepancy := range securityIssues.TrustDiscrepancies {
				osStatus := "Not Trusted"
				if discrepancy.TrustedByOS {
					osStatus = "Trusted"
				}
				mozillaStatus := "Not Trusted"
				if discrepancy.TrustedByMozilla {
					mozillaStatus = "Trusted"
				}

				printInfo("  [CERT] %s: OS=%s, Mozilla=%s\n",
					discrepancy.Certificate.Subject.CommonName, osStatus, mozillaStatus)
				printInfo("         Note: %s\n", discrepancy.Explanation)
			}
		}

		// Add untrusted CAs to results
		for _, cert := range securityIssues.UntrustedCAs {
			// Check if we already have this certificate (deduplication)
			if !output.ContainsCertificate(unknownCerts, cert) {
				unknownCerts = append(unknownCerts, cert)
				if isVerbose() {
					printInfo("Found unknown CA: %s\n", cert.Subject.CommonName)
				}
			}
		}
	}

	// Step 4: Report results
	if successCount == 0 {
		printError("Error: Failed to connect to any endpoints\n")
		os.Exit(2)
	}

	// If we're just doing chain analysis, exit here
	if isAnalyze() {
		os.Exit(0)
	}

	// Generate summary message from DPI detection results
	if len(unknownCerts) == 0 {
		// Always show success message to stdout (unless quiet/silent)
		printInfo("[OK] No corporate DPI detected (tested %d endpoint%s)\n",
			successCount,
			func() string {
				if successCount == 1 {
					return ""
				} else {
					return "s"
				}
			}())
		os.Exit(0)
	}

	// Generate enhanced DPI detection summary
	dpiSummary := generateDPISummary(dpiResults)
	printInfo("%s\n", dpiSummary)

	// Handle PEM output based on -o/-outfile flag
	outputFile := getOutputFile()
	if outputFile != "" {
		// Step 5: Output unknown certificates in PEM format
		pemOutput := output.GeneratePEM(unknownCerts)

		if outputFile == "-" {
			// Output PEM to stdout
			fmt.Print(pemOutput)
		} else {
			// Output PEM to file
			err := os.WriteFile(outputFile, []byte(pemOutput), 0644)
			if err != nil {
				printError("Error writing to file %s: %v\n", outputFile, err)
				os.Exit(2)
			}
			printInfo("Certificates saved to: %s\n", outputFile)
		}
	} else {
		// No output file specified - show helpful tip
		printInfo("Tip: Use -o file.pem to save certificates, or -o - to output PEM data\n")
	}

	// Exit with partial failure code if some endpoints failed
	if successCount < len(endpoints) {
		os.Exit(1)
	}
}
