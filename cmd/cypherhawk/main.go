package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/kaakaww/cypherhawk/internal/analysis"
	"github.com/kaakaww/cypherhawk/internal/bundle"
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
	targetURL    = flag.String("url", "", "Custom target URL to test (assumes https:// if no protocol specified)")
	verbose      = flag.Bool("verbose", false, "Enable verbose output")
	showVersion  = flag.Bool("version", false, "Show version information")
	analyzeChain = flag.Bool("analyze", false, "Show detailed certificate chain analysis")
)

// Default endpoints representing common corporate network requirements
var defaultEndpoints = []string{
	"https://www.google.com",
	"https://auth.stackhawk.com",
	"https://api.stackhawk.com",
	"https://s3.us-west-2.amazonaws.com",
}

// normalizeURL ensures the URL has a protocol prefix, defaulting to https://
func normalizeURL(url string) string {
	// If the URL already has a protocol, return as-is
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		return url
	}

	// Add https:// prefix by default
	return "https://" + url
}

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("CypherHawk %s (built %s)\n", version, buildTime)
		return
	}

	if *verbose {
		fmt.Fprintf(os.Stderr, "CypherHawk %s - Detecting corporate DPI/MitM proxies...\n", version)
	}

	// Step 1: Download and cross-validate Mozilla CA bundles
	if *verbose {
		fmt.Fprintf(os.Stderr, "Downloading and cross-validating CA bundles...\n")
	}
	mozillaCAs, bundleInfo, err := bundle.DownloadAndValidate()
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
		normalizedURL := normalizeURL(*targetURL)
		endpoints = []string{normalizedURL}
	}

	// Step 3: Test endpoints and collect unknown certificates
	var unknownCerts []*x509.Certificate
	successCount := 0

	for i, endpoint := range endpoints {
		if *verbose {
			fmt.Fprintf(os.Stderr, "Testing endpoint %d/%d: %s\n", i+1, len(endpoints), endpoint)
		}

		certs, err := network.GetCertificateChain(endpoint)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to connect to %s: %v\n", endpoint, err)
			continue
		}

		successCount++
		if *verbose {
			fmt.Fprintf(os.Stderr, "Retrieved %d certificates from %s\n", len(certs), endpoint)
		}

		// Certificate chain analysis (if requested)
		if *analyzeChain {
			chainAnalysis := analysis.AnalyzeCertificateChain(endpoint, certs, mozillaCAs)
			fmt.Print(chainAnalysis.DisplayChainAnalysis())
			fmt.Println() // Add spacing between endpoints
		}

		// Enhanced security validation with multiple techniques
		securityIssues := security.PerformEnhancedValidation(certs, mozillaCAs, endpoint)

		// Report security issues if verbose
		if *verbose && len(securityIssues.SuspiciousBehaviors) > 0 {
			fmt.Fprintf(os.Stderr, "Security analysis for %s:\n", endpoint)
			for _, issue := range securityIssues.SuspiciousBehaviors {
				fmt.Fprintf(os.Stderr, "  - %s\n", issue)
			}
		}

		// Report trust discrepancies if verbose (key diagnostic info for support)
		if *verbose && len(securityIssues.TrustDiscrepancies) > 0 {
			fmt.Fprintf(os.Stderr, "Trust store analysis for %s:\n", endpoint)
			for _, discrepancy := range securityIssues.TrustDiscrepancies {
				osStatus := "Not Trusted"
				if discrepancy.TrustedByOS {
					osStatus = "Trusted"
				}
				mozillaStatus := "Not Trusted"
				if discrepancy.TrustedByMozilla {
					mozillaStatus = "Trusted"
				}

				fmt.Fprintf(os.Stderr, "  [CERT] %s: OS=%s, Mozilla=%s\n",
					discrepancy.Certificate.Subject.CommonName, osStatus, mozillaStatus)
				fmt.Fprintf(os.Stderr, "         Note: %s\n", discrepancy.Explanation)
			}
		}

		// Add untrusted CAs to results
		for _, cert := range securityIssues.UntrustedCAs {
			// Check if we already have this certificate (deduplication)
			if !output.ContainsCertificate(unknownCerts, cert) {
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

	// If we're just doing chain analysis, exit here
	if *analyzeChain {
		os.Exit(0)
	}

	if len(unknownCerts) == 0 {
		// Always show success message (not just in verbose mode)
		fmt.Fprintf(os.Stderr, "[OK] No corporate DPI detected (tested %d endpoint%s)\n",
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

	// Step 5: Output unknown certificates in PEM format
	pemOutput := output.GeneratePEM(unknownCerts)

	// Show detection summary
	fmt.Fprintf(os.Stderr, "[!] Corporate DPI detected: found %d unknown CA certificate%s\n",
		len(unknownCerts),
		func() string {
			if len(unknownCerts) == 1 {
				return ""
			} else {
				return "s"
			}
		}())

	if *outputFile == "" || *outputFile == "-" {
		fmt.Print(pemOutput)
	} else {
		err := os.WriteFile(*outputFile, []byte(pemOutput), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to file %s: %v\n", *outputFile, err)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "Certificates saved to: %s\n", *outputFile)
	}

	// Exit with partial failure code if some endpoints failed
	if successCount < len(endpoints) {
		os.Exit(1)
	}
}
