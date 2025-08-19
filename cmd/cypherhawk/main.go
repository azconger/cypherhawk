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

// normalizeURL ensures the URL has a protocol prefix, defaulting to https://
func normalizeURL(url string) string {
	// If the URL already has a protocol, return as-is
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		return url
	}

	// Add https:// prefix by default
	return "https://" + url
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
		normalizedURL := normalizeURL(*targetURL)
		endpoints = []string{normalizedURL}
	}

	// Step 3: Test endpoints and collect unknown certificates
	var unknownCerts []*x509.Certificate
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

	// Show detection summary to stdout (unless quiet/silent)
	printInfo("[!] Corporate DPI detected: found %d unknown CA certificate%s\n",
		len(unknownCerts),
		func() string {
			if len(unknownCerts) == 1 {
				return ""
			} else {
				return "s"
			}
		}())

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
