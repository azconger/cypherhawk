package main

import (
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
	mozillaCACertURL = "https://curl.se/ca/cacert.pem"
	defaultTimeout   = 30 * time.Second
)

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

	// Step 1: Download Mozilla CA bundle
	if *verbose {
		fmt.Fprintf(os.Stderr, "Downloading Mozilla CA bundle...\n")
	}
	mozillaCAs, err := downloadMozillaCAs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error downloading Mozilla CA bundle: %v\n", err)
		os.Exit(2)
	}
	if *verbose {
		fmt.Fprintf(os.Stderr, "Loaded %d trusted CA certificates\n", len(mozillaCAs.Subjects()))
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

		// Check each certificate against Mozilla CA bundle
		for _, cert := range certs {
			if !isTrustedCA(cert, mozillaCAs) {
				// Check if we already have this certificate (deduplication)
				if !containsCertificate(unknownCerts, cert) {
					unknownCerts = append(unknownCerts, cert)
					if *verbose {
						fmt.Fprintf(os.Stderr, "Found unknown CA: %s\n", cert.Subject.CommonName)
					}
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

// downloadMozillaCAs downloads and parses Mozilla's trusted CA bundle
func downloadMozillaCAs() (*x509.CertPool, error) {
	client := &http.Client{
		Timeout: defaultTimeout,
	}

	resp, err := client.Get(mozillaCACertURL)
	if err != nil {
		return nil, fmt.Errorf("failed to download Mozilla CA bundle: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download Mozilla CA bundle: HTTP %d", resp.StatusCode)
	}

	pemData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Mozilla CA bundle: %w", err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("failed to parse Mozilla CA bundle")
	}

	return certPool, nil
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

// isTrustedCA checks if a certificate is in the Mozilla CA bundle
func isTrustedCA(cert *x509.Certificate, mozillaCAs *x509.CertPool) bool {
	// Only examine CA certificates for unknown detection
	if !cert.IsCA {
		return true // Skip non-CA certificates - we only care about CA certs
	}

	// Create a test cert pool with just Mozilla CAs and try to verify this cert
	// If verification fails, this CA is not trusted by Mozilla
	opts := x509.VerifyOptions{
		Roots: mozillaCAs,
	}

	// Try to verify the certificate against Mozilla's CA bundle
	_, err := cert.Verify(opts)
	
	// If verification succeeds, it's a trusted CA
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