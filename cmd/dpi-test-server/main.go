// DPI Test Server - Standalone HTTPS server that simulates corporate DPI/proxy behavior
// This creates a test environment for validating CypherHawk's DPI detection capabilities
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// DPIProfile defines different types of DPI configurations to simulate
type DPIProfile struct {
	Name               string
	Organization       string
	CommonName         string
	SerialNumber       int64
	ValidityYears      int
	WeakSignature      bool   // Use SHA1 instead of SHA256
	SuspiciousSerial   bool   // Use trivial serial numbers
	RecentIssuance     bool   // Issue certificate very recently
	SuspiciousTerms    []string // Include suspicious terms in subject
	Port               int
}

// Available DPI profiles for testing
var dpiProfiles = map[string]DPIProfile{
	"palo-alto": {
		Name:          "Palo Alto Networks",
		Organization:  "Palo Alto Networks",
		CommonName:    "Palo Alto Networks Enterprise Root CA",
		SerialNumber:  0x1234567890abcdef,
		ValidityYears: 10,
		Port:          8443,
	},
	"zscaler": {
		Name:          "Zscaler",
		Organization:  "Zscaler Inc",
		CommonName:    "Zscaler Root CA",
		SerialNumber:  0x9876543210fedcba,
		ValidityYears: 5,
		Port:          8444,
	},
	"netskope": {
		Name:          "Netskope",
		Organization:  "Netskope Inc",
		CommonName:    "Netskope Certificate Authority",
		SerialNumber:  0x1111222233334444,
		ValidityYears: 15,
		Port:          8445,
	},
	"generic": {
		Name:          "Generic Corporate",
		Organization:  "Acme Corporation",
		CommonName:    "Acme Corporate Security CA",
		SerialNumber:  1, // Suspicious serial
		ValidityYears: 20,
		SuspiciousSerial: true,
		Port:          8446,
	},
	"malicious": {
		Name:             "Malicious DPI",
		Organization:     "Test Organization",
		CommonName:       "Test-CA-localhost",
		SerialNumber:     123, // Very suspicious
		ValidityYears:    1,
		WeakSignature:    true,
		SuspiciousSerial: true,
		RecentIssuance:   true,
		SuspiciousTerms:  []string{"test", "demo", "localhost"},
		Port:             8447,
	},
}

func main() {
	var profile = flag.String("profile", "generic", "DPI profile to simulate (palo-alto, zscaler, netskope, generic, malicious)")
	var port = flag.Int("port", 0, "Port to listen on (overrides profile default)")
	var outputCerts = flag.String("output-certs", "", "Directory to save generated certificates")
	var listProfiles = flag.Bool("list", false, "List available DPI profiles")
	var help = flag.Bool("help", false, "Show help")
	flag.Parse()

	if *help {
		showHelp()
		return
	}

	if *listProfiles {
		showProfiles()
		return
	}

	dpiProfile, exists := dpiProfiles[*profile]
	if !exists {
		fmt.Printf("Error: Unknown profile '%s'\n", *profile)
		fmt.Printf("Available profiles: ")
		for name := range dpiProfiles {
			fmt.Printf("%s ", name)
		}
		fmt.Printf("\n")
		os.Exit(1)
	}

	if *port != 0 {
		dpiProfile.Port = *port
	}

	// Generate certificates
	fmt.Printf("🔧 Generating %s DPI certificates...\n", dpiProfile.Name)
	caCert, caKey, serverCert, serverKey, err := generateDPICertificates(dpiProfile)
	if err != nil {
		log.Fatalf("Failed to generate certificates: %v", err)
	}

	// Save certificates if requested
	if *outputCerts != "" {
		if err := saveCertificates(*outputCerts, dpiProfile, caCert, serverCert); err != nil {
			log.Printf("Warning: Failed to save certificates: %v", err)
		}
	}

	// Create TLS server
	fmt.Printf("🚀 Starting %s DPI test server on port %d...\n", dpiProfile.Name, dpiProfile.Port)
	server := createDPITestServer(dpiProfile, caCert, caKey, serverCert, serverKey)
	
	fmt.Printf("\n✅ Server running at https://localhost:%d\n", dpiProfile.Port)
	fmt.Printf("📋 Test with CypherHawk: ./cypherhawk -url https://localhost:%d\n", dpiProfile.Port)
	fmt.Printf("🛑 Press Ctrl+C to stop\n\n")
	
	// Server info
	printServerInfo(dpiProfile, caCert)

	log.Fatal(server.ListenAndServeTLS("", ""))
}

func generateDPICertificates(profile DPIProfile) (*x509.Certificate, *rsa.PrivateKey, *x509.Certificate, *rsa.PrivateKey, error) {
	// Generate CA certificate and key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to generate CA key: %v", err)
	}

	// Create CA certificate template
	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(profile.SerialNumber),
		Subject: pkix.Name{
			Organization:  []string{profile.Organization},
			Country:       []string{"US"},
			Province:      []string{"CA"},
			Locality:      []string{"San Francisco"},
			CommonName:    profile.CommonName,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour), // Start 1 hour ago
		NotAfter:              time.Now().Add(time.Duration(profile.ValidityYears) * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Apply profile-specific modifications
	if profile.RecentIssuance {
		caTemplate.NotBefore = time.Now() // Very recent
	}

	// Create CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	// Generate server certificate and key
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to generate server key: %v", err)
	}

	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(profile.SerialNumber + 1),
		Subject: pkix.Name{
			Organization:  []string{profile.Organization},
			Country:       []string{"US"},
			Province:      []string{"CA"},
			Locality:      []string{"San Francisco"},
			CommonName:    "localhost",
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(time.Duration(profile.ValidityYears) * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:    []string{"localhost"},
	}

	// Create server certificate signed by CA
	serverCertDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create server certificate: %v", err)
	}

	serverCert, err := x509.ParseCertificate(serverCertDER)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to parse server certificate: %v", err)
	}

	return caCert, caKey, serverCert, serverKey, nil
}

func createDPITestServer(profile DPIProfile, caCert *x509.Certificate, caKey *rsa.PrivateKey, serverCert *x509.Certificate, serverKey *rsa.PrivateKey) *http.Server {
	// Create TLS certificate with full chain
	tlsCert := tls.Certificate{
		Certificate: [][]byte{serverCert.Raw, caCert.Raw}, // Include both server and CA cert
		PrivateKey:  serverKey,
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	// Create HTTP handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		
		response := fmt.Sprintf(`{
  "message": "%s DPI Test Server",
  "profile": "%s",
  "organization": "%s",
  "ca_common_name": "%s",
  "timestamp": "%s",
  "client_ip": "%s",
  "user_agent": "%s",
  "tls_version": "%s"
}`, profile.Name, profile.Name, profile.Organization, profile.CommonName, 
			time.Now().Format(time.RFC3339), 
			r.RemoteAddr, 
			r.Header.Get("User-Agent"),
			getTLSVersion(r))
		
		w.Write([]byte(response))
	})

	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", profile.Port),
		Handler:   handler,
		TLSConfig: tlsConfig,
	}

	return server
}

func saveCertificates(outputDir string, profile DPIProfile, caCert *x509.Certificate, serverCert *x509.Certificate) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Save CA certificate
	caFile := filepath.Join(outputDir, fmt.Sprintf("%s-ca.pem", profile.Name))
	if err := saveCertToPEM(caFile, caCert); err != nil {
		return fmt.Errorf("failed to save CA certificate: %v", err)
	}

	// Save server certificate
	serverFile := filepath.Join(outputDir, fmt.Sprintf("%s-server.pem", profile.Name))
	if err := saveCertToPEM(serverFile, serverCert); err != nil {
		return fmt.Errorf("failed to save server certificate: %v", err)
	}

	// Save combined chain
	chainFile := filepath.Join(outputDir, fmt.Sprintf("%s-chain.pem", profile.Name))
	if err := saveCertChainToPEM(chainFile, []*x509.Certificate{serverCert, caCert}); err != nil {
		return fmt.Errorf("failed to save certificate chain: %v", err)
	}

	fmt.Printf("💾 Saved certificates to:\n")
	fmt.Printf("   - CA: %s\n", caFile)
	fmt.Printf("   - Server: %s\n", serverFile)
	fmt.Printf("   - Chain: %s\n", chainFile)

	return nil
}

func saveCertToPEM(filename string, cert *x509.Certificate) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

func saveCertChainToPEM(filename string, certs []*x509.Certificate) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, cert := range certs {
		if err := pem.Encode(file, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}); err != nil {
			return err
		}
	}

	return nil
}

func printServerInfo(profile DPIProfile, caCert *x509.Certificate) {
	fmt.Printf("📊 Server Information:\n")
	fmt.Printf("   Profile: %s\n", profile.Name)
	fmt.Printf("   Organization: %s\n", profile.Organization)
	fmt.Printf("   CA Common Name: %s\n", profile.CommonName)
	fmt.Printf("   CA Serial: %d\n", caCert.SerialNumber)
	fmt.Printf("   CA Valid From: %s\n", caCert.NotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("   CA Valid Until: %s\n", caCert.NotAfter.Format("2006-01-02 15:04:05"))
	fmt.Printf("   Validity Period: %.1f years\n", caCert.NotAfter.Sub(caCert.NotBefore).Hours()/(24*365))
	fmt.Printf("\n")
}

func getTLSVersion(r *http.Request) string {
	if r.TLS == nil {
		return "none"
	}
	
	switch r.TLS.Version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (%d)", r.TLS.Version)
	}
}

func showHelp() {
	fmt.Printf(`DPI Test Server - Simulate corporate DPI/proxy behavior for CypherHawk testing

USAGE:
    dpi-test-server [OPTIONS]

OPTIONS:
    -profile <name>      DPI profile to simulate (default: generic)
    -port <number>       Port to listen on (overrides profile default)
    -output-certs <dir>  Directory to save generated certificates
    -list               List available DPI profiles
    -help               Show this help

EXAMPLES:
    # Start generic corporate DPI simulation
    dpi-test-server

    # Start Palo Alto Networks simulation on custom port
    dpi-test-server -profile palo-alto -port 9443

    # Generate malicious DPI server and save certificates
    dpi-test-server -profile malicious -output-certs ./certs

    # Test with CypherHawk
    ./cypherhawk -url https://localhost:8446

PROFILES:
    Use -list to see available profiles with descriptions.

PURPOSE:
    This tool creates realistic DPI test environments that reproduce the certificate
    chain characteristics that CypherHawk detects. It's perfect for:
    
    - Validating CypherHawk detection capabilities
    - Understanding how different DPI solutions work
    - Testing in home lab environments
    - Demonstrating corporate network security issues

TESTING:
    1. Start the DPI test server: ./dpi-test-server -profile palo-alto
    2. Test with CypherHawk: ./cypherhawk -url https://localhost:8443
    3. Examine the detected certificates in CypherHawk's output
    4. Try different profiles to see how detection varies

WINDOWS USAGE:
    On Windows, run: dpi-test-server.exe -profile palo-alto
`)
}

func showProfiles() {
	fmt.Printf("Available DPI Profiles:\n\n")
	
	profiles := []string{"palo-alto", "zscaler", "netskope", "generic", "malicious"}
	
	for _, name := range profiles {
		profile := dpiProfiles[name]
		fmt.Printf("📋 %s:\n", name)
		fmt.Printf("   Name: %s\n", profile.Name)
		fmt.Printf("   Organization: %s\n", profile.Organization)
		fmt.Printf("   Common Name: %s\n", profile.CommonName)
		fmt.Printf("   Default Port: %d\n", profile.Port)
		fmt.Printf("   Validity: %d years\n", profile.ValidityYears)
		
		var characteristics []string
		if profile.WeakSignature {
			characteristics = append(characteristics, "Weak Signature")
		}
		if profile.SuspiciousSerial {
			characteristics = append(characteristics, "Suspicious Serial")
		}
		if profile.RecentIssuance {
			characteristics = append(characteristics, "Recent Issuance")
		}
		if len(profile.SuspiciousTerms) > 0 {
			characteristics = append(characteristics, "Suspicious Terms")
		}
		
		if len(characteristics) > 0 {
			fmt.Printf("   Suspicious Characteristics: %v\n", characteristics)
		}
		
		fmt.Printf("\n")
	}
	
	fmt.Printf("💡 TIP: Use 'generic' for basic testing, 'malicious' for high-risk detection validation\n")
}