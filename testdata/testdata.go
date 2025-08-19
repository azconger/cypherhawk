// Package testdata provides mock DPI certificate chains for testing CypherHawk
package testdata

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

// MockDPICertificates provides realistic DPI certificate chains for testing
type MockDPICertificates struct {
	Vendor       string
	Product      string
	Certificates []*x509.Certificate
	Description  string
}

// GeneratePaloAltoCertificateChain creates a realistic Palo Alto DPI certificate chain
func GeneratePaloAltoCertificateChain() *MockDPICertificates {
	// Generate Palo Alto root CA certificate
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(0x1234567890abcdef),
		Subject: pkix.Name{
			CommonName:   "Palo Alto Networks Root CA",
			Organization: []string{"Palo Alto Networks"},
			Country:      []string{"US"},
		},
		Issuer: pkix.Name{
			CommonName:   "Palo Alto Networks Root CA",
			Organization: []string{"Palo Alto Networks"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootCertDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootCertDER)

	// Generate leaf certificate
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(0x9876543210fedcb),
		Subject:      pkix.Name{CommonName: "www.example.com"},
		Issuer: pkix.Name{
			CommonName:   "Palo Alto Networks Root CA",
			Organization: []string{"Palo Alto Networks"},
			Country:      []string{"US"},
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"www.example.com", "example.com"},
	}

	leafCertDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &leafKey.PublicKey, rootKey)
	leafCert, _ := x509.ParseCertificate(leafCertDER)

	return &MockDPICertificates{
		Vendor:       "Palo Alto Networks",
		Product:      "PAN-OS Next-Generation Firewall",
		Certificates: []*x509.Certificate{leafCert, rootCert},
		Description:  "Typical Palo Alto DPI configuration",
	}
}

// GenerateZscalerCertificateChain creates a realistic Zscaler certificate chain
func GenerateZscalerCertificateChain() *MockDPICertificates {
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(0x1a2b3c4d5e6f7890),
		Subject: pkix.Name{
			CommonName:   "Zscaler Root CA",
			Organization: []string{"Zscaler Inc"},
			Country:      []string{"US"},
		},
		Issuer: pkix.Name{
			CommonName:   "Zscaler Root CA",
			Organization: []string{"Zscaler Inc"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now().Add(-30 * 24 * time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootCertDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootCertDER)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(0x789abc123def4567),
		Subject:      pkix.Name{CommonName: "*.company.com"},
		Issuer: pkix.Name{
			CommonName:   "Zscaler Root CA",
			Organization: []string{"Zscaler Inc"},
			Country:      []string{"US"},
		},
		NotBefore:   time.Now().Add(-5 * time.Hour),
		NotAfter:    time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"*.company.com", "company.com"},
	}

	leafCertDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &leafKey.PublicKey, rootKey)
	leafCert, _ := x509.ParseCertificate(leafCertDER)

	return &MockDPICertificates{
		Vendor:       "Zscaler",
		Product:      "Zscaler Internet Access (ZIA)",
		Certificates: []*x509.Certificate{leafCert, rootCert},
		Description:  "Zscaler DPI with 90-day rotation",
	}
}

// GenerateNetskopeCertificateChain creates a Netskope certificate chain
func GenerateNetskopeCertificateChain() *MockDPICertificates {
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(0x11223344556677),
		Subject: pkix.Name{
			CommonName:   "Netskope CA",
			Organization: []string{"Netskope Inc"},
			Country:      []string{"US"},
		},
		Issuer: pkix.Name{
			CommonName:   "Netskope CA",
			Organization: []string{"Netskope Inc"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now().Add(-60 * 24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootCertDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootCertDER)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(0x998877665544),
		Subject:      pkix.Name{CommonName: "secure.internal.com"},
		Issuer: pkix.Name{
			CommonName:   "Netskope CA",
			Organization: []string{"Netskope Inc"},
			Country:      []string{"US"},
		},
		NotBefore:   time.Now().Add(-2 * time.Hour),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"secure.internal.com"},
	}

	leafCertDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &leafKey.PublicKey, rootKey)
	leafCert, _ := x509.ParseCertificate(leafCertDER)

	return &MockDPICertificates{
		Vendor:       "Netskope",
		Product:      "Netskope Security Cloud",
		Certificates: []*x509.Certificate{leafCert, rootCert},
		Description:  "Netskope DPI configuration",
	}
}

// GenerateGenericCorporateCertificateChain creates a generic corporate DPI chain
func GenerateGenericCorporateCertificateChain() *MockDPICertificates {
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), // Suspicious simple serial
		Subject: pkix.Name{
			CommonName:   "Corporate Proxy CA",
			Organization: []string{"Example Corp"},
			Country:      []string{"US"},
		},
		Issuer: pkix.Name{
			CommonName:   "Corporate Proxy CA",
			Organization: []string{"Example Corp"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootCertDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootCertDER)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(123),
		Subject:      pkix.Name{CommonName: "www.google.com"},
		Issuer: pkix.Name{
			CommonName:   "Corporate Proxy CA",
			Organization: []string{"Example Corp"},
			Country:      []string{"US"},
		},
		NotBefore:   time.Now().Add(-30 * time.Minute),
		NotAfter:    time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"www.google.com", "google.com"},
	}

	leafCertDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &leafKey.PublicKey, rootKey)
	leafCert, _ := x509.ParseCertificate(leafCertDER)

	return &MockDPICertificates{
		Vendor:       "Corporate Internal CA",
		Product:      "Internal Certificate Authority",
		Certificates: []*x509.Certificate{leafCert, rootCert},
		Description:  "Generic corporate DPI with suspicious characteristics",
	}
}

// GenerateSquidProxyCertificateChain creates a Squid proxy certificate chain
func GenerateSquidProxyCertificateChain() *MockDPICertificates {
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(0xdeadbeef),
		Subject: pkix.Name{
			CommonName:   "Squid Proxy CA",
			Organization: []string{"IT Department"},
		},
		Issuer: pkix.Name{
			CommonName:   "Squid Proxy CA",
			Organization: []string{"IT Department"},
		},
		NotBefore:             time.Now().Add(-365 * 24 * time.Hour),
		NotAfter:              time.Now().Add(9 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootCertDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootCertDER)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(0xcafebabe),
		Subject:      pkix.Name{CommonName: "api.github.com"},
		Issuer: pkix.Name{
			CommonName:   "Squid Proxy CA",
			Organization: []string{"IT Department"},
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(9 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"api.github.com"},
	}

	leafCertDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &leafKey.PublicKey, rootKey)
	leafCert, _ := x509.ParseCertificate(leafCertDER)

	return &MockDPICertificates{
		Vendor:       "Squid Proxy",
		Product:      "Squid Caching Proxy (Open Source)",
		Certificates: []*x509.Certificate{leafCert, rootCert},
		Description:  "Squid proxy with long validity period",
	}
}

// GenerateLegitimateGoogleChain creates a mock legitimate Google certificate chain
func GenerateLegitimateGoogleChain() *MockDPICertificates {
	// Create GlobalSign Root CA (this would be in Mozilla's trusted CA bundle)
	globalSignKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	globalSignTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(0x400000000012158),
		Subject: pkix.Name{
			CommonName:         "GlobalSign Root CA",
			Organization:       []string{"GlobalSign nv-sa"},
			Country:            []string{"BE"},
			OrganizationalUnit: []string{"Root CA"},
		},
		Issuer: pkix.Name{
			CommonName:         "GlobalSign Root CA",
			Organization:       []string{"GlobalSign nv-sa"},
			Country:            []string{"BE"},
			OrganizationalUnit: []string{"Root CA"},
		},
		NotBefore:             time.Now().Add(-10 * 365 * 24 * time.Hour),
		NotAfter:              time.Now().Add(15 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            3,
	}

	globalSignCertDER, _ := x509.CreateCertificate(rand.Reader, globalSignTemplate, globalSignTemplate, &globalSignKey.PublicKey, globalSignKey)
	globalSignCert, _ := x509.ParseCertificate(globalSignCertDER)

	// Create Google Trust Services intermediate CA
	gtsKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	gtsTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(0x159ca6894d6026f),
		Subject: pkix.Name{
			CommonName:   "GTS Root R1",
			Organization: []string{"Google Trust Services LLC"},
			Country:      []string{"US"},
		},
		Issuer: pkix.Name{
			CommonName:         "GlobalSign Root CA",
			Organization:       []string{"GlobalSign nv-sa"},
			Country:            []string{"BE"},
			OrganizationalUnit: []string{"Root CA"},
		},
		NotBefore:             time.Now().Add(-3 * 365 * 24 * time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	gtsCertDER, _ := x509.CreateCertificate(rand.Reader, gtsTemplate, globalSignTemplate, &gtsKey.PublicKey, globalSignKey)
	gtsCert, _ := x509.ParseCertificate(gtsCertDER)

	// Create leaf certificate
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(0x1536336397d9e2cc),
		Subject:      pkix.Name{CommonName: "*.google.com"},
		Issuer: pkix.Name{
			CommonName:   "GTS Root R1",
			Organization: []string{"Google Trust Services LLC"},
			Country:      []string{"US"},
		},
		NotBefore:   time.Now().Add(-30 * 24 * time.Hour),
		NotAfter:    time.Now().Add(89 * 24 * time.Hour), // Typical Google cert duration
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"*.google.com", "google.com", "www.google.com"},
		IPAddresses: []net.IP{net.ParseIP("142.250.191.68")},
	}

	leafCertDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, gtsTemplate, &leafKey.PublicKey, gtsKey)
	leafCert, _ := x509.ParseCertificate(leafCertDER)

	return &MockDPICertificates{
		Vendor:       "Legitimate Site",
		Product:      "Google Services",
		Certificates: []*x509.Certificate{leafCert, gtsCert, globalSignCert},
		Description:  "Mock legitimate Google certificate chain",
	}
}

// GetAllMockDPIChains returns all available mock DPI certificate chains
func GetAllMockDPIChains() []*MockDPICertificates {
	return []*MockDPICertificates{
		GeneratePaloAltoCertificateChain(),
		GenerateZscalerCertificateChain(),
		GenerateNetskopeCertificateChain(),
		GenerateGenericCorporateCertificateChain(),
		GenerateSquidProxyCertificateChain(),
	}
}

// GetLegitimateTestChains returns mock legitimate certificate chains
func GetLegitimateTestChains() []*MockDPICertificates {
	return []*MockDPICertificates{
		GenerateLegitimateGoogleChain(),
	}
}