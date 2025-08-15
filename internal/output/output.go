package output

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

// ContainsCertificate checks if a certificate is already in the slice (deduplication)
func ContainsCertificate(certs []*x509.Certificate, target *x509.Certificate) bool {
	for _, cert := range certs {
		if cert.Equal(target) {
			return true
		}
	}
	return false
}

// GeneratePEM converts certificates to PEM format
func GeneratePEM(certs []*x509.Certificate) string {
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
