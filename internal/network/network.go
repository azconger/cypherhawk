package network

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"
)

// GetCertificateChain connects to an endpoint and extracts the certificate chain
func GetCertificateChain(url string) ([]*x509.Certificate, error) {
	// Create HTTP client with InsecureSkipVerify to capture certificates
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
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
