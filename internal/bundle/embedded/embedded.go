package embedded

import (
	_ "embed"
)

// EmbeddedCACerts contains a backup Mozilla CA bundle embedded at build time
// This provides fallback certificate validation when external downloads fail
// in corporate environments with restricted internet access.
//
// The bundle is updated during the build process from Mozilla's trusted CA sources.
// Source: https://curl.se/ca/cacert.pem
//
//go:embed cacert.pem
var EmbeddedCACerts []byte

// GetEmbeddedCACerts returns the embedded Mozilla CA certificate bundle
// This is used as a fallback when external CA bundle downloads fail
func GetEmbeddedCACerts() []byte {
	return EmbeddedCACerts
}