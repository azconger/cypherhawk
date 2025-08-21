package embedded

import (
	_ "embed"
)

// EmbeddedCACerts contains a backup Mozilla CA bundle embedded at build time
// This provides fallback certificate validation when external downloads fail
// in corporate environments with restricted internet access.
//
// The bundle is automatically updated during the build process (make build/build-all)
// by downloading the latest Mozilla CA certificates from trusted sources.
//
// Build-time update process:
//  1. scripts/update-ca-bundle.sh downloads latest bundle from curl.se
//  2. Falls back to GitHub mirror if primary source fails
//  3. Validates downloaded certificates and embeds them in the binary
//
// This ensures the embedded fallback bundle is always fresh at build time
// rather than using a potentially stale static file.
//
// Primary source: https://curl.se/ca/cacert.pem
// Backup source: https://raw.githubusercontent.com/bagder/ca-bundle/master/ca-bundle.crt
//
//go:embed cacert.pem
var EmbeddedCACerts []byte

// GetEmbeddedCACerts returns the embedded Mozilla CA certificate bundle
// This is used as a fallback when external CA bundle downloads fail
func GetEmbeddedCACerts() []byte {
	return EmbeddedCACerts
}
