#!/bin/sh
# Generate corporate CA certificates for mitmproxy DPI simulation

set -e

OUTPUT_DIR="/output"
CERT_DIR="$OUTPUT_DIR"

echo "🔧 Generating corporate CA certificates for mitmproxy..."

# Create output directory
mkdir -p "$CERT_DIR"

# Generate different corporate CA profiles
generate_ca() {
    local name="$1"
    local org="$2"
    local cn="$3"
    local validity_days="$4"
    
    echo "📋 Generating $name CA..."
    
    # Generate private key
    openssl genrsa -out "$CERT_DIR/${name}-ca-key.pem" 2048
    
    # Create CA certificate
    openssl req -new -x509 -key "$CERT_DIR/${name}-ca-key.pem" \
        -out "$CERT_DIR/${name}-ca-cert.pem" \
        -days "$validity_days" \
        -subj "/C=US/ST=CA/L=San Francisco/O=$org/CN=$cn"
    
    # Convert to PKCS12 format for some applications
    openssl pkcs12 -export -out "$CERT_DIR/${name}-ca.p12" \
        -inkey "$CERT_DIR/${name}-ca-key.pem" \
        -in "$CERT_DIR/${name}-ca-cert.pem" \
        -passout pass:changeit
    
    echo "✅ Generated $name CA certificate"
}

# Generate various corporate DPI CA certificates
generate_ca "palo-alto" "Palo Alto Networks" "Palo Alto Networks Enterprise Root CA" 3650
generate_ca "zscaler" "Zscaler Inc" "Zscaler Root CA" 1825
generate_ca "netskope" "Netskope Inc" "Netskope Certificate Authority" 5475
generate_ca "generic-corp" "Acme Corporation" "Acme Corporate Security CA" 7300
generate_ca "malicious" "Test Organization" "Test-CA-localhost" 365

# Create mitmproxy-compatible certificate (PEM format expected)
echo "🔄 Creating mitmproxy default certificate..."
cp "$CERT_DIR/generic-corp-ca-cert.pem" "$CERT_DIR/mitmproxy-ca-cert.pem"
cp "$CERT_DIR/generic-corp-ca-key.pem" "$CERT_DIR/mitmproxy-ca-key.pem"

# Create combined certificate file for mitmproxy
cat "$CERT_DIR/mitmproxy-ca-cert.pem" "$CERT_DIR/mitmproxy-ca-key.pem" > "$CERT_DIR/mitmproxy-ca.pem"

# Generate certificate installation instructions
cat > "$CERT_DIR/README.md" << 'EOF'
# Corporate CA Certificates for DPI Testing

## Generated Certificates

This directory contains corporate CA certificates for testing CypherHawk DPI detection:

- **palo-alto-ca-cert.pem** - Palo Alto Networks corporate CA
- **zscaler-ca-cert.pem** - Zscaler corporate CA  
- **netskope-ca-cert.pem** - Netskope corporate CA
- **generic-corp-ca-cert.pem** - Generic corporate CA
- **malicious-ca-cert.pem** - Malicious/suspicious CA for testing
- **mitmproxy-ca.pem** - Default certificate for mitmproxy

## Windows Installation

### Install CA Certificate (for testing only)
```cmd
# Import CA certificate to Windows certificate store
certlm.msc
# Or use PowerShell:
Import-Certificate -FilePath "generic-corp-ca-cert.pem" -CertStoreLocation "Cert:\LocalMachine\Root"
```

### Configure System Proxy
```cmd
# Set system proxy (run as Administrator)
netsh winhttp set proxy proxy-server="127.0.0.1:8080"

# To remove proxy later:
netsh winhttp reset proxy
```

## Testing with CypherHawk

1. Start mitmproxy with corporate CA
2. Configure Windows to use the proxy
3. Install the CA certificate 
4. Run CypherHawk to detect the corporate certificates:

```bash
# Build and run CypherHawk
go build -o cypherhawk.exe ./cmd/cypherhawk
./cypherhawk.exe -url https://www.google.com
```

## Security Warning

⚠️ **Only use these certificates in test environments!**

- These are self-signed certificates for testing only
- Installing them reduces your browser security
- Remove them after testing
- Never use in production environments

EOF

# Set permissions
chmod 644 "$CERT_DIR"/*.pem "$CERT_DIR"/*.p12 "$CERT_DIR/README.md"

echo ""
echo "✅ Corporate CA certificates generated successfully!"
echo "📁 Certificates saved to: $CERT_DIR"
echo "📋 See $CERT_DIR/README.md for installation instructions"
echo ""
echo "🔧 To use with mitmproxy:"
echo "   1. Start: docker-compose up mitmproxy"
echo "   2. Install CA: Import generic-corp-ca-cert.pem to Windows certificate store"
echo "   3. Set proxy: Configure Windows to use 127.0.0.1:8080"
echo "   4. Test: Run CypherHawk against any HTTPS website"
echo ""