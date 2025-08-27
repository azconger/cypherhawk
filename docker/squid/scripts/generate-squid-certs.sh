#!/bin/sh
# Generate corporate certificates for Squid DPI testing

set -e

CERT_DIR="/certs"

echo "🔐 Generating Squid DPI certificates..."

# Install OpenSSL if not available
if ! command -v openssl > /dev/null; then
    apk add --no-cache openssl
fi

# Create certificate directory
mkdir -p "$CERT_DIR"

# Generate different corporate CA profiles for Squid
generate_squid_ca() {
    local name="$1"
    local org="$2" 
    local cn="$3"
    local validity_days="$4"
    
    echo "📋 Generating $name Squid CA..."
    
    # Generate private key
    openssl genrsa -out "$CERT_DIR/${name}-squid-key.pem" 2048
    
    # Create CA certificate
    openssl req -new -x509 -key "$CERT_DIR/${name}-squid-key.pem" \
        -out "$CERT_DIR/${name}-squid-cert.pem" \
        -days "$validity_days" \
        -subj "/C=US/ST=CA/L=San Francisco/O=$org/CN=$cn"
    
    # Combine for Squid format
    cat "$CERT_DIR/${name}-squid-cert.pem" "$CERT_DIR/${name}-squid-key.pem" > "$CERT_DIR/${name}-squid.pem"
    
    echo "✅ Generated $name Squid CA"
}

# Generate corporate DPI CAs
generate_squid_ca "palo-alto" "Palo Alto Networks" "Palo Alto Networks Proxy CA" 3650
generate_squid_ca "zscaler" "Zscaler Inc" "Zscaler Proxy CA" 1825
generate_squid_ca "netskope" "Netskope Inc" "Netskope Proxy CA" 5475
generate_squid_ca "generic" "Acme Corporation" "Acme Corporate Proxy CA" 7300

# Create default certificate for Squid
echo "🔄 Creating default Squid certificate..."
cp "$CERT_DIR/generic-squid.pem" "$CERT_DIR/corporate-ca.pem"
cp "$CERT_DIR/generic-squid-cert.pem" "$CERT_DIR/corporate-ca-cert.pem"
cp "$CERT_DIR/generic-squid-key.pem" "$CERT_DIR/corporate-ca-key.pem"

# Set permissions
chmod 600 "$CERT_DIR"/*-key.pem "$CERT_DIR"/*.pem
chmod 644 "$CERT_DIR"/*-cert.pem

# Generate Windows installation guide
cat > "$CERT_DIR/SQUID-SETUP.md" << 'EOF'
# Squid DPI Proxy Setup for Windows

## Installation Steps

### 1. Start Squid DPI Proxy
```bash
# Start Squid with SSL bumping
docker-compose up squid-dpi

# Or with logs
docker-compose up squid-dpi --logs
```

### 2. Install Corporate CA Certificate

Copy the CA certificate to Windows:
```cmd
# Copy certificate to Windows (from WSL/PowerShell)
copy \\wsl$\Ubuntu\path\to\certs\corporate-ca-cert.pem C:\temp\

# Import to Windows certificate store (Run as Administrator)
certlm.msc
```

Or use PowerShell:
```powershell
# Import CA certificate (Run as Administrator) 
Import-Certificate -FilePath "C:\temp\corporate-ca-cert.pem" -CertStoreLocation "Cert:\LocalMachine\Root"
```

### 3. Configure Windows Proxy

**Option A: System-wide proxy (Recommended)**
```cmd
# Set system proxy (Run as Administrator)
netsh winhttp set proxy proxy-server="127.0.0.1:3128"

# Verify settings
netsh winhttp show proxy
```

**Option B: Browser proxy (Chrome/Edge)**
1. Open Chrome settings
2. Advanced > System > Open proxy settings
3. Set HTTP proxy: 127.0.0.1:3128
4. Set HTTPS proxy: 127.0.0.1:3128

### 4. Test DPI Detection

```bash
# Build CypherHawk (if not already built)
cd /path/to/cypherhawk
go build -o cypherhawk.exe ./cmd/cypherhawk

# Test against any HTTPS website
./cypherhawk.exe -url https://www.google.com
./cypherhawk.exe -url https://github.com
./cypherhawk.exe -url https://stackoverflow.com

# Save detected certificates
./cypherhawk.exe -o detected-certs.pem
```

## Expected Results

CypherHawk should detect:
- Corporate CA certificate not in Mozilla's bundle
- Certificate chain showing Squid proxy interception
- Suspicious certificate characteristics

## Cleanup

```cmd
# Remove system proxy
netsh winhttp reset proxy

# Remove CA certificate (Run as Administrator)
# Use certlm.msc to manually remove from "Trusted Root Certification Authorities"
```

## Troubleshooting

### Certificate Trust Issues
- Ensure CA certificate is installed in "Trusted Root Certification Authorities"
- Restart browser after certificate installation
- Check Windows event logs for certificate errors

### Proxy Connection Issues  
- Verify Docker container is running: `docker ps`
- Check Squid logs: `docker-compose logs squid-dpi`
- Test direct connection: `curl -v --proxy 127.0.0.1:3128 https://www.google.com`

### CypherHawk Not Detecting
- Verify proxy is intercepting traffic
- Check that CA certificate is NOT in Mozilla's bundle
- Use verbose mode: `./cypherhawk.exe --verbose`

## Security Warning

⚠️ **Test Environment Only!**
- These certificates are for testing only
- Remove proxy configuration after testing  
- Uninstall CA certificates when done
- Never use in production
EOF

echo ""
echo "✅ Squid DPI certificates generated successfully!"
echo "📁 Certificates location: $CERT_DIR"
echo "📋 Setup instructions: $CERT_DIR/SQUID-SETUP.md"
echo ""
echo "🔧 Next steps:"
echo "   1. Start Squid: docker-compose up squid-dpi"
echo "   2. Install CA: Import corporate-ca-cert.pem to Windows"
echo "   3. Set proxy: netsh winhttp set proxy proxy-server=\"127.0.0.1:3128\""
echo "   4. Test: Run CypherHawk against any HTTPS site"