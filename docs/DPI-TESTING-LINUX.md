# Linux DPI Testing Guide for CypherHawk

> **Other Platforms:** [Windows Guide](DPI-TESTING-WINDOWS.md) | [macOS Guide](DPI-TESTING-MACOS.md) | [Overview](DPI-TESTING.md)

This guide shows you how to set up a realistic DPI testing environment on Linux to validate CypherHawk's detection capabilities. You'll simulate corporate DPI/proxy behavior without needing expensive enterprise solutions.

## 🎯 Overview

We provide **three approaches** from easiest to most realistic:

1. **🚀 Go Test Server** - Standalone HTTPS server (easiest, no Docker needed)
2. **🐳 mitmproxy** - Professional proxy with SSL interception (recommended)
3. **🌐 Squid Proxy** - Enterprise-grade proxy with SSL bumping (most realistic)

## Prerequisites

- Linux (Ubuntu 20.04+, CentOS 8+, Fedora 35+, or similar)
- [Go 1.19+](https://golang.org/dl/) for building CypherHawk
- [Docker](https://docs.docker.com/engine/install/) and [Docker Compose](https://docs.docker.com/compose/install/) (for options 2 & 3)
- Git for cloning the repository
- Root/sudo access for certificate operations

## 🚀 Option 1: Go Test Server (Easiest)

**Perfect for:** Quick validation, no additional software needed

### Setup Steps

1. **Build the DPI test server:**
   ```bash
   cd /path/to/cypherhawk
   go build -o dpi-test-server ./cmd/dpi-test-server
   ```

2. **Start a DPI simulation:**
   ```bash
   # Generic corporate DPI
   ./dpi-test-server -profile generic

   # Palo Alto Networks simulation  
   ./dpi-test-server -profile palo-alto -port 8443

   # Malicious DPI for high-risk testing
   ./dpi-test-server -profile malicious -output-certs ./test-certs
   ```

3. **Test with CypherHawk:**
   ```bash
   # Build CypherHawk
   go build -o cypherhawk ./cmd/cypherhawk

   # Test against the DPI server
   ./cypherhawk --url https://localhost:8446

   # Expected output: Corporate DPI detected with certificate details
   ```

### Cleanup
```bash
# Stop the test server (Ctrl+C)
# No certificates are installed system-wide with this approach
pkill -f dpi-test-server 2>/dev/null || true
```

## 🐳 Option 2: mitmproxy (Recommended)

**Perfect for:** Realistic HTTPS interception, modern corporate proxy simulation

### Setup Steps

1. **Start mitmproxy with corporate CA:**
   ```bash
   cd docker/mitmproxy
   
   # Generate corporate CA certificate
   docker-compose --profile tools run mitmproxy-cert-gen
   
   # Start mitmproxy with SSL interception
   docker-compose up mitmproxy-dpi
   ```

2. **Install corporate CA certificate (optional, for browser testing):**
   ```bash
   # Copy certificate from container
   docker cp mitmproxy-dpi:/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem ./corporate-ca.pem

   # Install in system certificate store (Ubuntu/Debian)
   sudo cp corporate-ca.pem /usr/local/share/ca-certificates/mitmproxy-corporate-ca.crt
   sudo update-ca-certificates

   # Install in system certificate store (CentOS/RHEL/Fedora)
   sudo cp corporate-ca.pem /etc/pki/ca-trust/source/anchors/mitmproxy-corporate-ca.pem
   sudo update-ca-trust

   # Install in system certificate store (Arch Linux)
   sudo cp corporate-ca.pem /etc/ca-certificates/trust-source/anchors/mitmproxy-corporate-ca.pem
   sudo trust extract-compat
   ```

3. **Configure system proxy:**
   ```bash
   # Set HTTP/HTTPS proxy environment variables
   export HTTP_PROXY=http://127.0.0.1:8080
   export HTTPS_PROXY=http://127.0.0.1:8080
   export http_proxy=http://127.0.0.1:8080
   export https_proxy=http://127.0.0.1:8080

   # For GUI applications (GNOME)
   gsettings set org.gnome.system.proxy mode 'manual'
   gsettings set org.gnome.system.proxy.http host '127.0.0.1'
   gsettings set org.gnome.system.proxy.http port 8080
   gsettings set org.gnome.system.proxy.https host '127.0.0.1'
   gsettings set org.gnome.system.proxy.https port 8080

   # For GUI applications (KDE)
   # Use System Settings > Network > Proxy to configure manually
   ```

4. **Test with CypherHawk:**
   ```bash
   # Test CypherHawk detection (should detect corporate DPI)
   ./cypherhawk --verbose --url https://www.google.com

   # Save extracted certificates
   ./cypherhawk --output mitmproxy-certs.pem --url https://www.google.com
   ```

5. **Verify proxy interception:**
   ```bash
   # Test direct connection vs proxy
   curl -x http://127.0.0.1:8080 -k https://www.google.com -I
   
   # Check certificate chain
   openssl s_client -connect www.google.com:443 -proxy 127.0.0.1:8080 -showcerts
   ```

## 🌐 Option 3: Squid Proxy (Most Realistic)

**Perfect for:** Enterprise-grade DPI simulation, maximum realism

### Setup Steps

1. **Start Squid DPI proxy:**
   ```bash
   cd docker/squid
   
   # Generate corporate certificates 
   docker-compose --profile tools run squid-cert-gen
   
   # Start Squid with SSL bumping
   docker-compose up squid-dpi
   ```

2. **Install corporate CA certificate:**
   ```bash
   # Copy certificate from container
   docker cp squid-dpi:/etc/squid/ssl_cert/corporate-ca.pem ./squid-corporate-ca.pem

   # Install in system certificate store (Ubuntu/Debian)
   sudo cp squid-corporate-ca.pem /usr/local/share/ca-certificates/squid-corporate-ca.crt  
   sudo update-ca-certificates

   # Install in system certificate store (CentOS/RHEL/Fedora)
   sudo cp squid-corporate-ca.pem /etc/pki/ca-trust/source/anchors/squid-corporate-ca.pem
   sudo update-ca-trust

   # Install in system certificate store (Arch Linux)
   sudo cp squid-corporate-ca.pem /etc/ca-certificates/trust-source/anchors/squid-corporate-ca.pem
   sudo trust extract-compat
   ```

3. **Configure system proxy:**
   ```bash
   # Set proxy environment variables
   export HTTP_PROXY=http://127.0.0.1:3128
   export HTTPS_PROXY=http://127.0.0.1:3128

   # For GUI applications (GNOME)
   gsettings set org.gnome.system.proxy mode 'manual'
   gsettings set org.gnome.system.proxy.http host '127.0.0.1'
   gsettings set org.gnome.system.proxy.http port 3128
   gsettings set org.gnome.system.proxy.https host '127.0.0.1'
   gsettings set org.gnome.system.proxy.https port 3128
   ```

4. **Test with CypherHawk:**
   ```bash
   # Test DPI detection
   ./cypherhawk --verbose --analyze

   # Extract certificates for Java applications  
   ./cypherhawk --output squid-dpi-certs.pem
   ```

5. **Advanced testing:**
   ```bash
   # Test various protocols
   curl -x http://127.0.0.1:3128 https://www.google.com -v
   wget --proxy=on --https-proxy=127.0.0.1:3128 https://www.google.com -O /dev/null

   # Analyze certificate chain
   openssl s_client -connect www.google.com:443 -proxy 127.0.0.1:3128
   ```

## 🔒 Security Considerations

### ⚠️ Important Warnings

- **Test Environment Only**: These setups create security vulnerabilities
- **Remove After Testing**: Always cleanup certificates and proxy settings
- **Private Network**: Only use on isolated/home networks
- **Legal Compliance**: Only intercept your own traffic
- **Certificate Validation**: Never install unknown CA certificates permanently

### 🧹 Complete Cleanup Guide

**⚠️ CRITICAL:** Failure to properly remove test certificates can leave your system vulnerable to MitM attacks. Follow all steps carefully.

#### Step 1: Stop All Test Services

```bash
# Stop Docker containers
cd docker/mitmproxy && docker-compose down --remove-orphans 2>/dev/null || true
cd ../squid && docker-compose down --remove-orphans 2>/dev/null || true
cd ../.. # Return to project root
docker system prune -f

# Kill any running DPI test servers
pkill -f dpi-test-server 2>/dev/null || true
```

#### Step 2: Remove Proxy Configuration

```bash
# Clear proxy environment variables
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy

# Reset GNOME proxy settings
if command -v gsettings >/dev/null 2>&1; then
    gsettings set org.gnome.system.proxy mode 'none'
    gsettings reset org.gnome.system.proxy.http host 2>/dev/null || true
    gsettings reset org.gnome.system.proxy.http port 2>/dev/null || true
    gsettings reset org.gnome.system.proxy.https host 2>/dev/null || true
    gsettings reset org.gnome.system.proxy.https port 2>/dev/null || true
fi

# Clear proxy from shell profile files
sed -i '/HTTP_PROXY\|HTTPS_PROXY\|http_proxy\|https_proxy/d' ~/.bashrc 2>/dev/null || true
sed -i '/HTTP_PROXY\|HTTPS_PROXY\|http_proxy\|https_proxy/d' ~/.zshrc 2>/dev/null || true
```

#### Step 3: Remove Test CA Certificates (SAFE CLI METHOD)

**Ubuntu/Debian Systems:**

```bash
# List potentially problematic certificates
echo "🔍 Scanning for test certificates in /usr/local/share/ca-certificates..."
find /usr/local/share/ca-certificates -name "*test*" -o -name "*corporate*" -o -name "*mitmproxy*" -o -name "*squid*" -o -name "*acme*" 2>/dev/null || true

# Function to safely remove certificates
remove_test_certs_debian() {
    local cert_pattern="$1"
    local certs=$(find /usr/local/share/ca-certificates -name "*${cert_pattern}*" 2>/dev/null)
    
    if [ -n "$certs" ]; then
        echo "Found test certificates matching '$cert_pattern':"
        echo "$certs"
        echo "Remove these certificates? (y/N)"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            echo "$certs" | while IFS= read -r cert_file; do
                if [ -f "$cert_file" ]; then
                    echo "Removing: $cert_file"
                    sudo rm -f "$cert_file"
                fi
            done
            sudo update-ca-certificates
        fi
    else
        echo "✅ No certificates found matching '$cert_pattern'"
    fi
}

# Remove test certificates by pattern
remove_test_certs_debian "mitmproxy"
remove_test_certs_debian "squid"
remove_test_certs_debian "corporate"
remove_test_certs_debian "acme"
remove_test_certs_debian "test"
```

**CentOS/RHEL/Fedora Systems:**

```bash
# List potentially problematic certificates
echo "🔍 Scanning for test certificates in /etc/pki/ca-trust/source/anchors..."
find /etc/pki/ca-trust/source/anchors -name "*test*" -o -name "*corporate*" -o -name "*mitmproxy*" -o -name "*squid*" -o -name "*acme*" 2>/dev/null || true

# Function to safely remove certificates
remove_test_certs_rhel() {
    local cert_pattern="$1"
    local certs=$(find /etc/pki/ca-trust/source/anchors -name "*${cert_pattern}*" 2>/dev/null)
    
    if [ -n "$certs" ]; then
        echo "Found test certificates matching '$cert_pattern':"
        echo "$certs"
        echo "Remove these certificates? (y/N)"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            echo "$certs" | while IFS= read -r cert_file; do
                if [ -f "$cert_file" ]; then
                    echo "Removing: $cert_file"
                    sudo rm -f "$cert_file"
                fi
            done
            sudo update-ca-trust
        fi
    else
        echo "✅ No certificates found matching '$cert_pattern'"
    fi
}

# Remove test certificates by pattern
remove_test_certs_rhel "mitmproxy"
remove_test_certs_rhel "squid"
remove_test_certs_rhel "corporate"
remove_test_certs_rhel "acme"
remove_test_certs_rhel "test"
```

**Arch Linux Systems:**

```bash
# List potentially problematic certificates
echo "🔍 Scanning for test certificates in /etc/ca-certificates/trust-source/anchors..."
find /etc/ca-certificates/trust-source/anchors -name "*test*" -o -name "*corporate*" -o -name "*mitmproxy*" -o -name "*squid*" -o -name "*acme*" 2>/dev/null || true

# Function to safely remove certificates
remove_test_certs_arch() {
    local cert_pattern="$1"
    local certs=$(find /etc/ca-certificates/trust-source/anchors -name "*${cert_pattern}*" 2>/dev/null)
    
    if [ -n "$certs" ]; then
        echo "Found test certificates matching '$cert_pattern':"
        echo "$certs"
        echo "Remove these certificates? (y/N)"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            echo "$certs" | while IFS= read -r cert_file; do
                if [ -f "$cert_file" ]; then
                    echo "Removing: $cert_file"
                    sudo rm -f "$cert_file"
                fi
            done
            sudo trust extract-compat
        fi
    else
        echo "✅ No certificates found matching '$cert_pattern'"
    fi
}

# Remove test certificates by pattern
remove_test_certs_arch "mitmproxy"
remove_test_certs_arch "squid"
remove_test_certs_arch "corporate"
remove_test_certs_arch "acme"
remove_test_certs_arch "test"
```

#### Step 4: Clear Browser Certificate Caches

```bash
# Stop browsers
pkill -x firefox 2>/dev/null || true
pkill -x chromium-browser 2>/dev/null || true
pkill -x google-chrome 2>/dev/null || true
pkill -x chrome 2>/dev/null || true

# Clear system DNS cache
if command -v systemctl >/dev/null 2>&1; then
    # SystemD systems
    sudo systemctl flush-dns 2>/dev/null || true
    sudo systemctl restart systemd-resolved 2>/dev/null || true
elif command -v service >/dev/null 2>&1; then
    # SysV init systems
    sudo service nscd restart 2>/dev/null || true
    sudo service dnsmasq restart 2>/dev/null || true
fi

echo "🔄 Browser certificate caches cleared. Restart browsers to ensure clean state."
```

#### Step 5: Verification

```bash
# Verify test certificates are removed
echo "🔍 Verifying certificate removal..."

# Check different distro certificate stores
cert_locations=(
    "/usr/local/share/ca-certificates"
    "/etc/pki/ca-trust/source/anchors"  
    "/etc/ca-certificates/trust-source/anchors"
)

test_cert_count=0
for location in "${cert_locations[@]}"; do
    if [ -d "$location" ]; then
        for pattern in "test" "corporate" "mitmproxy" "squid" "acme"; do
            count=$(find "$location" -name "*${pattern}*" 2>/dev/null | wc -l)
            if [ "$count" -gt 0 ]; then
                echo "⚠️ WARNING: Found $count certificates matching '$pattern' in $location"
                find "$location" -name "*${pattern}*" 2>/dev/null
                test_cert_count=$((test_cert_count + count))
            fi
        done
    fi
done

if [ $test_cert_count -eq 0 ]; then
    echo "✅ All test certificates successfully removed"
else
    echo "⚠️ WARNING: $test_cert_count test certificates still present"
    echo "Review and remove manually if needed"
fi

# Test normal HTTPS connection
echo "🔗 Testing normal HTTPS connection..."
if curl -s --connect-timeout 5 https://www.google.com > /dev/null 2>&1; then
    echo "✅ HTTPS connections working normally"
else
    echo "❌ HTTPS connection issues - check network settings"
fi

# Verify proxy settings are cleared
if [ -z "$HTTP_PROXY" ] && [ -z "$HTTPS_PROXY" ]; then
    echo "✅ Proxy environment variables cleared"
else
    echo "⚠️ WARNING: Proxy environment variables still set:"
    env | grep -i proxy || true
fi
```

#### 🚨 Emergency Certificate Cleanup

If you accidentally installed malicious certificates or need to reset everything:

```bash
# NUCLEAR OPTION: Reset all user-installed certificates  
# WARNING: This removes ALL user-installed certificates, including legitimate ones
# Only use if you understand the consequences

echo "⚠️ EMERGENCY CLEANUP - This will remove ALL user-installed certificates"
echo "Continue? (y/N)"
read -r response

if [[ "$response" =~ ^[Yy]$ ]]; then
    # Ubuntu/Debian
    if [ -d "/usr/local/share/ca-certificates" ]; then
        sudo find /usr/local/share/ca-certificates -type f -delete
        sudo update-ca-certificates --fresh
    fi
    
    # CentOS/RHEL/Fedora
    if [ -d "/etc/pki/ca-trust/source/anchors" ]; then
        sudo find /etc/pki/ca-trust/source/anchors -type f -delete
        sudo update-ca-trust
    fi
    
    # Arch Linux
    if [ -d "/etc/ca-certificates/trust-source/anchors" ]; then
        sudo find /etc/ca-certificates/trust-source/anchors -type f -delete
        sudo trust extract-compat
    fi
    
    echo "🔄 All user-installed certificates removed. You may need to:"
    echo "  - Reinstall legitimate corporate certificates"
    echo "  - Reconfigure applications that depend on custom CAs"  
    echo "  - Contact IT support for required certificates"
fi
```

#### Automated Cleanup Script

```bash
# Use the automated validation script for comprehensive cleanup
if [ -f "./scripts/validate-dpi-setup.sh" ]; then
    echo "🤖 Running automated cleanup script..."
    ./scripts/validate-dpi-setup.sh --cleanup
else
    echo "⚠️ Automated cleanup script not found - using manual steps above"
fi
```

## 🎓 Educational Value

This setup teaches you:

1. **How corporate DPI works** - Certificate substitution, SSL bumping
2. **Certificate chain analysis** - Understanding trust relationships  
3. **Security implications** - Why unknown CAs are dangerous
4. **Detection techniques** - How CypherHawk identifies DPI
5. **Linux certificate management** - System certificate stores and trust

## 📚 Next Steps

After successful testing:

1. **Try different profiles** - Test various DPI vendors
2. **Analyze output** - Study the certificate characteristics CypherHawk detects
3. **Compare results** - Test legitimate sites vs. corporate DPI
4. **Integrate with HawkScan** - Use generated PEM files with StackHawk
5. **Cross-platform testing** - Compare results with Windows/macOS environments

---

**⚠️ Remember:** Always clean up test certificates completely to maintain system security!