# macOS DPI Testing Guide for CypherHawk

> **Other Platforms:** [Windows Guide](DPI-TESTING-WINDOWS.md) | [Linux Guide](DPI-TESTING-LINUX.md) | [Overview](DPI-TESTING.md)

This guide shows you how to set up a realistic DPI testing environment on macOS to validate CypherHawk's detection capabilities. You'll simulate corporate DPI/proxy behavior without needing expensive enterprise solutions.

## 🎯 Overview

We provide **three approaches** from easiest to most realistic:

1. **🚀 Go Test Server** - Standalone HTTPS server (easiest, no Docker needed)
2. **🐳 mitmproxy** - Professional proxy with SSL interception (recommended)
3. **🌐 Squid Proxy** - Enterprise-grade proxy with SSL bumping (most realistic)

## Prerequisites

- macOS 10.15+ (Intel or Apple Silicon)
- [Go 1.19+](https://golang.org/dl/) for building CypherHawk
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (for options 2 & 3)
- Git for cloning the repository
- Administrator access for certificate operations

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
   ./cypherhawk -url https://localhost:8446
   
   # Save detected certificates
   ./cypherhawk -url https://localhost:8446 -o dpi-certs.pem
   ```

### Available Profiles

```bash
# List all available profiles
./dpi-test-server -list
```

| Profile | Organization | Port | Description |
|---------|--------------|------|-------------|
| `palo-alto` | Palo Alto Networks | 8443 | Enterprise firewall simulation |
| `zscaler` | Zscaler Inc | 8444 | Cloud security platform |
| `netskope` | Netskope Inc | 8445 | Cloud access security broker |
| `generic` | Acme Corporation | 8446 | Generic corporate DPI |
| `malicious` | Test Organization | 8447 | Suspicious/malicious DPI |

## 🐳 Option 2: mitmproxy (Recommended)

**Perfect for:** Realistic transparent proxy testing, modern UI

### Setup Steps

1. **Start mitmproxy:**
   ```bash
   cd docker/mitmproxy
   
   # Generate corporate certificates
   docker-compose --profile tools run cert-generator
   
   # Start mitmproxy
   docker-compose up mitmproxy
   ```

2. **Install corporate CA certificate:**

   **Method A: Keychain Access (GUI)**
   ```bash
   # Copy certificate from container
   docker cp cypherhawk-mitmproxy:/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem ./corporate-ca.pem
   
   # Double-click the PEM file to open Keychain Access
   open corporate-ca.pem
   ```
   
   In Keychain Access:
   1. Select "System" keychain (requires admin password)
   2. Certificate appears in "Certificates" category  
   3. Double-click the certificate → Trust → "Always Trust"
   4. Enter admin password to confirm

   **Method B: Command Line**
   ```bash
   # Install directly to system keychain (requires sudo)
   sudo security add-trusted-cert -d -r trustRoot \
     -k /System/Library/Keychains/SystemRootCertificates.keychain \
     corporate-ca.pem
   ```

3. **Configure macOS proxy:**

   **Method A: System Preferences (GUI)**
   1. System Preferences → Network
   2. Select your active connection (Wi-Fi/Ethernet)
   3. Advanced → Proxies tab
   4. Check "Web Proxy (HTTP)" and "Secure Web Proxy (HTTPS)"
   5. Server: `127.0.0.1`, Port: `8080` for both
   6. Apply changes

   **Method B: Command Line**
   ```bash
   # Set system proxy (requires admin password)
   sudo networksetup -setwebproxy "Wi-Fi" 127.0.0.1 8080
   sudo networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 8080
   
   # For Ethernet instead of Wi-Fi
   sudo networksetup -setwebproxy "Ethernet" 127.0.0.1 8080
   sudo networksetup -setsecurewebproxy "Ethernet" 127.0.0.1 8080
   
   # Verify proxy settings
   networksetup -getwebproxy "Wi-Fi"
   networksetup -getsecurewebproxy "Wi-Fi"
   ```

4. **Test DPI detection:**
   ```bash
   # Test against real websites (now proxied through mitmproxy)
   ./cypherhawk -url https://www.google.com
   ./cypherhawk -url https://github.com
   ./cypherhawk --verbose
   
   # Save all detected corporate certificates
   ./cypherhawk -o corporate-dpi-certs.pem
   ```

5. **Monitor traffic (optional):**
   - Open browser to http://127.0.0.1:8081 for mitmproxy web interface
   - View real-time HTTPS interception and certificate substitution

### Cleanup

```bash
# Remove proxy configuration
sudo networksetup -setwebproxystate "Wi-Fi" off
sudo networksetup -setsecurewebproxystate "Wi-Fi" off

# Remove CA certificate via Keychain Access
# 1. Open Keychain Access
# 2. System keychain → Certificates
# 3. Find and delete the corporate CA certificate
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

   **Method A: Keychain Access**
   ```bash
   # Copy certificate from container
   docker cp cypherhawk-squid-dpi:/etc/squid/certs/corporate-ca-cert.pem ./squid-ca.pem
   
   # Open in Keychain Access
   open squid-ca.pem
   ```
   
   Follow the same Keychain Access steps as mitmproxy above.

   **Method B: Command Line**
   ```bash
   # Install to system keychain
   sudo security add-trusted-cert -d -r trustRoot \
     -k /System/Library/Keychains/SystemRootCertificates.keychain \
     squid-ca.pem
   ```

3. **Configure macOS proxy:**

   **System Preferences Method:**
   1. System Preferences → Network → Advanced → Proxies
   2. Check "Web Proxy (HTTP)" and "Secure Web Proxy (HTTPS)"
   3. Server: `127.0.0.1`, Port: `3128` for both
   4. Apply changes

   **Command Line Method:**
   ```bash
   # Set system proxy for both HTTP and HTTPS
   sudo networksetup -setwebproxy "Wi-Fi" 127.0.0.1 3128
   sudo networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 3128
   
   # Verify settings
   networksetup -getwebproxy "Wi-Fi"
   networksetup -getsecurewebproxy "Wi-Fi"
   ```

4. **Test enterprise DPI detection:**
   ```bash
   # Test against various websites
   ./cypherhawk -url https://www.google.com
   ./cypherhawk -url https://stackoverflow.com  
   ./cypherhawk -url https://api.github.com
   
   # Verbose analysis
   ./cypherhawk --verbose -o enterprise-dpi.pem
   ```

5. **Monitor Squid logs:**
   ```bash
   # View SSL bumping in action
   docker-compose logs -f squid-dpi
   
   # Check access logs
   docker exec cypherhawk-squid-dpi tail -f /var/log/squid/access.log
   ```

## 🧪 Automated Testing & Validation

### Quick Validation Script

```bash
# Test standalone DPI server
./scripts/validate-dpi-setup.sh --test-type standalone

# Test mitmproxy setup
./scripts/validate-dpi-setup.sh --test-type mitmproxy

# Test Squid proxy setup
./scripts/validate-dpi-setup.sh --test-type squid

# Complete cleanup
./scripts/validate-dpi-setup.sh --cleanup
```

### Expected CypherHawk Output

**✅ Successful DPI Detection:**
```
🔍 Analyzing certificate chains from 4 endpoints...

⚠️  CORPORATE DPI DETECTED ⚠️  
Unknown CA certificates detected (not in Mozilla's trusted bundle):

🏢 Certificate: Acme Corporate Security CA
   Issuer: Acme Corporate Security CA (Self-signed)
   Serial: 1
   Valid: 2025-08-25 to 2035-08-25 (10.0 years)
   
📊 Security Analysis:
   ✓ Suspicious serial number: 1
   ✓ Unusually long validity period (10.0 years)
   ✓ Self-signed root certificate
   → HIGH RISK: Multiple suspicious indicators detected
```

**❌ No DPI (Normal traffic):**
```
✅ No corporate DPI detected
All certificates verified against Mozilla's CA bundle
```

## 🍎 macOS-Specific Tips

### Apple Silicon vs Intel Macs
- **Both supported**: CypherHawk builds native binaries for both architectures
- **Docker Desktop**: Works on both, but Apple Silicon may need Rosetta for some containers
- **Performance**: Apple Silicon Macs typically run tests faster

### Keychain Access Tips
- **System vs Login**: Install corporate CAs in "System" keychain (requires admin)
- **Trust settings**: Always set to "Always Trust" for SSL
- **Backup**: Export your current certificates before testing
- **Multiple certificates**: Import each corporate CA separately

### Network Interface Names
Common macOS network interface names:
```bash
# Check your interface names
networksetup -listallnetworkservices

# Common names:
# - "Wi-Fi" (most common)
# - "Ethernet" (wired connections)  
# - "USB 10/100/1000 LAN" (USB adapters)
# - "Thunderbolt Bridge" (rare)
```

### macOS Security Gatekeeper
If you see "cannot be opened because it is from an unidentified developer":
```bash
# Allow the binary to run (one-time)
sudo xattr -rd com.apple.quarantine ./cypherhawk
sudo xattr -rd com.apple.quarantine ./dpi-test-server

# Or build from source (recommended)
go build -o cypherhawk ./cmd/cypherhawk
```

## 🔧 Troubleshooting

### Certificate Trust Issues

**Problem**: "Certificate not trusted" errors
```bash
# Verify certificate is installed
security find-certificate -c "Acme Corporate Security CA" -p /System/Library/Keychains/SystemRootCertificates.keychain

# Check trust settings
security dump-trust-settings -s

# Re-install if needed
sudo security add-trusted-cert -d -r trustRoot -k /System/Library/Keychains/SystemRootCertificates.keychain corporate-ca.pem
```

**Problem**: Keychain Access shows "This certificate is marked as trusted for all users"
- This is correct! It means the certificate is properly installed.

### Proxy Connection Issues  

**Problem**: "No route to host" or connection timeouts
```bash
# Test proxy connectivity
curl -v --proxy 127.0.0.1:8080 https://www.google.com

# Check Docker containers are running
docker ps | grep cypherhawk

# Check logs
docker-compose logs mitmproxy
docker-compose logs squid-dpi

# Verify proxy settings
networksetup -getwebproxy "Wi-Fi"
networksetup -getsecurewebproxy "Wi-Fi"
```

**Problem**: Safari shows "Cannot establish a secure connection"
- Normal! This means the corporate CA isn't trusted by Safari yet
- Install the CA certificate properly via Keychain Access

### CypherHawk Not Detecting

**Problem**: Shows "No corporate DPI detected" when it should detect
```bash
# Use verbose mode for detailed analysis
./cypherhawk --verbose

# Test specific endpoints
./cypherhawk -url https://www.google.com

# Verify certificates are being intercepted
openssl s_client -connect www.google.com:443 -proxy 127.0.0.1:8080 -showcerts

# Check certificate is actually corporate
openssl x509 -in corporate-ca.pem -text -noout | grep "Subject:"
```

### Docker Desktop Issues

**Problem**: Docker Desktop not starting on Apple Silicon
- Enable "Use Rosetta for x86/amd64 emulation" in Docker Desktop settings
- Restart Docker Desktop after enabling

**Problem**: Port already in use
```bash
# Find what's using the port
lsof -i :8080   # for mitmproxy
lsof -i :3128   # for squid

# Stop the conflicting process or use different ports
./dpi-test-server -port 9446
```

### Network Interface Issues

**Problem**: `networksetup` command fails
```bash
# List available network services
networksetup -listallnetworkservices

# Use the exact name from the list
sudo networksetup -setwebproxy "Wi-Fi" 127.0.0.1 8080
# Not: sudo networksetup -setwebproxy "WiFi" 127.0.0.1 8080
```

## 🔒 Security Considerations

### ⚠️ Important Warnings

- **Test Environment Only**: These setups create security vulnerabilities
- **Remove After Testing**: Always cleanup certificates and proxy settings
- **Private Network**: Only use on trusted/home networks
- **Legal Compliance**: Only intercept your own traffic
- **Certificate Validation**: Never install unknown CA certificates permanently

### 🧹 Complete Cleanup Guide

**⚠️ CRITICAL:** Failure to properly remove test certificates can leave your system vulnerable to MitM attacks. Follow all steps carefully.

#### Step 1: Stop All Test Services

```bash
# Stop Docker containers
cd docker/mitmproxy && docker-compose down --remove-orphans 2>/dev/null
cd docker/squid && docker-compose down --remove-orphans 2>/dev/null
cd ../.. # Return to project root
docker system prune -f

# Kill any running DPI test servers
pkill -f dpi-test-server 2>/dev/null || true
```

#### Step 2: Remove Proxy Configuration

```bash
# Reset network proxy settings for all network interfaces
for interface in $(networksetup -listallnetworkservices | grep -v "An asterisk" | grep -v "services"); do
    echo "Clearing proxy for interface: $interface"
    sudo networksetup -setwebproxystate "$interface" off 2>/dev/null || true
    sudo networksetup -setsecurewebproxystate "$interface" off 2>/dev/null || true
    sudo networksetup -setftpproxystate "$interface" off 2>/dev/null || true
    sudo networksetup -setsocksfirewallproxystate "$interface" off 2>/dev/null || true
done

# Clear system proxy environment variables
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy
```

#### Step 3: Remove Test CA Certificates (SAFE CLI METHOD)

**Option A: Command Line Certificate Removal (Recommended)**

```bash
# List all certificates in system keychain to identify test certificates
echo "🔍 Scanning for test certificates..."
security find-certificate -a -c "Test" /Library/Keychains/System.keychain 2>/dev/null || true
security find-certificate -a -c "Corporate" /Library/Keychains/System.keychain 2>/dev/null || true  
security find-certificate -a -c "Acme" /Library/Keychains/System.keychain 2>/dev/null || true
security find-certificate -a -c "DPI" /Library/Keychains/System.keychain 2>/dev/null || true

# Function to safely remove certificates by name pattern
remove_test_certs() {
    local pattern="$1"
    local certs=$(security find-certificate -a -c "$pattern" /Library/Keychains/System.keychain 2>/dev/null | grep "alis" | cut -d'"' -f4)
    
    if [ -n "$certs" ]; then
        echo "Found certificates matching '$pattern':"
        echo "$certs"
        echo "Remove these certificates? (y/N)"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            while IFS= read -r cert_name; do
                if [ -n "$cert_name" ]; then
                    echo "Removing certificate: $cert_name"
                    sudo security delete-certificate -c "$cert_name" /Library/Keychains/System.keychain 2>/dev/null || echo "⚠️ Failed to remove $cert_name (may not exist)"
                fi
            done <<< "$certs"
        fi
    else
        echo "✅ No certificates found matching '$pattern'"
    fi
}

# Remove test certificates by common patterns  
remove_test_certs "Acme Corporate Security CA"
remove_test_certs "Test-CA-localhost"  
remove_test_certs "Palo Alto Networks Enterprise Root CA"
remove_test_certs "mitmproxy"
remove_test_certs "Squid"

# Remove certificates from user keychain as well
echo "🔍 Checking user keychain..."
security find-certificate -a -c "Test" ~/Library/Keychains/login.keychain-db 2>/dev/null || true
security find-certificate -a -c "Corporate" ~/Library/Keychains/login.keychain-db 2>/dev/null || true

# Remove from user keychain if found
user_certs=$(security find-certificate -a -c "Test" ~/Library/Keychains/login.keychain-db 2>/dev/null | grep "alis" | cut -d'"' -f4)
if [ -n "$user_certs" ]; then
    echo "Found test certificates in user keychain. Remove? (y/N)"
    read -r response  
    if [[ "$response" =~ ^[Yy]$ ]]; then
        while IFS= read -r cert_name; do
            security delete-certificate -c "$cert_name" ~/Library/Keychains/login.keychain-db 2>/dev/null || true
        done <<< "$user_certs"
    fi
fi
```

**Option B: Keychain Access GUI (Visual Verification)**

```bash
# Open Keychain Access for manual verification
open "/Applications/Utilities/Keychain Access.app"

# Instructions for manual cleanup:
echo "📋 Manual cleanup in Keychain Access:"
echo "1. Select 'System' keychain in the left sidebar"
echo "2. Click 'Certificates' category"  
echo "3. Look for certificates with these names:"
echo "   - Acme Corporate Security CA"
echo "   - Test-CA-localhost"
echo "   - Palo Alto Networks Enterprise Root CA"
echo "   - mitmproxy"
echo "   - Any certificate issued today with suspicious names"
echo "4. Right-click suspicious certificates and select 'Delete'"
echo "5. Enter your admin password when prompted"
echo "6. Repeat for 'login' keychain"
```

#### Step 4: Clear Browser Certificate Caches

```bash  
# Chrome - Clear certificate cache
if pgrep -x "Google Chrome" > /dev/null; then
    echo "Stopping Chrome..."
    osascript -e 'quit app "Google Chrome"' 2>/dev/null || true
    sleep 2
fi

# Safari - Clear certificate cache
if pgrep -x "Safari" > /dev/null; then
    echo "Stopping Safari..."
    osascript -e 'quit app "Safari"' 2>/dev/null || true
    sleep 2
fi

# Firefox - Clear certificate cache
if pgrep -x "firefox" > /dev/null; then
    echo "Stopping Firefox..."
    osascript -e 'quit app "Firefox"' 2>/dev/null || true
    sleep 2
fi

# Clear system certificate cache
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder 2>/dev/null || true

echo "🔄 Browser certificate caches cleared. Restart browsers to ensure clean state."
```

#### Step 5: Verification

```bash
# Verify test certificates are removed
echo "🔍 Verifying certificate removal..."

test_cert_count=0
for pattern in "Test" "Corporate" "Acme" "DPI"; do
    count=$(security find-certificate -a -c "$pattern" /Library/Keychains/System.keychain 2>/dev/null | grep -c "alis" || echo "0")
    if [ "$count" -gt 0 ]; then
        echo "⚠️ WARNING: Found $count certificates matching '$pattern'"
        test_cert_count=$((test_cert_count + count))
    fi
done

if [ $test_cert_count -eq 0 ]; then
    echo "✅ All test certificates successfully removed"
else
    echo "⚠️ WARNING: $test_cert_count test certificates still present"
    echo "Review manually using Keychain Access"
fi

# Test normal HTTPS connection
echo "🔗 Testing normal HTTPS connection..."
if curl -s --connect-timeout 5 https://www.google.com > /dev/null; then
    echo "✅ HTTPS connections working normally"
else
    echo "❌ HTTPS connection issues - check network settings"
fi
```

#### 🚨 Emergency Certificate Cleanup

If you accidentally installed malicious certificates or need to reset everything:

```bash
# NUCLEAR OPTION: Reset certificate trust settings (requires admin password)
# WARNING: This may affect legitimate certificates and require reconfiguration

echo "⚠️ EMERGENCY CLEANUP - This will reset certificate trust settings"
echo "Continue? (y/N)"
read -r response

if [[ "$response" =~ ^[Yy]$ ]]; then
    # Reset certificate trust settings
    sudo security authorizationdb write com.apple.trust-settings.admin allow
    
    # Remove all user-added certificates (DANGEROUS - use only in emergencies)
    # sudo rm -rf ~/Library/Keychains/*.keychain-db
    # sudo security create-keychain ~/Library/Keychains/login.keychain-db
    
    echo "🔄 Certificate trust settings reset. You may need to:"
    echo "  - Re-accept legitimate corporate certificates"  
    echo "  - Reconfigure browser certificate settings"
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

### Privacy Protection

- **Local operation**: All certificate analysis happens locally
- **No telemetry**: CypherHawk doesn't send data anywhere
- **Temporary setup**: DPI simulation is completely local
- **Audit trail**: All operations are logged and visible

## 🎓 Educational Value

This setup teaches you:

1. **How corporate DPI works** - Certificate substitution, SSL bumping
2. **Certificate chain analysis** - Understanding trust relationships  
3. **Security implications** - Why unknown CAs are dangerous
4. **Detection techniques** - How CypherHawk identifies DPI
5. **macOS networking** - Proxy configuration and certificate management

## 📚 Next Steps

After successful testing:

1. **Try different profiles** - Test various DPI vendors
2. **Analyze output** - Study the certificate characteristics CypherHawk detects
3. **Compare results** - Test legitimate sites vs. corporate DPI
4. **Integrate with HawkScan** - Use generated PEM files with StackHawk
5. **Share knowledge** - Help improve DPI detection techniques

## 🆘 Support

If you encounter issues:

1. Check the troubleshooting section above
2. Review Docker Desktop logs in macOS Console app
3. Verify macOS firewall isn't blocking connections (System Preferences → Security & Privacy → Firewall)
4. Ensure SIP (System Integrity Protection) allows certificate modifications
5. Test with multiple browsers to isolate application-specific issues

### Quick Commands Reference

```bash
# Build everything
make build

# Quick test (standalone)
./scripts/validate-dpi-setup.sh --test-type standalone

# View certificates in Keychain
open -a "Keychain Access"

# Check proxy settings
networksetup -getwebproxy "Wi-Fi"
networksetup -getsecurewebproxy "Wi-Fi"

# Reset everything  
./scripts/validate-dpi-setup.sh --cleanup
```

This setup provides a comprehensive DPI testing environment that's perfect for validating CypherHawk's detection capabilities in a safe, controlled environment on macOS.