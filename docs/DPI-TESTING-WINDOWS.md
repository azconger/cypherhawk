# Windows DPI Testing Guide for CypherHawk

> **Other Platforms:** [macOS Guide](DPI-TESTING-MACOS.md) | [Linux Guide](DPI-TESTING-LINUX.md) | [Overview](DPI-TESTING.md)

This guide shows you how to set up a realistic DPI testing environment on Windows to validate CypherHawk's detection capabilities. You'll simulate corporate DPI/proxy behavior without needing expensive enterprise solutions.

## 🎯 Overview

We provide **three approaches** from easiest to most realistic:

1. **🚀 Go Test Server** - Standalone HTTPS server (easiest, no Docker needed)
2. **🐳 mitmproxy** - Professional proxy with SSL interception (recommended)
3. **🌐 Squid Proxy** - Enterprise-grade proxy with SSL bumping (most realistic)

## Prerequisites

- Windows 10/11 with administrator access
- [Go 1.19+](https://golang.org/dl/) for building CypherHawk
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (for options 2 & 3)
- Git for cloning the repository

## 🚀 Option 1: Go Test Server (Easiest)

**Perfect for:** Quick validation, no additional software needed

### Setup Steps

1. **Build the DPI test server:**
   ```bash
   cd /path/to/cypherhawk
   go build -o dpi-test-server.exe ./cmd/dpi-test-server
   ```

2. **Start a DPI simulation:**
   ```bash
   # Generic corporate DPI
   .\dpi-test-server.exe -profile generic

   # Palo Alto Networks simulation  
   .\dpi-test-server.exe -profile palo-alto -port 8443

   # Malicious DPI for high-risk testing
   .\dpi-test-server.exe -profile malicious -output-certs ./test-certs
   ```

3. **Test with CypherHawk:**
   ```bash
   # Build CypherHawk
   go build -o cypherhawk.exe ./cmd/cypherhawk

   # Test against the DPI server
   .\cypherhawk.exe -url https://localhost:8446
   
   # Save detected certificates
   .\cypherhawk.exe -url https://localhost:8446 -o dpi-certs.pem
   ```

### Available Profiles

```bash
# List all available profiles
.\dpi-test-server.exe -list
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
   ```cmd
   # Copy certificate from container
   docker cp cypherhawk-mitmproxy:/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem ./corporate-ca.pem

   # Install to Windows certificate store (Run as Administrator)
   certlm.msc
   ```
   
   In Certificate Manager:
   - Navigate to "Trusted Root Certification Authorities" → "Certificates"
   - Right-click → "All Tasks" → "Import"
   - Select `corporate-ca.pem`

3. **Configure Windows proxy:**
   ```cmd
   # Set system proxy (Run as Administrator)
   netsh winhttp set proxy proxy-server="127.0.0.1:8080"
   
   # Verify proxy settings
   netsh winhttp show proxy
   ```

4. **Test DPI detection:**
   ```bash
   # Test against real websites (now proxied through mitmproxy)
   .\cypherhawk.exe -url https://www.google.com
   .\cypherhawk.exe -url https://github.com
   .\cypherhawk.exe --verbose
   
   # Save all detected corporate certificates
   .\cypherhawk.exe -o corporate-dpi-certs.pem
   ```

5. **Monitor traffic (optional):**
   - Open browser to http://127.0.0.1:8081 for mitmproxy web interface
   - View real-time HTTPS interception and certificate substitution

### Cleanup
```cmd
# Remove proxy configuration
netsh winhttp reset proxy

# Remove CA certificate using certlm.msc
# Navigate to "Trusted Root Certification Authorities" and delete the corporate CA
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
   ```cmd
   # Copy certificate from container
   docker cp cypherhawk-squid-dpi:/etc/squid/certs/corporate-ca-cert.pem ./squid-ca.pem

   # Install via PowerShell (Run as Administrator)
   Import-Certificate -FilePath "squid-ca.pem" -CertStoreLocation "Cert:\LocalMachine\Root"
   ```

3. **Configure Windows proxy:**
   ```cmd
   # Set system proxy for both HTTP and HTTPS (Run as Administrator)
   netsh winhttp set proxy proxy-server="http=127.0.0.1:3128;https=127.0.0.1:3128"
   
   # Alternative: Configure in browser settings
   # Chrome: Settings > Advanced > System > Open proxy settings
   ```

4. **Test enterprise DPI detection:**
   ```bash
   # Test against various websites
   .\cypherhawk.exe -url https://www.google.com
   .\cypherhawk.exe -url https://stackoverflow.com  
   .\cypherhawk.exe -url https://api.github.com
   
   # Verbose analysis
   .\cypherhawk.exe --verbose -o enterprise-dpi.pem
   ```

5. **Monitor Squid logs:**
   ```bash
   # View SSL bumping in action
   docker-compose logs -f squid-dpi
   
   # Check access logs
   docker exec cypherhawk-squid-dpi tail -f /var/log/squid/access.log
   ```

## 🧪 Testing & Validation

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

### Troubleshooting

#### Certificate Trust Issues
```cmd
# Verify CA is installed correctly
certlm.msc
# Check "Trusted Root Certification Authorities" contains your corporate CA

# Test certificate trust
certutil -verify -urlfetch corporate-ca.pem
```

#### Proxy Connection Issues  
```cmd
# Test proxy connectivity
curl -v --proxy 127.0.0.1:8080 https://www.google.com

# Check Docker containers
docker ps
docker-compose logs
```

#### CypherHawk Not Detecting
```bash
# Use verbose mode for detailed analysis
.\cypherhawk.exe --verbose

# Test specific endpoints
.\cypherhawk.exe -url https://www.google.com

# Verify certificates are being intercepted
openssl s_client -connect www.google.com:443 -proxy 127.0.0.1:8080
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

```powershell
# Stop Docker containers
docker-compose down --remove-orphans
docker system prune -f

# Kill any running DPI test servers
taskkill /f /im dpi-test-server.exe 2>$null
```

#### Step 2: Remove Proxy Configuration

```powershell
# Reset system proxy (run as Administrator)
netsh winhttp reset proxy
netsh winhttp reset tracing

# Reset Internet Explorer proxy settings
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /f 2>$null
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /f 2>$null
```

#### Step 3: Remove Test CA Certificates (SAFE CLI METHOD)

**Option A: PowerShell Certificate Removal (Recommended)**

```powershell
# Open PowerShell as Administrator and run:

# List test certificates to identify them
Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {
    $_.Subject -like "*Test*" -or 
    $_.Subject -like "*Corporate*" -or 
    $_.Subject -like "*Acme*" -or
    $_.Subject -like "*DPI*" -or
    $_.Issuer -eq $_.Subject  # Self-signed certificates
} | Format-Table Subject, Thumbprint, NotAfter

# Remove specific test certificates by thumbprint (SAFE - only removes what you specify)
# Replace THUMBPRINT with the actual thumbprint from the list above
$thumbprint = "REPLACE_WITH_ACTUAL_THUMBPRINT"
if ($thumbprint -ne "REPLACE_WITH_ACTUAL_THUMBPRINT") {
    Get-ChildItem -Path Cert:\LocalMachine\Root\$thumbprint | Remove-Item -Confirm
}

# Alternative: Remove by subject pattern (use with CAUTION)
Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {
    $_.Subject -like "*Acme Corporate Security*" -or
    $_.Subject -like "*Test-CA-localhost*" -or
    $_.Subject -like "*Palo Alto Networks Enterprise Root CA*"
} | Remove-Item -Confirm
```

**Option B: Certificate Manager GUI (Visual Verification)**

```powershell
# Open Certificate Manager
certlm.msc

# Navigate to: Trusted Root Certification Authorities > Certificates
# Look for certificates with these characteristics:
#   - Issued To: "Acme Corporate Security CA", "Test-CA-localhost", etc.
#   - Issued By: Same as "Issued To" (self-signed)
#   - Valid from: Recent date (today)
# Right-click suspicious certificates and select "Delete"
```

#### Step 4: Remove User Certificate Store (Additional Safety)

```powershell
# Check and remove from Current User store as well
Get-ChildItem -Path Cert:\CurrentUser\Root | Where-Object {
    $_.Subject -like "*Test*" -or 
    $_.Subject -like "*Corporate*" -or 
    $_.Subject -like "*Acme*" -or
    $_.Subject -like "*DPI*"
} | Remove-Item -Confirm

# Also check Intermediate Certification Authorities
Get-ChildItem -Path Cert:\LocalMachine\CA | Where-Object {
    $_.Subject -like "*Test*" -or $_.Subject -like "*Corporate*"
} | Remove-Item -Confirm
```

#### Step 5: Clear Browser Certificate Caches

```powershell
# Chrome/Edge - Clear certificate cache
Get-Process chrome,msedge -ErrorAction SilentlyContinue | Stop-Process -Force

# Firefox - Clear certificate cache  
Get-Process firefox -ErrorAction SilentlyContinue | Stop-Process -Force

# Clear Windows certificate cache
certlm.msc
# In Certificate Manager, go to Action > All Tasks > Clear SSL State
```

#### Step 6: Verification

```powershell
# Verify all test certificates are removed
$testCerts = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {
    $_.Subject -like "*Test*" -or 
    $_.Subject -like "*Corporate*" -or 
    $_.Subject -like "*Acme*" -or
    $_.Subject -like "*DPI*"
}

if ($testCerts.Count -eq 0) {
    Write-Host "✅ All test certificates successfully removed" -ForegroundColor Green
} else {
    Write-Host "⚠️ WARNING: Test certificates still present:" -ForegroundColor Yellow
    $testCerts | Format-Table Subject, Thumbprint
}

# Test normal HTTPS connection
Test-NetConnection google.com -Port 443 -InformationLevel Detailed
```

#### 🚨 Emergency Certificate Cleanup

If you accidentally installed malicious certificates or need to reset everything:

```powershell
# NUCLEAR OPTION: Reset all certificates (run as Administrator)
# WARNING: This removes ALL non-Windows certificates, including legitimate ones
# Only use if you understand the consequences

# Backup current certificates first
Export-Certificate -Cert (Get-ChildItem -Path Cert:\LocalMachine\Root) -FilePath C:\temp\cert_backup.zip

# Clear certificate stores (DANGEROUS - use only in emergencies)
# Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object { $_.Subject -notlike "*Microsoft*" -and $_.Subject -notlike "*Windows*" } | Remove-Item -Force

# After this, you may need to reinstall legitimate CA certificates
```

## 🎓 Educational Value

This setup teaches you:

1. **How corporate DPI works** - Certificate substitution, SSL bumping
2. **Certificate chain analysis** - Understanding trust relationships  
3. **Security implications** - Why unknown CAs are dangerous
4. **Detection techniques** - How CypherHawk identifies DPI
5. **Enterprise networking** - Proxy configuration and management

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
2. Review Docker/container logs
3. Verify Windows firewall isn't blocking connections
4. Ensure administrator privileges for certificate operations
5. Test with multiple browsers to isolate issues

This setup provides a comprehensive DPI testing environment that's perfect for validating CypherHawk's detection capabilities in a safe, controlled environment on Windows.