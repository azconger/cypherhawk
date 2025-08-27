# CypherHawk DPI Testing Scripts

This directory contains validation and testing scripts for the CypherHawk DPI testing environment.

## Files

### Validation Scripts

- **`validate-dpi-setup.ps1`** - Windows PowerShell validation script
- **`validate-dpi-setup.sh`** - Linux/macOS bash validation script

### Usage

**Windows (PowerShell as Administrator):**
```powershell
# Test standalone DPI server
.\validate-dpi-setup.ps1 -TestType standalone

# Test mitmproxy setup  
.\validate-dpi-setup.ps1 -TestType mitmproxy

# Test Squid proxy setup
.\validate-dpi-setup.ps1 -TestType squid

# Cleanup everything
.\validate-dpi-setup.ps1 -Cleanup
```

**Linux/macOS:**
```bash
# Test standalone DPI server
./validate-dpi-setup.sh --test-type standalone

# Test mitmproxy setup
./validate-dpi-setup.sh --test-type mitmproxy

# Test Squid proxy setup  
./validate-dpi-setup.sh --test-type squid

# Cleanup everything
./validate-dpi-setup.sh --cleanup
```

## What These Scripts Do

1. **Prerequisites Check** - Verify CypherHawk is built and Docker is running (if needed)
2. **Environment Validation** - Check that DPI servers/proxies are running correctly
3. **Certificate Testing** - Validate that corporate CAs are being used
4. **Detection Testing** - Run CypherHawk to ensure DPI detection works
5. **Result Analysis** - Verify CypherHawk detects the corporate certificates
6. **Cleanup Support** - Reset proxy settings and stop containers

## Expected Results

### Successful DPI Detection
```
✅ SUCCESS: standalone DPI setup is working correctly!

🎯 Next Steps:
   • Test with different websites: .\cypherhawk.exe -url https://github.com
   • Save certificates: .\cypherhawk.exe -o detected-dpi.pem
   • Use verbose mode: .\cypherhawk.exe --verbose
   • Try HawkScan integration with detected certificates
```

### Failed DPI Detection
```
❌ FAILURE: mitmproxy DPI setup has issues

🔧 Troubleshooting:
   • Check the error messages above
   • Verify all prerequisites are installed
   • Review the setup documentation: WINDOWS-DPI-TESTING.md
   • Run with --cleanup to reset everything and start over
```

## Prerequisites

- **Windows**: PowerShell 5.1+ with Administrator privileges
- **Linux/macOS**: Bash 4.0+ with sudo access
- **All platforms**: 
  - CypherHawk built (`go build -o cypherhawk ./cmd/cypherhawk`)
  - Docker Desktop (for mitmproxy/squid tests)
  - Git (for cloning the repository)

## Security Notes

⚠️ **Always run the cleanup command after testing:**
- `.\validate-dpi-setup.ps1 -Cleanup` (Windows)
- `./validate-dpi-setup.sh --cleanup` (Linux/macOS)

This removes:
- System proxy configurations
- Docker containers
- Test artifacts

**Manual cleanup required:**
- Corporate CA certificates from system trust store
- Browser cache and settings

## Troubleshooting

### Common Issues

1. **"Must be run as Administrator"** - Right-click PowerShell and "Run as Administrator"
2. **"CypherHawk executable not found"** - Build it first: `go build -o cypherhawk.exe ./cmd/cypherhawk`
3. **"Docker container not running"** - Start with: `cd docker/mitmproxy && docker-compose up mitmproxy`
4. **"No DPI detected"** - Check CA certificate installation and proxy configuration

### Getting Help

```bash
# Show help for validation scripts
.\validate-dpi-setup.ps1 -Help          # Windows
./validate-dpi-setup.sh --help          # Linux/macOS

# Show help for DPI test server
.\dpi-test-server.exe -help              # Windows
./dpi-test-server -help                  # Linux/macOS

# Show help for CypherHawk
.\cypherhawk.exe --help                  # Windows  
./cypherhawk --help                      # Linux/macOS
```

These scripts make it easy to validate that your DPI testing environment is working correctly and that CypherHawk can detect corporate certificate interception.