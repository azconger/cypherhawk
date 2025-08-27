# Windows DPI Setup Validation Script for CypherHawk
# This script validates that your DPI testing environment is working correctly

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("standalone", "mitmproxy", "squid")]
    [string]$TestType = "standalone",
    
    [Parameter(Mandatory=$false)]
    [string]$CypherHawkPath = ".\cypherhawk.exe",
    
    [Parameter(Mandatory=$false)]
    [int]$Port = 8446,
    
    [Parameter(Mandatory=$false)]
    [switch]$Cleanup,
    
    [Parameter(Mandatory=$false)]
    [switch]$Help
)

if ($Help) {
    Write-Host @"
Windows DPI Setup Validation Script for CypherHawk

USAGE:
    .\validate-dpi-setup.ps1 [OPTIONS]

OPTIONS:
    -TestType       Type of DPI setup to validate (standalone, mitmproxy, squid)
    -CypherHawkPath Path to CypherHawk executable (default: .\cypherhawk.exe)
    -Port           Port for standalone server testing (default: 8446)
    -Cleanup        Remove test artifacts and restore system settings
    -Help           Show this help message

EXAMPLES:
    # Validate standalone DPI test server
    .\validate-dpi-setup.ps1 -TestType standalone

    # Validate mitmproxy setup
    .\validate-dpi-setup.ps1 -TestType mitmproxy

    # Validate squid proxy setup  
    .\validate-dpi-setup.ps1 -TestType squid

    # Cleanup all test artifacts
    .\validate-dpi-setup.ps1 -Cleanup

PREREQUISITES:
    - Run as Administrator for proxy and certificate operations
    - Docker Desktop running (for mitmproxy/squid tests)
    - CypherHawk built and available

"@
    return
}

# Check if running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Colors for output
$Green = "Green"
$Red = "Red" 
$Yellow = "Yellow"
$Cyan = "Cyan"

Write-Host "🧪 CypherHawk DPI Setup Validation" -ForegroundColor $Cyan
Write-Host "Testing: $TestType" -ForegroundColor $Yellow
Write-Host ""

# Check prerequisites
Write-Host "📋 Checking Prerequisites..." -ForegroundColor $Cyan

if (-not (Test-Administrator)) {
    Write-Host "❌ ERROR: This script must be run as Administrator for proxy/certificate operations" -ForegroundColor $Red
    Write-Host "   Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor $Yellow
    exit 1
}
Write-Host "✅ Running as Administrator" -ForegroundColor $Green

if (-not (Test-Path $CypherHawkPath)) {
    Write-Host "❌ ERROR: CypherHawk executable not found at: $CypherHawkPath" -ForegroundColor $Red
    Write-Host "   Build it with: go build -o cypherhawk.exe ./cmd/cypherhawk" -ForegroundColor $Yellow
    exit 1
}
Write-Host "✅ CypherHawk executable found" -ForegroundColor $Green

if ($Cleanup) {
    Write-Host ""
    Write-Host "🧹 Cleaning up DPI test environment..." -ForegroundColor $Cyan
    
    # Reset proxy settings
    try {
        & netsh winhttp reset proxy | Out-Null
        Write-Host "✅ Proxy settings reset" -ForegroundColor $Green
    } catch {
        Write-Host "⚠️  Could not reset proxy settings: $($_.Exception.Message)" -ForegroundColor $Yellow
    }
    
    # Stop Docker containers
    try {
        if (Get-Command docker -ErrorAction SilentlyContinue) {
            & docker stop cypherhawk-mitmproxy cypherhawk-squid-dpi 2>$null | Out-Null
            & docker rm cypherhawk-mitmproxy cypherhawk-squid-dpi 2>$null | Out-Null
            Write-Host "✅ Docker containers stopped" -ForegroundColor $Green
        }
    } catch {
        Write-Host "⚠️  Could not stop Docker containers: $($_.Exception.Message)" -ForegroundColor $Yellow
    }
    
    Write-Host ""
    Write-Host "🔐 IMPORTANT: Manually remove corporate CA certificates from Certificate Manager (certlm.msc)" -ForegroundColor $Yellow
    Write-Host "   1. Open certlm.msc as Administrator" -ForegroundColor $Yellow
    Write-Host "   2. Navigate to Trusted Root Certification Authorities > Certificates" -ForegroundColor $Yellow
    Write-Host "   3. Delete any corporate/test CA certificates you installed" -ForegroundColor $Yellow
    
    return
}

# Test functions
function Test-StandaloneDPI {
    Write-Host ""
    Write-Host "🚀 Testing Standalone DPI Server..." -ForegroundColor $Cyan
    
    # Check if DPI test server exists
    $dpiServerPath = ".\dpi-test-server.exe"
    if (-not (Test-Path $dpiServerPath)) {
        Write-Host "❌ DPI test server not found. Building..." -ForegroundColor $Yellow
        try {
            & go build -o dpi-test-server.exe ./cmd/dpi-test-server
            Write-Host "✅ Built DPI test server" -ForegroundColor $Green
        } catch {
            Write-Host "❌ Failed to build DPI test server: $($_.Exception.Message)" -ForegroundColor $Red
            return $false
        }
    }
    
    # Start DPI server in background
    Write-Host "🔧 Starting DPI test server on port $Port..."
    $job = Start-Job -ScriptBlock {
        param($serverPath, $port)
        & $serverPath -profile generic -port $port
    } -ArgumentList $dpiServerPath, $Port
    
    # Wait for server to start
    Start-Sleep -Seconds 3
    
    # Test with CypherHawk
    Write-Host "🔍 Testing CypherHawk detection..."
    try {
        $result = & $CypherHawkPath -url "https://localhost:$Port" 2>&1
        
        if ($LASTEXITCODE -eq 0 -and $result -match "CORPORATE DPI DETECTED|Unknown CA") {
            Write-Host "✅ CypherHawk successfully detected DPI certificates" -ForegroundColor $Green
            Write-Host "📊 Detection Result:" -ForegroundColor $Cyan
            $result | ForEach-Object { Write-Host "   $_" -ForegroundColor $Yellow }
            $success = $true
        } else {
            Write-Host "❌ CypherHawk did not detect DPI certificates" -ForegroundColor $Red
            Write-Host "Output: $result" -ForegroundColor $Yellow
            $success = $false
        }
    } catch {
        Write-Host "❌ Error running CypherHawk: $($_.Exception.Message)" -ForegroundColor $Red
        $success = $false
    }
    
    # Cleanup
    Stop-Job -Job $job -ErrorAction SilentlyContinue
    Remove-Job -Job $job -ErrorAction SilentlyContinue
    
    return $success
}

function Test-MitmproxyDPI {
    Write-Host ""
    Write-Host "🐳 Testing mitmproxy DPI Setup..." -ForegroundColor $Cyan
    
    # Check if Docker is available
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Host "❌ Docker not found. Install Docker Desktop first." -ForegroundColor $Red
        return $false
    }
    
    # Check if mitmproxy container is running
    $container = & docker ps --filter "name=cypherhawk-mitmproxy" --format "{{.Names}}" 2>$null
    if (-not $container) {
        Write-Host "❌ mitmproxy container not running. Start it with:" -ForegroundColor $Red
        Write-Host "   cd docker/mitmproxy && docker-compose up mitmproxy" -ForegroundColor $Yellow
        return $false
    }
    Write-Host "✅ mitmproxy container is running" -ForegroundColor $Green
    
    # Check proxy configuration
    $proxyConfig = & netsh winhttp show proxy 2>$null
    if ($proxyConfig -match "127\.0\.0\.1:8080") {
        Write-Host "✅ System proxy configured correctly" -ForegroundColor $Green
    } else {
        Write-Host "⚠️  System proxy not configured. Set with:" -ForegroundColor $Yellow
        Write-Host "   netsh winhttp set proxy proxy-server=`"127.0.0.1:8080`"" -ForegroundColor $Yellow
    }
    
    # Test DPI detection
    Write-Host "🔍 Testing DPI detection through mitmproxy..."
    try {
        $result = & $CypherHawkPath -url "https://httpbin.org/get" 2>&1
        
        if ($result -match "CORPORATE DPI DETECTED|Unknown CA") {
            Write-Host "✅ mitmproxy DPI detection successful" -ForegroundColor $Green
            return $true
        } else {
            Write-Host "❌ No DPI detected. Check CA certificate installation." -ForegroundColor $Red
            Write-Host "   1. Extract CA: docker cp cypherhawk-mitmproxy:/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem ./ca.pem" -ForegroundColor $Yellow
            Write-Host "   2. Install CA: Import-Certificate -FilePath ca.pem -CertStoreLocation Cert:\LocalMachine\Root" -ForegroundColor $Yellow
            return $false
        }
    } catch {
        Write-Host "❌ Error testing mitmproxy: $($_.Exception.Message)" -ForegroundColor $Red
        return $false
    }
}

function Test-SquidDPI {
    Write-Host ""
    Write-Host "🌐 Testing Squid DPI Setup..." -ForegroundColor $Cyan
    
    # Check if Docker is available
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Host "❌ Docker not found. Install Docker Desktop first." -ForegroundColor $Red
        return $false
    }
    
    # Check if Squid container is running
    $container = & docker ps --filter "name=cypherhawk-squid-dpi" --format "{{.Names}}" 2>$null
    if (-not $container) {
        Write-Host "❌ Squid container not running. Start it with:" -ForegroundColor $Red
        Write-Host "   cd docker/squid && docker-compose up squid-dpi" -ForegroundColor $Yellow
        return $false
    }
    Write-Host "✅ Squid container is running" -ForegroundColor $Green
    
    # Check proxy configuration
    $proxyConfig = & netsh winhttp show proxy 2>$null
    if ($proxyConfig -match "127\.0\.0\.1:3128") {
        Write-Host "✅ System proxy configured correctly" -ForegroundColor $Green
    } else {
        Write-Host "⚠️  System proxy not configured. Set with:" -ForegroundColor $Yellow
        Write-Host "   netsh winhttp set proxy proxy-server=`"127.0.0.1:3128`"" -ForegroundColor $Yellow
    }
    
    # Test Squid connectivity
    Write-Host "🔗 Testing Squid connectivity..."
    try {
        $testResult = & curl -s --proxy "127.0.0.1:3128" --max-time 10 "http://httpbin.org/ip" 2>$null
        if ($testResult) {
            Write-Host "✅ Squid proxy is accessible" -ForegroundColor $Green
        } else {
            Write-Host "❌ Cannot connect through Squid proxy" -ForegroundColor $Red
        }
    } catch {
        Write-Host "⚠️  curl not available, skipping connectivity test" -ForegroundColor $Yellow
    }
    
    # Test DPI detection
    Write-Host "🔍 Testing DPI detection through Squid..."
    try {
        $result = & $CypherHawkPath -url "https://httpbin.org/get" 2>&1
        
        if ($result -match "CORPORATE DPI DETECTED|Unknown CA") {
            Write-Host "✅ Squid DPI detection successful" -ForegroundColor $Green
            return $true
        } else {
            Write-Host "❌ No DPI detected. Check CA certificate installation." -ForegroundColor $Red  
            Write-Host "   1. Extract CA: docker cp cypherhawk-squid-dpi:/etc/squid/certs/corporate-ca-cert.pem ./squid-ca.pem" -ForegroundColor $Yellow
            Write-Host "   2. Install CA: Import-Certificate -FilePath squid-ca.pem -CertStoreLocation Cert:\LocalMachine\Root" -ForegroundColor $Yellow
            return $false
        }
    } catch {
        Write-Host "❌ Error testing Squid: $($_.Exception.Message)" -ForegroundColor $Red
        return $false
    }
}

# Run the appropriate test
$success = $false
switch ($TestType) {
    "standalone" { $success = Test-StandaloneDPI }
    "mitmproxy" { $success = Test-MitmproxyDPI }
    "squid" { $success = Test-SquidDPI }
    default {
        Write-Host "❌ Unknown test type: $TestType" -ForegroundColor $Red
        exit 1
    }
}

# Summary
Write-Host ""
Write-Host "📊 Validation Summary" -ForegroundColor $Cyan
Write-Host "===================" -ForegroundColor $Cyan

if ($success) {
    Write-Host "✅ SUCCESS: $TestType DPI setup is working correctly!" -ForegroundColor $Green
    Write-Host ""
    Write-Host "🎯 Next Steps:" -ForegroundColor $Cyan
    Write-Host "   • Test with different websites: .\cypherhawk.exe -url https://github.com" -ForegroundColor $Yellow
    Write-Host "   • Save certificates: .\cypherhawk.exe -o detected-dpi.pem" -ForegroundColor $Yellow
    Write-Host "   • Use verbose mode: .\cypherhawk.exe --verbose" -ForegroundColor $Yellow
    Write-Host "   • Try HawkScan integration with detected certificates" -ForegroundColor $Yellow
} else {
    Write-Host "❌ FAILURE: $TestType DPI setup has issues" -ForegroundColor $Red
    Write-Host ""
    Write-Host "🔧 Troubleshooting:" -ForegroundColor $Cyan
    Write-Host "   • Check the error messages above" -ForegroundColor $Yellow
    Write-Host "   • Verify all prerequisites are installed" -ForegroundColor $Yellow
    Write-Host "   • Review the setup documentation: WINDOWS-DPI-TESTING.md" -ForegroundColor $Yellow
    Write-Host "   • Run with -Cleanup to reset everything and start over" -ForegroundColor $Yellow
}

Write-Host ""
Write-Host "🔒 Security Reminder:" -ForegroundColor $Cyan
Write-Host "   Remember to run .\validate-dpi-setup.ps1 -Cleanup when finished testing!" -ForegroundColor $Yellow