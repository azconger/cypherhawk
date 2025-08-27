#!/bin/bash
# Linux/macOS DPI Setup Validation Script for CypherHawk
# This script validates that your DPI testing environment is working correctly

set -e

# Default values
TEST_TYPE="standalone"
CYPHERHAWK_PATH="./cypherhawk"
PORT=8446
CLEANUP=false
HELP=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'  
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

show_help() {
    cat << 'EOF'
Linux/macOS DPI Setup Validation Script for CypherHawk

USAGE:
    ./validate-dpi-setup.sh [OPTIONS]

OPTIONS:
    --test-type TYPE     Type of DPI setup to validate (standalone, mitmproxy, squid)
    --cypherhawk PATH    Path to CypherHawk executable (default: ./cypherhawk)
    --port NUMBER        Port for standalone server testing (default: 8446)
    --cleanup           Remove test artifacts and restore system settings
    --help              Show this help message

EXAMPLES:
    # Validate standalone DPI test server
    ./validate-dpi-setup.sh --test-type standalone

    # Validate mitmproxy setup
    ./validate-dpi-setup.sh --test-type mitmproxy

    # Validate squid proxy setup  
    ./validate-dpi-setup.sh --test-type squid

    # Cleanup all test artifacts
    ./validate-dpi-setup.sh --cleanup

PREREQUISITES:
    - CypherHawk built and available
    - Docker running (for mitmproxy/squid tests)
    - sudo access (for proxy operations)

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --test-type)
            TEST_TYPE="$2"
            shift 2
            ;;
        --cypherhawk)
            CYPHERHAWK_PATH="$2"
            shift 2
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --cleanup)
            CLEANUP=true
            shift
            ;;
        --help)
            HELP=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

if [ "$HELP" = true ]; then
    show_help
    exit 0
fi

echo -e "${CYAN}🧪 CypherHawk DPI Setup Validation${NC}"
echo -e "${YELLOW}Testing: $TEST_TYPE${NC}"
echo ""

# Check prerequisites
echo -e "${CYAN}📋 Checking Prerequisites...${NC}"

if [ ! -f "$CYPHERHAWK_PATH" ]; then
    echo -e "${RED}❌ ERROR: CypherHawk executable not found at: $CYPHERHAWK_PATH${NC}"
    echo -e "${YELLOW}   Build it with: go build -o cypherhawk ./cmd/cypherhawk${NC}"
    exit 1
fi
echo -e "${GREEN}✅ CypherHawk executable found${NC}"

if [ "$CLEANUP" = true ]; then
    echo ""
    echo -e "${CYAN}🧹 Cleaning up DPI test environment...${NC}"
    
    # Reset proxy settings (if applicable)
    if command -v networksetup &> /dev/null; then
        # macOS
        sudo networksetup -setwebproxystate "Wi-Fi" off 2>/dev/null || true
        sudo networksetup -setsecurewebproxystate "Wi-Fi" off 2>/dev/null || true
        echo -e "${GREEN}✅ macOS proxy settings reset${NC}"
    fi
    
    # Stop Docker containers
    if command -v docker &> /dev/null; then
        docker stop cypherhawk-mitmproxy cypherhawk-squid-dpi 2>/dev/null || true
        docker rm cypherhawk-mitmproxy cypherhawk-squid-dpi 2>/dev/null || true
        echo -e "${GREEN}✅ Docker containers stopped${NC}"
    fi
    
    echo ""
    echo -e "${YELLOW}🔐 IMPORTANT: Manually remove corporate CA certificates from system trust store${NC}"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo -e "${YELLOW}   macOS: Open Keychain Access > System > Certificates, delete corporate CAs${NC}"
    else
        echo -e "${YELLOW}   Linux: Check /etc/ssl/certs/ and /usr/local/share/ca-certificates/${NC}"
    fi
    
    exit 0
fi

# Test functions
test_standalone_dpi() {
    echo ""
    echo -e "${CYAN}🚀 Testing Standalone DPI Server...${NC}"
    
    # Check if DPI test server exists
    DPI_SERVER_PATH="./dpi-test-server"
    if [ ! -f "$DPI_SERVER_PATH" ]; then
        echo -e "${YELLOW}❌ DPI test server not found. Building...${NC}"
        if go build -o dpi-test-server ./cmd/dpi-test-server; then
            echo -e "${GREEN}✅ Built DPI test server${NC}"
        else
            echo -e "${RED}❌ Failed to build DPI test server${NC}"
            return 1
        fi
    fi
    
    # Start DPI server in background
    echo "🔧 Starting DPI test server on port $PORT..."
    $DPI_SERVER_PATH -profile generic -port $PORT &
    DPI_PID=$!
    
    # Wait for server to start
    sleep 3
    
    # Test with CypherHawk
    echo "🔍 Testing CypherHawk detection..."
    if result=$($CYPHERHAWK_PATH -url "https://localhost:$PORT" 2>&1); then
        if echo "$result" | grep -q "CORPORATE DPI DETECTED\|Unknown CA"; then
            echo -e "${GREEN}✅ CypherHawk successfully detected DPI certificates${NC}"
            echo -e "${CYAN}📊 Detection Result:${NC}"
            echo "$result" | sed 's/^/   /'
            success=true
        else
            echo -e "${RED}❌ CypherHawk did not detect DPI certificates${NC}"
            echo -e "${YELLOW}Output: $result${NC}"
            success=false
        fi
    else
        echo -e "${RED}❌ Error running CypherHawk${NC}"
        success=false
    fi
    
    # Cleanup
    kill $DPI_PID 2>/dev/null || true
    
    return $([[ "$success" == "true" ]] && echo 0 || echo 1)
}

test_mitmproxy_dpi() {
    echo ""
    echo -e "${CYAN}🐳 Testing mitmproxy DPI Setup...${NC}"
    
    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}❌ Docker not found. Install Docker first.${NC}"
        return 1
    fi
    
    # Check if mitmproxy container is running
    if ! docker ps --filter "name=cypherhawk-mitmproxy" --format "{{.Names}}" | grep -q "cypherhawk-mitmproxy"; then
        echo -e "${RED}❌ mitmproxy container not running. Start it with:${NC}"
        echo -e "${YELLOW}   cd docker/mitmproxy && docker-compose up mitmproxy${NC}"
        return 1
    fi
    echo -e "${GREEN}✅ mitmproxy container is running${NC}"
    
    # Check proxy configuration (basic test)
    echo -e "${YELLOW}⚠️  Proxy configuration varies by system. Please verify manually:${NC}"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo -e "${YELLOW}   macOS: System Preferences > Network > Advanced > Proxies${NC}"
    else
        echo -e "${YELLOW}   Linux: Check your network manager or environment variables${NC}"
    fi
    
    # Test DPI detection
    echo "🔍 Testing DPI detection through mitmproxy..."
    if result=$($CYPHERHAWK_PATH -url "https://httpbin.org/get" 2>&1); then
        if echo "$result" | grep -q "CORPORATE DPI DETECTED\|Unknown CA"; then
            echo -e "${GREEN}✅ mitmproxy DPI detection successful${NC}"
            return 0
        else
            echo -e "${RED}❌ No DPI detected. Check CA certificate installation.${NC}"
            echo -e "${YELLOW}   1. Extract CA: docker cp cypherhawk-mitmproxy:/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem ./ca.pem${NC}"
            echo -e "${YELLOW}   2. Install CA to system trust store${NC}"
            return 1
        fi
    else
        echo -e "${RED}❌ Error testing mitmproxy${NC}"
        return 1
    fi
}

test_squid_dpi() {
    echo ""
    echo -e "${CYAN}🌐 Testing Squid DPI Setup...${NC}"
    
    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}❌ Docker not found. Install Docker first.${NC}"
        return 1
    fi
    
    # Check if Squid container is running
    if ! docker ps --filter "name=cypherhawk-squid-dpi" --format "{{.Names}}" | grep -q "cypherhawk-squid-dpi"; then
        echo -e "${RED}❌ Squid container not running. Start it with:${NC}"
        echo -e "${YELLOW}   cd docker/squid && docker-compose up squid-dpi${NC}"
        return 1
    fi
    echo -e "${GREEN}✅ Squid container is running${NC}"
    
    # Test Squid connectivity
    echo "🔗 Testing Squid connectivity..."
    if curl -s --proxy "127.0.0.1:3128" --max-time 10 "http://httpbin.org/ip" > /dev/null; then
        echo -e "${GREEN}✅ Squid proxy is accessible${NC}"
    else
        echo -e "${RED}❌ Cannot connect through Squid proxy${NC}"
    fi
    
    # Test DPI detection
    echo "🔍 Testing DPI detection through Squid..."
    if result=$($CYPHERHAWK_PATH -url "https://httpbin.org/get" 2>&1); then
        if echo "$result" | grep -q "CORPORATE DPI DETECTED\|Unknown CA"; then
            echo -e "${GREEN}✅ Squid DPI detection successful${NC}"
            return 0
        else
            echo -e "${RED}❌ No DPI detected. Check CA certificate installation.${NC}"
            echo -e "${YELLOW}   1. Extract CA: docker cp cypherhawk-squid-dpi:/etc/squid/certs/corporate-ca-cert.pem ./squid-ca.pem${NC}"
            echo -e "${YELLOW}   2. Install CA to system trust store${NC}"
            return 1
        fi
    else
        echo -e "${RED}❌ Error testing Squid${NC}"
        return 1
    fi
}

# Run the appropriate test
success=false
case $TEST_TYPE in
    "standalone")
        if test_standalone_dpi; then
            success=true
        fi
        ;;
    "mitmproxy")
        if test_mitmproxy_dpi; then
            success=true
        fi
        ;;
    "squid")
        if test_squid_dpi; then
            success=true
        fi
        ;;
    *)
        echo -e "${RED}❌ Unknown test type: $TEST_TYPE${NC}"
        exit 1
        ;;
esac

# Summary
echo ""
echo -e "${CYAN}📊 Validation Summary${NC}"
echo -e "${CYAN}===================${NC}"

if [ "$success" = true ]; then
    echo -e "${GREEN}✅ SUCCESS: $TEST_TYPE DPI setup is working correctly!${NC}"
    echo ""
    echo -e "${CYAN}🎯 Next Steps:${NC}"
    echo -e "${YELLOW}   • Test with different websites: $CYPHERHAWK_PATH -url https://github.com${NC}"
    echo -e "${YELLOW}   • Save certificates: $CYPHERHAWK_PATH -o detected-dpi.pem${NC}"
    echo -e "${YELLOW}   • Use verbose mode: $CYPHERHAWK_PATH --verbose${NC}"
    echo -e "${YELLOW}   • Try HawkScan integration with detected certificates${NC}"
else
    echo -e "${RED}❌ FAILURE: $TEST_TYPE DPI setup has issues${NC}"
    echo ""
    echo -e "${CYAN}🔧 Troubleshooting:${NC}"
    echo -e "${YELLOW}   • Check the error messages above${NC}"
    echo -e "${YELLOW}   • Verify all prerequisites are installed${NC}"
    echo -e "${YELLOW}   • Review the setup documentation: WINDOWS-DPI-TESTING.md${NC}"
    echo -e "${YELLOW}   • Run with --cleanup to reset everything and start over${NC}"
fi

echo ""
echo -e "${CYAN}🔒 Security Reminder:${NC}"
echo -e "${YELLOW}   Remember to run ./validate-dpi-setup.sh --cleanup when finished testing!${NC}"