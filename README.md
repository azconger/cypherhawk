# CypherHawk


A production-ready command-line tool that detects corporate Deep Packet Inspection (DPI) firewalls and man-in-the-middle (MitM) proxies, extracts their CA certificates, and provides comprehensive security analysis with advanced threat detection capabilities.

**Enhanced with enterprise-grade architecture:** HashiCorp go-retryablehttp networking, Cobra CLI framework, structured logging, and configuration management. Features vendor identification for 15+ enterprise security platforms, behavioral analysis, Certificate Transparency validation, and HawkScan-optimized PEM output.

Built by StackHawk but designed for the broader Java ecosystem including Maven, Gradle, Spring Boot applications, and security tools like HawkScan.

## Features

- **🔍 Corporate DPI Detection**: Automatically detects enterprise security infrastructure with 15+ vendor patterns
- **🚨 Advanced Threat Detection**: Identifies malicious MitM attacks vs. legitimate corporate proxies using risk scoring
- **📋 Certificate Chain Analysis**: Detailed analysis of TLS certificate chains with anomaly detection
- **🛡️ Security Validation**: Certificate Transparency validation, behavioral analysis, and CA impersonation detection
- **📦 HawkScan Integration**: Optimized PEM output with comprehensive usage examples and custom help system
- **⚡ Fast & Reliable**: Enhanced networking with HashiCorp go-retryablehttp, exponential backoff, circuit breakers
- **🔧 Professional CLI**: Cobra framework with subcommands, environment variables, structured logging
- **🔒 Enterprise-Ready**: Supports 15+ major DPI vendors with confidence scoring and vendor identification
- **🌐 Cross-Platform**: Comprehensive testing on Windows, macOS, Linux with proxy environment support
- **📦 Modular Architecture**: High-quality dependencies with 50% code reduction and enhanced reliability

## Quick Start

### Installation

Download the latest binary from [releases](https://github.com/kaakaww/cypherhawk/releases) or build from source:

```bash
git clone https://github.com/kaakaww/cypherhawk.git
cd cypherhawk
make build  # Downloads latest CA bundle and builds binary
```

### Basic Usage

```bash
# Test default endpoints (Google, StackHawk, AWS)
./cypherhawk

# Test a specific website
./cypherhawk --url https://example.com

# Alternative subcommand syntax
./cypherhawk detect https://example.com

# Show version information
./cypherhawk version

# Show comprehensive help with HawkScan integration examples
./cypherhawk --help

# Enable detailed security analysis with structured logging
./cypherhawk --verbose --analyze --log-level debug

# Save certificates to file
./cypherhawk --output corporate-certs.pem --url https://internal.company.com

# Environment variable configuration
export CYPHERHAWK_OUTPUT=certs.pem
export CYPHERHAWK_LOG_LEVEL=debug
./cypherhawk
```

## Usage Examples

### Corporate Environment Detection

```bash
# Basic DPI detection
$ ./cypherhawk
✓ No corporate DPI detected (tested 4 endpoints)

# When DPI is detected
$ ./cypherhawk -url https://internal.corp.com
⚠ Corporate DPI detected: found 1 unknown CA certificate

# CypherHawk - Corporate DPI/MitM CA Certificates
# Generated for HawkScan integration
#
# Usage with HawkScan:
#   hawk scan --ca-bundle this-file.pem
#
# [DPI] Palo Alto Networks DPI detected (confidence: 85%)
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKoK/mNGOWj3MA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV...
-----END CERTIFICATE-----
```

### Certificate Chain Analysis

```bash
$ ./cypherhawk --analyze -url example.com

Certificate Chain Analysis for https://example.com
============================================================

Chain Summary:
  Total certificates: 2
  Chain structure: 1 leaf + 1 intermediate + 0 root
  Trust status: ✓ Trusted chain
  Security issues: ✓ No major issues detected

Certificate Chain:
  [1] ✓ Leaf Certificate - *.example.com
      Issued by: DigiCert Global G3 TLS ECC SHA384 2020 CA1
      Valid: 2025-01-15 to 2026-01-15 (366.0 days)
      Key: 256-bit ECDSA-SHA384, Serial: 14416812...40436634

  [2] ✓ Intermediate Certificate - DigiCert Global G3 TLS ECC SHA384 2020 CA1
      Issued by: DigiCert Global Root G3
      Valid: 2021-04-14 to 2031-04-13 (3652.0 days)
      Key: 384-bit ECDSA-SHA384, Serial: 14626237...42652550
```

### Corporate DPI Detection with Analysis

```bash
$ ./cypherhawk --analyze -url corporate.internal

Certificate Chain Analysis for https://corporate.internal
============================================================

Chain Summary:
  Total certificates: 2
  Chain structure: 1 leaf + 0 intermediate + 1 root
  Trust status: ⚠ Untrusted chain
  Security issues: ⚠ 1 certificates with issues

Certificate Chain:
  [1] ✓ Leaf Certificate - corporate.internal
      Issued by: Acme Corporate Security Gateway
      Valid: 2025-05-18 to 2025-11-14 (180.0 days)
      Key: 2048-bit SHA256-RSA, Serial: 2

  [2] ⚠ Root Certificate - Acme Corporate Security Gateway
      Issued by: Self-signed
      Valid: 2025-05-18 to 2030-08-15 (1915.0 days)
      Key: 2048-bit SHA256-RSA, Serial: 81985529...16486895

Corporate DPI Indicators:
  🔍 Corporate DPI term: 'corporate' found
  🔍 Corporate DPI term: 'security' found
  🔍 Corporate DPI term: 'gateway' found
  🔍 Unknown self-signed CA (likely corporate DPI)

Chain Anomalies:
  ⚠ Potentially missing intermediate certificates
```

## Command Line Options

```
Usage: ./cypherhawk [command] [options]

Commands:
  detect          Detect corporate DPI and extract certificates (default)
  version         Show version information
  help            Show comprehensive help with HawkScan integration examples

Options:
  -a, --analyze         Show comprehensive certificate chain analysis
  -h, --help            Show help for command
  -o, --output string   Output file for CA certificates (use '-' for stdout)
  -q, --quiet           Suppress all non-error output
  -u, --url string      Custom target URL to test (assumes https:// if no protocol specified)
  -v, --verbose         Show detailed progress and security analysis
      --silent          Suppress ALL output (even errors)
      --log-level string Log level: debug, info, warn, error (default "info")

Environment Variables:
  HTTP_PROXY                    HTTP proxy URL for corporate networks
  HTTPS_PROXY                   HTTPS proxy URL for corporate networks
  CYPHERHAWK_OUTPUT             Output file for CA certificates
  CYPHERHAWK_URL                Custom target URL to test
  CYPHERHAWK_VERBOSE            Enable verbose mode (true/false)
  CYPHERHAWK_ANALYZE            Enable analysis mode (true/false)
  CYPHERHAWK_LOG_LEVEL          Set log level (debug, info, warn, error)
  CYPHERHAWK_SKIP_NETWORK_TESTS Set to "1" to skip network tests (testing mode)
```

## Integration with Java Applications

### StackHawk Scanner (HawkScan)
```bash
# Extract corporate DPI certificates
./cypherhawk --output corporate-certs.pem

# Use with HawkScan
hawk scan --ca-bundle corporate-certs.pem

# For specific target testing
./cypherhawk --url https://internal.corp.com --output corp-internal.pem
hawk scan --ca-bundle corp-internal.pem

# Using environment variables
export CYPHERHAWK_OUTPUT=corporate-certs.pem
export CYPHERHAWK_URL=https://internal.corp.com
./cypherhawk
hawk scan --ca-bundle corporate-certs.pem
```

### Java Applications (PEM format - Java 9+)
```bash
java -Djavax.net.ssl.trustStoreType=PEM \
     -Djavax.net.ssl.trustStore=corporate-certs.pem \
     MyApplication
```

### Java Applications (JKS format - all Java versions)
```bash
# Convert PEM to JKS
keytool -importcert -noprompt \
        -file corporate-certs.pem \
        -keystore corporate.jks \
        -storepass changeit \
        -alias corporate-ca

# Use with Java application
java -Djavax.net.ssl.trustStore=corporate.jks \
     -Djavax.net.ssl.trustStorePassword=changeit \
     MyApplication
```

### Maven
```bash
# PEM format
mvn clean install \
    -Djavax.net.ssl.trustStoreType=PEM \
    -Djavax.net.ssl.trustStore=corporate-certs.pem

# JKS format
mvn clean install \
    -Djavax.net.ssl.trustStore=corporate.jks \
    -Djavax.net.ssl.trustStorePassword=changeit
```

### Gradle
```bash
./gradlew build \
    -Djavax.net.ssl.trustStoreType=PEM \
    -Djavax.net.ssl.trustStore=corporate-certs.pem
```

## How It Works

CypherHawk works by:

1. **Fresh CA bundle at build time** - Downloads latest Mozilla CA certificates during build to prevent stale embedded fallback bundles
2. **Runtime CA bundle download** - Downloads Mozilla's trusted CA bundle from multiple sources with cross-validation and integrity checking
3. **Enhanced TLS connections** - Uses HashiCorp go-retryablehttp with exponential backoff, circuit breakers, and corporate proxy support
4. **Analyzing certificate chains** using browser-like validation logic with structured logging and enhanced behavioral analysis
5. **Detecting unknown CAs** that aren't in Mozilla's trusted bundle using advanced threat detection
6. **Performing security analysis** with Certificate Transparency validation, 10+ behavioral indicators, and CA impersonation detection
7. **Vendor identification** using 15+ enterprise DPI vendor patterns with confidence scoring
8. **Extracting CA certificates** in HawkScan-optimized PEM format with comprehensive usage instructions

### Default Test Endpoints

- `https://www.google.com` - Primary connectivity test
- `https://auth.stackhawk.com` - StackHawk authentication service
- `https://api.stackhawk.com` - StackHawk API service  
- `https://s3.us-west-2.amazonaws.com` - AWS S3 for pre-signed URLs

## Security Features

### Advanced Threat Detection

- **Certificate Transparency Validation**: Checks for SCT extensions in recent certificates
- **Behavioral Analysis**: Detects 10+ suspicious certificate indicators including:
  - Weak cryptographic keys (RSA < 2048 bits, ECDSA < 256 bits)
  - Suspicious serial numbers and recent issuance patterns
  - Weak signature algorithms (MD5, SHA1)
  - Suspicious subject/issuer terms
- **CA Impersonation Detection**: Identifies certificates falsely claiming to be from legitimate CAs
- **Risk Scoring**: Combines multiple indicators for high-confidence detection

### Enterprise DPI Vendor Detection

CypherHawk recognizes certificates from 15+ major enterprise security vendors with confidence scoring:

- **Palo Alto Networks** - Next-Generation Firewalls and Prisma Access
- **Zscaler** - Cloud Security Platform and Private Access
- **Netskope** - Cloud Access Security Broker (CASB)
- **Forcepoint** - Web Security and Data Protection
- **Cisco/BlueCoat** - Web Security Appliance and Cloud Web Security
- **McAfee/Trellix** - Web Gateway and Network Security Platform
- **Symantec/Broadcom** - ProxySG and Web Security Service
- **Check Point** - Threat Prevention and Mobile Access
- **Fortinet** - FortiGate and FortiProxy
- **Sophos** - XG Firewall and Cloud Optix
- **iBoss** - Cloud Security Platform
- **Menlo Security** - Isolation Platform
- **Wandera/Jamf** - Mobile Threat Defense
- **CrowdStrike** - Falcon Go and Cloud Workload Protection
- **CloudFlare for Teams** - Zero Trust Network Access

## Exit Codes

- `0` - Success (no DPI detected or analysis completed)
- `1` - Partial failure (some endpoints failed but operation completed)
- `2` - Complete failure (unable to complete operation)

## Supported Platforms

- Linux (amd64, arm64)
- macOS (amd64, arm64) 
- Windows (amd64, arm64)

## Building from Source

```bash
# Clone the repository
git clone https://github.com/kaakaww/cypherhawk.git
cd cypherhawk

# Quick build (downloads fresh CA bundle + includes code quality checks)
make build

# Clean build (removes embedded CA bundle for completely fresh download)
make clean && make build

# Update CA bundle manually
make update-ca-bundle

# Full development workflow
make pre-commit  # Run all checks + tests before committing

# Run tests
make test

# Cross-platform builds (downloads fresh CA bundle)
make build-all

# Code quality checks
make check      # Format check + vet + lint
make fmt        # Fix formatting issues
```

**Important:** Always use `make build` rather than direct `go build` commands. The embedded CA bundle is downloaded fresh at build time and is not checked into git.

## Development

### Project Structure

```
cypherhawk/
├── cmd/cypherhawk/              # Main CLI application with custom help system
├── internal/
│   ├── analysis/               # Certificate chain analysis and DPI detection
│   ├── bundle/                 # Mozilla CA bundle management with multi-source validation
│   ├── network/                # TLS certificate retrieval with retry logic and proxy support
│   ├── output/                 # HawkScan-optimized PEM formatting and file output
│   └── security/               # Advanced security validation (CT, behavioral analysis, CA impersonation)
├── testdata/                   # Mock certificate generation for 6+ DPI vendors
├── main_test.go                # Core security validation tests with mock DPI environments
├── cross_platform_test.go      # Cross-platform compatibility tests (Windows, macOS, Linux)
├── network_conditions_test.go  # Network condition and error handling tests
├── hawkscan_integration_test.go # HawkScan PEM compatibility tests
├── test_utils.go               # Test utilities and proxy environment cleanup
└── README.md
```

### Running Tests

```bash
# Run all tests (comprehensive test suite)
go test -v ./...

# Run specific test suites
go test -v -run TestEnhancedSecurityValidation    # Core security testing
go test -v -run TestCrossPlatformCompatibility    # Cross-platform testing
go test -v -run TestNetworkConditions             # Network condition testing
go test -v -run TestHawkScanPEMCompatibility      # HawkScan integration testing

# Run tests with network skip (faster for development)
CYPHERHAWK_SKIP_NETWORK_TESTS=1 go test -v ./...

# Run specific vendor tests
go test -v -run TestPaloAltoDetection
go test -v -run TestZscalerDetection
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security Considerations

CypherHawk is a **defensive security tool** designed to help users adapt to corporate security infrastructure:

- **Legitimate purpose**: Detects and extracts CA certificates from corporate DPI/MitM proxies with advanced threat analysis
- **Multiple CA bundle validation**: Cross-validates Mozilla's trusted CA bundles from multiple sources with integrity checking
- **Advanced security validation**: Combines Certificate Transparency checking, behavioral analysis, and CA impersonation detection
- **No malicious capability**: Cannot create, modify, or bypass security controls
- **Read-only operation**: Only extracts and outputs certificate information with comprehensive security analysis
- **No telemetry**: Tool does not send usage data or certificates to external services
- **Local operation**: All certificate analysis performed locally with enhanced security algorithms

## Support

- 📖 [Documentation](https://github.com/kaakaww/cypherhawk/wiki)
- 🐛 [Issues](https://github.com/kaakaww/cypherhawk/issues)
- 💬 [Discussions](https://github.com/kaakaww/cypherhawk/discussions)

## Acknowledgments

- Built by [StackHawk](https://stackhawk.com) for the Java security community
- Uses Mozilla's trusted CA bundle from [curl.se](https://curl.se/ca/cacert.pem) and GitHub mirror with cross-validation
- Inspired by the need to simplify corporate Java application deployment and HawkScan integration
- Comprehensive testing infrastructure with mock DPI environments for 6+ major enterprise security vendors