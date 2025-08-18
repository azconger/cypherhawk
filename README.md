# CypherHawk

[![Go Version](https://img.shields.io/github/go-mod/go-version/kaakaww/cypherhawk)](https://golang.org/dl/)
[![License](https://img.shields.io/github/license/kaakaww/cypherhawk)](LICENSE)
[![Build Status](https://img.shields.io/github/actions/workflow/status/kaakaww/cypherhawk/build.yml?branch=main)](https://github.com/kaakaww/cypherhawk/actions)

A command-line tool to detect corporate Deep Packet Inspection (DPI) firewalls and man-in-the-middle (MitM) proxies, then extract their CA certificates for Java applications and security tools.

CypherHawk uses Mozilla's trusted CA bundle for validation and supports custom target URLs for flexible testing. Built by StackHawk but designed for the broader Java ecosystem including Maven, Gradle, Spring Boot applications, and other security tools.

## Features

- **🔍 Corporate DPI Detection**: Automatically detects enterprise security infrastructure
- **🚨 Advanced Threat Detection**: Identifies malicious MitM attacks vs. legitimate corporate proxies
- **📋 Certificate Chain Analysis**: Detailed analysis of TLS certificate chains with anomaly detection
- **🛡️ Security Validation**: Certificate Transparency validation, behavioral analysis, and CA impersonation detection
- **📦 PEM Output**: Extracts unknown CA certificates in standard PEM format for easy integration
- **⚡ Fast & Reliable**: Single binary with no dependencies, 30-second timeouts, graceful error handling
- **🔒 Enterprise-Ready**: Supports major DPI vendors (Palo Alto, Zscaler, Netskope, etc.)

## Quick Start

### Installation

Download the latest binary from [releases](https://github.com/kaakaww/cypherhawk/releases) or build from source:

```bash
git clone https://github.com/kaakaww/cypherhawk.git
cd cypherhawk
go build -o cypherhawk ./cmd/cypherhawk
```

### Basic Usage

```bash
# Test default endpoints (Google, StackHawk, AWS)
./cypherhawk

# Test a specific website
./cypherhawk -url example.com

# Analyze certificate chain details
./cypherhawk --analyze -url github.com

# Save certificates to file
./cypherhawk -o corporate-certs.pem -url internal.company.com
```

## Usage Examples

### Corporate Environment Detection

```bash
# Basic DPI detection
$ ./cypherhawk
✓ No corporate DPI detected (tested 4 endpoints)

# When DPI is detected
$ ./cypherhawk -url internal.corp.com
⚠ Corporate DPI detected: found 1 unknown CA certificate
# PEM certificates follow...
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
Usage: ./cypherhawk [options]

Options:
  -analyze              Show detailed certificate chain analysis
  -o string             Output file for CA certificates (use '-' for stdout)
  -url string           Custom target URL to test (assumes https:// if no protocol specified)
  -verbose              Enable verbose output
  -version              Show version information
```

## Integration with Java Applications

### StackHawk Scanner
```bash
./cypherhawk -o corporate-certs.pem
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

1. **Downloading Mozilla's trusted CA bundle** from multiple sources with cross-validation
2. **Testing TLS connections** to default endpoints (or your custom URL)
3. **Analyzing certificate chains** using browser-like validation logic
4. **Detecting unknown CAs** that aren't in Mozilla's trusted bundle
5. **Performing security analysis** with Certificate Transparency validation, behavioral analysis, and threat detection
6. **Extracting CA certificates** that likely belong to corporate DPI infrastructure

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

CypherHawk recognizes certificates from major enterprise security vendors:

- Palo Alto Networks
- Zscaler
- Netskope
- Forcepoint
- Cisco/BlueCoat
- McAfee Web Gateway
- Symantec ProxySG
- Checkpoint
- Fortinet
- Sophos
- And many more...

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

# Quick build (includes code quality checks)
make build

# Full development workflow
make pre-commit  # Run all checks + tests before committing

# Run tests
make test

# Cross-platform builds
make build-all

# Code quality checks
make check      # Format check + vet + lint
make fmt        # Fix formatting issues
```

## Development

### Project Structure

```
cypherhawk/
├── cmd/cypherhawk/        # Main CLI application
├── internal/
│   ├── analysis/         # Certificate chain analysis and DPI detection
│   ├── bundle/           # Mozilla CA bundle management
│   ├── network/          # TLS certificate retrieval
│   ├── output/           # PEM formatting and file output
│   └── security/         # Advanced security validation
├── main_test.go          # Comprehensive test suite
└── README.md
```

### Running Tests

```bash
# Run all tests
go test -v ./...

# Run specific test suites
go test -v -run TestRealisticDPIEnvironments
go test -v -run TestAdvancedDPITechniques

# Generate test artifacts for inspection
go test -v -run TestWithArtifacts
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

- **Legitimate purpose**: Detects and extracts CA certificates from corporate DPI/MitM proxies
- **No malicious capability**: Cannot create, modify, or bypass security controls
- **Read-only operation**: Only extracts and outputs certificate information
- **No telemetry**: Tool does not send usage data or certificates to external services
- **Local operation**: All certificate analysis performed locally

## Support

- 📖 [Documentation](https://github.com/kaakaww/cypherhawk/wiki)
- 🐛 [Issues](https://github.com/kaakaww/cypherhawk/issues)
- 💬 [Discussions](https://github.com/kaakaww/cypherhawk/discussions)

## Acknowledgments

- Built by [StackHawk](https://stackhawk.com) for the Java security community
- Uses Mozilla's trusted CA bundle from [curl.se](https://curl.se/ca/cacert.pem)
- Inspired by the need to simplify corporate Java application deployment