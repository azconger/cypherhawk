# DPI Hawk - Claude Code Context

## Project Overview

CLI utility to detect corporate Deep Packet Inspection (DPI) firewalls and man-in-the-middle (MitM) proxies, then extract their CA certificates for Java applications and security tools. Uses Mozilla's trusted CA bundle for validation and supports custom target URLs for flexible testing.

Built by StackHawk but designed for the broader Java ecosystem including Maven, Gradle, Spring Boot applications, and other security tools.

## Project Type
- Language: Go
- Type: CLI application
- Distribution: Single static binary (no dependencies)
- Validation: Mozilla CA bundle from curl.se/ca/cacert.pem

## Build Commands

```bash
# Development (simplified approach)
go run main.go              # Run the tool with default settings
go run main.go -url https://example.com  # Run with custom target URL
go run main.go -o certs.pem # Save certificates to file
go test -v                  # Run comprehensive tests with mock DPI simulation

# Build
go build -o dpi-hawk main.go  # Build single binary

# Cross-platform builds (advanced)
make build-all      # Build for all platforms
make package        # Create release archives
make clean          # Clean build artifacts
```

## Development Workflow

1. Use `go run main.go -url <target>` for testing during development
2. Use `go build -o dpi-hawk main.go` to create local binary for testing
3. Use `go test -v` to run comprehensive functional tests with simulated DPI environments
4. Use `make build-all` for cross-platform binaries when preparing releases
5. Test against various corporate environments when possible

## Architecture & Design Decisions

### Core Principles
- **Zero external dependencies** - Uses only Go standard library for easy distribution
- **Single binary** - Customers can download and run immediately
- **Cross-platform** - Supports Linux, macOS, Windows (AMD64/ARM64)
- **Enterprise-focused** - Designed for corporate environments with DPI
- **Mozilla CA validation** - Uses Mozilla's trusted CA bundle for accurate MitM detection

### Key Components
- **Multiple CA bundle sources** - Cross-validates Mozilla CA bundles from multiple sources with integrity checking
- **Enhanced certificate chain validation** - Browser-like certificate verification with hostname validation
- **Certificate Transparency validation** - Checks for SCT extensions in recent certificates
- **Comprehensive behavioral analysis** - 10+ suspicious behavior indicators including weak keys, recent issuance, unusual validity periods
- **CA impersonation detection** - Detects certificates claiming to be from legitimate CAs but with suspicious characteristics
- **DPI vendor identification** - Recognizes major enterprise security vendors (Palo Alto, Netskope, Zscaler)
- **Risk scoring system** - Combines multiple security indicators for high-confidence detection
- **Flexible target URLs** - Supports custom target URLs via `-url` flag (default: 4 endpoints)
- **PEM extraction** - Outputs unknown CA certificates in standard PEM format

## Key Files

| File | Purpose |
|------|---------|
| `main.go` | Main CLI application (~750 lines) with advanced security validation, multiple CA bundle sources, Certificate Transparency checking, behavioral analysis, and CA impersonation detection |
| `main_test.go` | Comprehensive security validation tests with mock CA/server certificates, CT validation tests, behavioral analysis tests, and CA impersonation detection tests |
| `go.mod` | Go module definition - intentionally no external dependencies |
| `Makefile` | Cross-platform build automation and packaging (optional, prefer go build) |
| `README.md` | User documentation and usage examples |
| `.github/workflows/build.yml` | Automated testing and release building |

## Testing Strategy

### Functional Testing (main_test.go)
- **Advanced security validation tests** with mock certificate generation
- **Simulated DPI environment** by creating test TLS server with custom CA
- **Mock CA and server certificates** for realistic MitM scenario testing  
- **Certificate Transparency validation tests** - Verifies CT evidence checking for recent certificates
- **Behavioral analysis tests** - Tests detection of 10+ suspicious certificate indicators
- **CA impersonation detection tests** - Validates detection of fake certificates claiming to be from legitimate CAs
- **Multiple CA bundle source tests** - Tests cross-validation of CA bundles from multiple sources
- **Enhanced security validation integration tests** - Tests combined security analysis with risk scoring
- **Comprehensive validation** that tool correctly detects and extracts unknown CAs with advanced threat detection
- **Production-ready testing** suitable for CI/CD pipelines

### Default Test Endpoints
The tool tests against four key endpoints that represent common corporate network requirements:

- **Primary target** - https://www.google.com (default, configurable via `-url` flag)
- **StackHawk authentication** - `https://auth.stackhawk.com`
- **StackHawk API** - `https://api.stackhawk.com`
- **AWS S3** - `https://s3.us-west-2.amazonaws.com` (for pre-signed URLs)

**Connection Handling:**
- 30-second timeout per endpoint
- Graceful failure handling for dropped connections
- Continues testing remaining endpoints if one fails
- Reports which endpoints succeeded/failed in output

### DPI Detection
- **Multiple CA bundle sources** - Cross-validates Mozilla CA bundles from curl.se and GitHub mirror with size variance checking (up to 10% allowed)
- **Enhanced certificate chain validation** - Browser-like certificate verification with hostname validation and complete chain analysis
- **Certificate Transparency validation** - Checks for SCT (Signed Certificate Timestamp) extensions in certificates issued within the last 3 years
- **Comprehensive behavioral analysis** - Detects 10+ suspicious indicators:
  - Recent issuance patterns (< 24 hours)
  - Unusual validity periods (> 10 years or < 7 days)
  - Suspicious serial numbers (trivial values like "1", "123")
  - Weak cryptographic keys (RSA < 2048 bits, ECDSA < 256 bits)
  - Suspicious subject/issuer terms ("test", "demo", "localhost")
  - Hostname mismatches and self-signed leaf certificates
  - Weak signature algorithms (MD5, SHA1)
  - Future-dated certificates and unusual chain lengths
- **CA impersonation detection** - Identifies certificates claiming to be from legitimate CAs (Google, DigiCert, Let's Encrypt) but with suspicious characteristics
- **Vendor identification** for major DPI providers (Palo Alto, Netskope, Zscaler, etc.)
- **Risk scoring system** - Combines multiple suspicious indicators for high-confidence detection (3+ indicators = HIGH RISK)
- **Unknown CA extraction** - Identifies certificates not trusted by Mozilla's CA bundle
- **Certificate deduplication** across multiple endpoints

## Command Line Interface

```bash
# Basic usage
dpi-hawk                          # Test default 4 endpoints (Google, StackHawk auth/API, AWS S3)
dpi-hawk -url https://example.com # Test specific target URL
dpi-hawk -o certs.pem            # Save certificates to file
dpi-hawk -o -                    # Output certificates to stdout
dpi-hawk --verbose               # Enable detailed security analysis output
```

**Verbose Mode Security Output:**
When using `--verbose`, the tool provides detailed security analysis including:
- Certificate Transparency validation results
- Behavioral analysis findings (weak keys, suspicious patterns, etc.)
- Hostname validation results
- CA impersonation detection alerts
- Risk scoring when multiple suspicious indicators are detected

### Key Functions (main.go)
- **Mozilla CA download** - Downloads trusted CA bundle from curl.se/ca/cacert.pem
- **HTTP client creation** - Uses InsecureSkipVerify to capture all certificate chains
- **Certificate chain analysis** - Compares received certificates against Mozilla bundle
- **PEM conversion** - Converts unknown CA certificates to standard PEM format via `certToPEM()`

## MVP Implementation Plan

**✅ Phase 1 - Core MVP (Essential Features) - COMPLETED:**
1. ✅ **Mozilla CA bundle integration** - Download and cache Mozilla's trusted CA bundle
2. ✅ **Four endpoint testing** - Test against Google, StackHawk auth/API, and AWS S3 endpoints
3. ✅ **Certificate chain extraction** - Use InsecureSkipVerify to capture all certificates
4. ✅ **Unknown CA detection** - Compare certificates against Mozilla bundle
5. ✅ **PEM output** - Output unknown CA certificates in standard PEM format
6. ✅ **Robust error handling** - 30-second timeouts, graceful failure handling, clear error messages

**✅ Phase 2 - Enhanced Features - COMPLETED:**
1. ✅ **Custom target URLs** - Support `-url` flag for testing arbitrary endpoints
2. ✅ **Verbose mode** - Detailed debugging output with `--verbose` flag
3. ✅ **JKS conversion helper** - Documentation and examples for PEM-to-JKS conversion
4. ✅ **DPI vendor identification** - Pattern matching for Palo Alto, Netskope, Zscaler
5. ✅ **Certificate deduplication** - Remove duplicate certificates across endpoints
6. ✅ **Progress indicators** - Show testing progress for multiple endpoints

**✅ Phase 3 - Advanced Security Features - COMPLETED:**
1. ✅ **Multiple CA bundle sources** - Cross-validate CA bundles from curl.se and GitHub mirror with integrity checking
2. ✅ **Certificate Transparency validation** - Check for SCT extensions in certificates issued within last 3 years
3. ✅ **Comprehensive behavioral analysis** - Detect 10+ suspicious certificate indicators (weak keys, recent issuance, unusual validity, etc.)
4. ✅ **CA impersonation detection** - Identify certificates falsely claiming to be from legitimate CAs
5. ✅ **Enhanced certificate chain validation** - Browser-like verification with hostname validation
6. ✅ **Risk scoring system** - Combine multiple suspicious indicators for high-confidence detection

**Phase 4 - Future Enhancements:**
1. **Embedded CA bundle backup** - Fallback for air-gapped environments
2. **JSON output format** - Machine-readable output option
3. **Configuration file support** - Custom endpoint lists and settings
4. **Proxy support** - Corporate proxy configuration
5. **Advanced CT log validation** - Direct querying of Certificate Transparency logs

## Common Enhancement Areas

When modifying this project, common tasks include:

1. **Mozilla CA bundle integration** - Enhancing the Mozilla CA validation logic and caching
2. **Certificate validation improvements** - Enhanced chain analysis and comparison algorithms
3. **Connection reliability** - Improved timeout handling, retry logic, and network resilience
4. **DPI vendor detection** - New patterns for additional enterprise security vendors
5. **Output format options** - Additional formats like JSON, YAML, or direct JKS generation
6. **Testing enhancements** - More sophisticated mock DPI scenarios and edge case testing

## Target Audience

- **Java developers** dealing with corporate environments
- **StackHawk users** evaluating the scanner in corporate environments
- **DevOps/SRE teams** dealing with corporate security infrastructure
- **Security teams** who need to configure certificate trust for Java applications

## Integration Examples

The generated PEM file works with various Java tools:

**StackHawk:**
```bash
hawk scan --ca-bundle dpi-hawk-certs.pem
```

**Java applications (PEM format - Java 9+):**
```bash
java -Djavax.net.ssl.trustStoreType=PEM -Djavax.net.ssl.trustStore=dpi-hawk-certs.pem MyApp
```

**Java applications (JKS format - all Java versions):**
```bash
# Convert PEM to JKS format
keytool -importcert -noprompt -file dpi-hawk-certs.pem -keystore dpi-hawk.jks -storepass changeit -alias dpi-ca

# Use JKS with Java application
java -Djavax.net.ssl.trustStore=dpi-hawk.jks -Djavax.net.ssl.trustStorePassword=changeit MyApp
```

**Maven (PEM format):**
```bash
mvn -Djavax.net.ssl.trustStoreType=PEM -Djavax.net.ssl.trustStore=dpi-hawk-certs.pem clean install
```

**Maven (JKS format):**
```bash
mvn -Djavax.net.ssl.trustStore=dpi-hawk.jks -Djavax.net.ssl.trustStorePassword=changeit clean install
```

**Gradle:**
```bash
./gradlew build -Djavax.net.ssl.trustStoreType=PEM -Djavax.net.ssl.trustStore=dpi-hawk-certs.pem
```

## Security Considerations

This is a **defensive security tool** designed to help users adapt to corporate security infrastructure:

**Tool Security:**
- **Legitimate purpose** - Detects and extracts CA certificates from corporate DPI/MitM proxies with advanced threat analysis
- **Multiple CA bundle validation** - Cross-validates Mozilla's trusted CA bundles from multiple sources (curl.se and GitHub mirror) with integrity checking
- **Advanced security validation** - Combines Certificate Transparency checking, behavioral analysis, and CA impersonation detection
- **No malicious capability** - Cannot create, modify, or bypass security controls
- **Read-only operation** - Only extracts and outputs certificate information with comprehensive security analysis

**Network Security:**
- **HTTPS download** - Mozilla CA bundles downloaded over secure HTTPS connections from multiple trusted sources
- **InsecureSkipVerify usage** - Only used for certificate inspection, not for validation bypass
- **Certificate Transparency validation** - Checks for proper CT evidence in recent certificates to detect potential forgeries
- **Behavioral analysis protection** - Detects multiple categories of suspicious certificate characteristics
- **CA impersonation protection** - Identifies certificates falsely claiming to be from legitimate certificate authorities
- **No credential handling** - Tool does not store, transmit, or log any sensitive information
- **Local operation** - All certificate analysis performed locally with enhanced security algorithms

**Data Privacy:**
- **No telemetry** - Tool does not send usage data or certificates to external services
- **Local file output** - Certificate data only written to user-specified local files
- **Ephemeral operation** - No persistent storage of sensitive data beyond user-requested output

**Corporate Environment Safety:**
- **Transparent operation** - Tool clearly reports which endpoints it tests and why
- **Graceful failure** - Continues operation even if some endpoints are blocked
- **Audit-friendly** - All actions logged and can be monitored by corporate security tools

## Error Handling Strategy

**Network Errors:**
- **Connection timeouts** - 30-second timeout per endpoint with clear error messages
- **DNS resolution failures** - Graceful handling with specific error reporting
- **Certificate parsing errors** - Continue processing other certificates, report parsing failures
- **HTTP errors** - Distinguish between network issues and HTTP status errors

**Certificate Processing:**
- **Invalid certificate chains** - Log errors but continue processing valid certificates
- **Mozilla CA bundle failures** - Fall back to embedded backup bundle or clear error message
- **PEM encoding errors** - Skip malformed certificates, report count of skipped items
- **Duplicate detection** - Handle duplicate certificates across endpoints gracefully

**File Operations:**
- **Output file permissions** - Create files with appropriate permissions (0644)
- **Disk space** - Check available space before writing large certificate bundles
- **File locking** - Handle concurrent access to output files

**User Experience:**
- **Progress indicators** - Show progress when testing multiple endpoints
- **Verbose mode** - Detailed error reporting with `--verbose` flag
- **Exit codes** - Standard exit codes: 0=success, 1=partial failure, 2=complete failure
- **Clear error messages** - Human-readable error descriptions with suggested actions

## Deployment Considerations

- GitHub Actions automatically builds releases on version tags
- No installation required - single binary distribution
- Works in air-gapped environments (with embedded Mozilla CA bundle backup)
- Minimal resource requirements for customer systems
- Compatible with corporate security scanning and monitoring tools