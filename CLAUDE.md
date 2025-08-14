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
- **Mozilla CA bundle** - Downloads and compares against Mozilla's trusted certificates from curl.se
- **Certificate chain analysis** - Compares received vs expected certificate chains using InsecureSkipVerify
- **DPI vendor identification** - Recognizes major enterprise security vendors (Palo Alto, Netskope, Zscaler)
- **Flexible target URLs** - Supports custom target URLs via `-url` flag (default: https://www.google.com)
- **PEM extraction** - Outputs unknown CA certificates in standard PEM format
- **Default endpoints** - Tests StackHawk services and configurable targets

## Key Files

| File | Purpose |
|------|---------|
| `main.go` | Main CLI application (~150 lines) with Mozilla CA bundle validation and certificate extraction |
| `main_test.go` | Comprehensive functional tests with mock CA and server certificate generation |
| `go.mod` | Go module definition - intentionally no external dependencies |
| `Makefile` | Cross-platform build automation and packaging (optional, prefer go build) |
| `README.md` | User documentation and usage examples |
| `.github/workflows/build.yml` | Automated testing and release building |

## Testing Strategy

### Functional Testing (main_test.go)
- **Sophisticated unit tests** with mock certificate generation
- **Simulated DPI environment** by creating test TLS server with custom CA
- **Mock CA and server certificates** for realistic MitM scenario testing
- **Comprehensive validation** that tool correctly detects and extracts unknown CAs
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
- **Mozilla CA bundle validation** - Downloads from curl.se/ca/cacert.pem for trust comparison
- **Certificate chain analysis** using InsecureSkipVerify to capture all certificates
- **Vendor identification** for major DPI providers (Palo Alto, Netskope, Zscaler, etc.)
- **Unknown CA extraction** - Identifies certificates not in Mozilla's trusted bundle
- **Certificate deduplication** across multiple endpoints

## Command Line Interface

```bash
# Basic usage
dpi-hawk                          # Use default target (https://www.google.com)
dpi-hawk -url https://example.com # Test specific target URL
dpi-hawk -o certs.pem            # Save certificates to file
dpi-hawk -o -                    # Output certificates to stdout
```

### Key Functions (main.go)
- **Mozilla CA download** - Downloads trusted CA bundle from curl.se/ca/cacert.pem
- **HTTP client creation** - Uses InsecureSkipVerify to capture all certificate chains
- **Certificate chain analysis** - Compares received certificates against Mozilla bundle
- **PEM conversion** - Converts unknown CA certificates to standard PEM format via `certToPEM()`

## MVP Implementation Plan

**Phase 1 - Core MVP (Essential Features):**
1. **Mozilla CA bundle integration** - Download and cache Mozilla's trusted CA bundle
2. **Four endpoint testing** - Test against Google, StackHawk auth/API, and AWS S3 endpoints
3. **Certificate chain extraction** - Use InsecureSkipVerify to capture all certificates
4. **Unknown CA detection** - Compare certificates against Mozilla bundle
5. **PEM output** - Output unknown CA certificates in standard PEM format
6. **Robust error handling** - 30-second timeouts, graceful failure handling, clear error messages

**Phase 2 - Enhanced Features:**
1. **Custom target URLs** - Support `-url` flag for testing arbitrary endpoints
2. **Verbose mode** - Detailed debugging output with `--verbose` flag
3. **JKS conversion helper** - Documentation and examples for PEM-to-JKS conversion
4. **DPI vendor identification** - Pattern matching for Palo Alto, Netskope, Zscaler
5. **Certificate deduplication** - Remove duplicate certificates across endpoints
6. **Progress indicators** - Show testing progress for multiple endpoints

**Phase 3 - Advanced Features:**
1. **Embedded CA bundle backup** - Fallback for air-gapped environments
2. **JSON output format** - Machine-readable output option
3. **Configuration file support** - Custom endpoint lists and settings
4. **Proxy support** - Corporate proxy configuration
5. **Certificate chain validation** - Advanced certificate path validation

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
- **Legitimate purpose** - Detects and extracts CA certificates from corporate DPI/MitM proxies
- **Mozilla CA validation** - Uses Mozilla's trusted CA bundle (curl.se/ca/cacert.pem) for accurate comparison
- **No malicious capability** - Cannot create, modify, or bypass security controls
- **Read-only operation** - Only extracts and outputs certificate information

**Network Security:**
- **HTTPS download** - Mozilla CA bundle downloaded over secure HTTPS connection
- **InsecureSkipVerify usage** - Only used for certificate inspection, not for validation bypass
- **No credential handling** - Tool does not store, transmit, or log any sensitive information
- **Local operation** - All certificate analysis performed locally

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