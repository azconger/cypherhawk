# CypherHawk - Claude Code Context

## Project Overview

Production-ready CLI utility that detects corporate Deep Packet Inspection (DPI) firewalls and man-in-the-middle (MitM) proxies, extracts their CA certificates, and provides comprehensive security analysis. Features advanced threat detection capabilities with vendor identification, behavioral analysis, and Certificate Transparency validation.

Built by StackHawk but designed for the broader Java ecosystem including Maven, Gradle, Spring Boot applications, and security tools like HawkScan.

## Current Status: Phase 3+ Complete ✅

**✅ Phase 1-3 COMPLETED Features:**
- Core DPI detection with Mozilla CA bundle validation
- Enhanced security analysis with 15+ vendor detection patterns  
- Comprehensive test suite with mock DPI environments
- Advanced threat detection including Certificate Transparency validation
- Behavioral analysis detecting 10+ suspicious certificate indicators
- Cross-platform compatibility testing
- Network condition testing and proxy environment cleanup
- HawkScan integration optimization

**✅ Phase 3+ ADDITIONAL COMPLETED Features:**
- Complete DPI testing infrastructure for development and validation
- Cross-platform DPI testing environment (Windows, macOS, Linux)
- Automated validation scripts with comprehensive cleanup
- Multiple DPI simulation approaches (standalone, mitmproxy, Squid)
- Platform-specific documentation and troubleshooting guides

**🎯 Current Status:**
- Production-ready with comprehensive testing infrastructure
- Ready for advanced features and enhanced detection modes
- Complete cross-platform DPI testing capability established

## Project Type
- **Language:** Go with high-quality external modules
- **Type:** CLI application for defensive security analysis
- **Distribution:** Single static binary with minimal dependencies
- **Dependencies:** HashiCorp go-retryablehttp, Cobra CLI framework, Viper configuration
- **Validation:** Multiple Mozilla CA bundle sources with cross-validation
- **Architecture:** Modular internal packages with robust external libraries
- **Security Focus:** Corporate DPI detection, threat analysis, defensive tooling
- **Logging:** Structured logging with configurable levels for enterprise debugging

## Build Commands

```bash
# Development (enhanced CLI with Cobra framework)
go run ./cmd/cypherhawk              # Run the tool with default settings
go run ./cmd/cypherhawk --url https://example.com  # Run with custom target URL
go run ./cmd/cypherhawk --output certs.pem # Save certificates to file
go run ./cmd/cypherhawk detect --verbose --analyze  # Enhanced analysis with structured logging
go run ./cmd/cypherhawk version      # Show version information
go test -v ./...               # Run comprehensive tests with mock DPI simulation

# Build (includes fresh CA bundle download)
make build                    # Build with latest Mozilla CA bundle
make update-ca-bundle         # Manually update CA bundle
go build -o cypherhawk ./cmd/cypherhawk  # Build single binary (uses existing CA bundle)

# Cross-platform builds (advanced)
make build-all      # Build for all platforms with fresh CA bundle
make package        # Create release archives
make clean          # Clean build artifacts
```

## Development Workflow

1. Use `go run ./cmd/cypherhawk -url <target>` for testing during development
2. Use `make build` to create local binary with fresh CA bundle for testing
3. Use `go test -v ./...` to run comprehensive functional tests with simulated DPI environments
4. Use `make build-all` for cross-platform binaries when preparing releases (includes CA bundle update)
5. Use `make update-ca-bundle` to manually refresh the embedded CA bundle
6. Test against various corporate environments when possible

**Important:** Always use `make build` or `make build-all` for production builds to ensure the embedded CA bundle is fresh. Direct `go build` commands will fail if no embedded bundle exists.

**Build System Design:**
- `make clean` removes the embedded CA bundle to force fresh downloads
- `make build` downloads latest CA bundle before building 
- No static CA bundle is checked into git - always downloaded fresh
- CI/CD builds always get the latest Mozilla CA certificates

## Architecture & Design Decisions

### Core Principles
- **Zero external dependencies** - Uses only Go standard library for easy distribution
- **Single binary** - Customers can download and run immediately
- **Cross-platform** - Supports Linux, macOS, Windows (AMD64/ARM64)
- **Enterprise-focused** - Designed for corporate environments with DPI
- **Mozilla CA validation** - Uses Mozilla's trusted CA bundle for accurate MitM detection

### Key Components
- **Build-time CA bundle updates** - Downloads latest Mozilla CA certificates during build process to prevent stale embedded bundles
- **Multiple CA bundle sources** - Cross-validates Mozilla CA bundles from multiple sources with integrity checking
- **Enhanced HTTP client** - HashiCorp go-retryablehttp for robust networking with enterprise proxy support
- **Professional CLI** - Cobra framework with subcommands, configuration files, and structured help
- **Structured logging** - Go 1.21+ slog with configurable levels for enterprise debugging
- **Enhanced certificate chain validation** - Browser-like certificate verification with hostname validation
- **Certificate Transparency validation** - Checks for SCT extensions in recent certificates
- **Comprehensive behavioral analysis** - 10+ suspicious behavior indicators including weak keys, recent issuance, unusual validity periods
- **CA impersonation detection** - Detects certificates claiming to be from legitimate CAs but with suspicious characteristics
- **DPI vendor identification** - Recognizes major enterprise security vendors (Palo Alto, Netskope, Zscaler)
- **Risk scoring system** - Combines multiple security indicators for high-confidence detection
- **Flexible target URLs** - Supports custom target URLs via `--url` flag (default: 4 endpoints)
- **PEM extraction** - Outputs unknown CA certificates in standard PEM format
- **Complete DPI testing infrastructure** - Standalone server, mitmproxy, and Squid setups with cross-platform validation scripts

## Project Structure

```
cypherhawk/
├── cmd/
│   └── cypherhawk/         # Main application entry point
│       └── main.go         # CLI interface with custom help system (~200 lines)
├── internal/               # Internal packages (not importable by other projects)
│   ├── bundle/            # CA bundle management (~118 lines)
│   │   └── bundle.go      # Multiple source download and cross-validation
│   ├── analysis/          # Certificate analysis (~192 lines) 
│   │   └── analysis.go    # Chain validation and DPI detection
│   ├── security/          # Security validation features (~242 lines)
│   │   └── security.go    # CT validation, behavioral analysis, CA impersonation
│   ├── network/           # Network operations (~247 lines)
│   │   └── network.go     # Certificate retrieval, retry logic, proxy support
│   └── output/            # Output generation (~85 lines)
│       └── output.go      # HawkScan-optimized PEM formatting and deduplication
├── cmd/
│   └── dpi-test-server/    # DPI simulation server for testing
│       └── main.go         # Standalone HTTPS server with 5 corporate DPI profiles (~200 lines)
├── scripts/              # Build and automation scripts  
│   ├── update-ca-bundle.sh # Downloads latest Mozilla CA bundle at build time (~140 lines)
│   ├── validate-dpi-setup.sh # Linux/macOS DPI testing validation script (~325 lines)
│   ├── validate-dpi-setup.ps1 # Windows PowerShell DPI testing validation script (~325 lines)
│   └── README.md           # Validation script documentation and usage guide
├── docker/               # DPI testing environments
│   ├── mitmproxy/         # Professional proxy with SSL interception
│   │   ├── docker-compose.yml # mitmproxy container configuration
│   │   └── generate-corporate-ca.sh # Corporate CA generation for mitmproxy
│   └── squid/             # Enterprise-grade proxy with SSL bumping
│       ├── docker-compose.yml # Squid proxy container configuration
│       └── scripts/generate-squid-certs.sh # Corporate CA generation for Squid (~175 lines)
├── testdata/              # Test data and mock certificate generation
│   └── testdata.go        # Mock DPI certificate chains for 6+ vendors (~300 lines)
├── main_test.go           # Comprehensive security validation tests (~640 lines)
├── cross_platform_test.go # Cross-platform compatibility tests (~409 lines)
├── network_conditions_test.go # Network condition and error handling tests (~492 lines)
├── hawkscan_integration_test.go # HawkScan PEM compatibility tests (~150 lines)
├── test_utils.go          # Test utilities and proxy environment cleanup (~58 lines)
├── Makefile               # Build automation with CA bundle updates and cross-platform builds (~230 lines)
├── go.mod                 # Go module definition (github.com/kaakaww/cypherhawk)
├── go.sum                 # Go module checksums
├── CLAUDE.md              # Context file for Claude Code
├── README.md              # User documentation and usage examples  
├── WINDOWS-DPI-TESTING.md # Windows-specific DPI testing setup guide (~311 lines)
├── MACOS-DPI-TESTING.md   # macOS-specific DPI testing setup guide (~315 lines)
└── .github/workflows/build.yml  # Automated testing and release building with fresh CA bundles
```

## Key Files

| File/Package | Purpose |
|--------------|---------|
| `cmd/cypherhawk/main.go` | Main CLI application entry point with custom help system - handles command-line interface, orchestrates other packages |
| `internal/bundle/` | CA bundle management - downloads Mozilla CA bundles from multiple sources with cross-validation |
| `internal/analysis/` | Certificate chain analysis - browser-like validation, DPI detection, trust verification |
| `internal/security/` | Advanced security features - Certificate Transparency validation, behavioral analysis, CA impersonation detection |
| `internal/network/` | Network operations - TLS certificate retrieval, retry logic, proxy support, enhanced error handling |
| `internal/output/` | Output generation - HawkScan-optimized PEM formatting, certificate deduplication |
| `cmd/dpi-test-server/` | DPI simulation server - standalone HTTPS server with 5 corporate DPI profiles for testing |
| `scripts/update-ca-bundle.sh` | Build-time script that downloads latest Mozilla CA bundle to prevent stale embedded certificates |
| `scripts/validate-dpi-setup.sh` | Linux/macOS DPI testing validation script - automated testing with comprehensive cleanup |
| `scripts/validate-dpi-setup.ps1` | Windows PowerShell DPI testing validation script - automated testing with comprehensive cleanup |
| `docker/mitmproxy/` | Professional proxy setup - SSL interception with corporate CA generation |
| `docker/squid/` | Enterprise-grade proxy setup - SSL bumping with corporate CA generation |
| `WINDOWS-DPI-TESTING.md` | Windows-specific DPI testing setup guide with detailed troubleshooting |
| `MACOS-DPI-TESTING.md` | macOS-specific DPI testing setup guide with Keychain Access and networksetup instructions |
| `testdata/testdata.go` | Mock certificate generation for 6+ DPI vendors - realistic test data for comprehensive validation |
| `main_test.go` | Core security validation tests with mock DPI environments and advanced threat detection |
| `cross_platform_test.go` | Cross-platform compatibility tests for Windows, macOS, Linux |
| `network_conditions_test.go` | Network condition testing - timeouts, retries, proxy authentication, DNS failures |
| `hawkscan_integration_test.go` | HawkScan PEM compatibility tests - format validation, ordering, metadata |
| `test_utils.go` | Test utilities including proxy environment cleanup to prevent test pollution |
| `Makefile` | Build automation with CA bundle updates, cross-platform builds, and comprehensive testing |
| `go.mod` | Go module definition with GitHub import path - zero external dependencies |

## Testing Strategy

CypherHawk features a comprehensive test suite with 4 specialized test files covering different aspects:

### Core Security Testing (main_test.go)
- **Advanced security validation tests** with mock certificate generation for 6+ DPI vendors
- **Simulated DPI environment** by creating test TLS server with custom CA chains
- **Mock CA and server certificates** for realistic MitM scenario testing (Palo Alto, Zscaler, Netskope, etc.)
- **Certificate Transparency validation tests** - Verifies CT evidence checking for recent certificates
- **Behavioral analysis tests** - Tests detection of 10+ suspicious certificate indicators
- **CA impersonation detection tests** - Validates detection of fake certificates claiming to be from legitimate CAs
- **Multiple CA bundle source tests** - Tests cross-validation of CA bundles from multiple sources
- **Enhanced security validation integration tests** - Tests combined security analysis with risk scoring
- **Production-ready testing** suitable for CI/CD pipelines

### Cross-Platform Testing (cross_platform_test.go)
- **Platform compatibility** - Windows, macOS, Linux support validation
- **File system operations** - Path separators, temp directory access, Unicode handling
- **Environment variable handling** - Proxy configuration across platforms
- **Memory usage validation** - Reasonable resource consumption with GC handling
- **Executable naming conventions** - Platform-specific binary naming
- **Error message portability** - Platform-neutral error guidance

### Network Condition Testing (network_conditions_test.go)
- **Timeout handling** - 10-second timeout validation with proper retry logic
- **Connection failure scenarios** - DNS failures, connection refused, proxy authentication
- **Retry logic validation** - Exponential backoff, non-retryable error detection
- **Proxy support testing** - HTTP/HTTPS proxy environment variable handling
- **TLS handshake error handling** - Invalid certificates, protocol failures
- **Concurrent connection testing** - Multiple simultaneous connections
- **Real-world network scenarios** - Corporate firewall, DNS blocking, proxy authentication

### HawkScan Integration Testing (hawkscan_integration_test.go)
- **PEM format compliance** - RFC-compliant certificate formatting
- **Certificate ordering** - Proper leaf-to-root chain ordering
- **Metadata compatibility** - HawkScan-specific header formatting
- **Concatenation validation** - Multiple certificate chains in single file
- **Usage instruction embedding** - Clear integration guidance in output

### Default Test Endpoints
The tool tests against four key endpoints that represent common corporate network requirements:

- **Primary target** - https://www.google.com (default, configurable via `-url` flag)
- **StackHawk authentication** - `https://auth.stackhawk.com`
- **StackHawk API** - `https://api.stackhawk.com`
- **AWS S3** - `https://s3.us-west-2.amazonaws.com` (for pre-signed URLs)

**Connection Handling:**
- 10-second timeout per endpoint (optimized for user experience)
- Retry logic with exponential backoff (3 attempts max)
- Graceful failure handling for dropped connections
- Continues testing remaining endpoints if one fails
- Enhanced corporate network error guidance
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
- **Vendor identification** for 15+ major DPI providers (Palo Alto, Netskope, Zscaler, Fortinet, Check Point, etc.)
- **Risk scoring system** - Combines multiple suspicious indicators for high-confidence detection (3+ indicators = HIGH RISK)
- **Unknown CA extraction** - Identifies certificates not trusted by Mozilla's CA bundle
- **Certificate deduplication** across multiple endpoints
- **Enhanced error handling** - Corporate network guidance with specific troubleshooting steps

## Command Line Interface

```bash
# Basic usage with enhanced Cobra CLI
cypherhawk                          # Test default 4 endpoints (Google, StackHawk auth/API, AWS S3)
cypherhawk --url https://example.com # Test specific target URL
cypherhawk detect https://example.com # Alternative subcommand syntax
cypherhawk --output certs.pem      # Save certificates to file  
cypherhawk --output -              # Output certificates to stdout
cypherhawk --verbose --analyze     # Enable detailed security analysis output
cypherhawk --log-level debug       # Enhanced debugging with structured logging
cypherhawk version                 # Show version information
cypherhawk --help                  # Show comprehensive help with examples

# Configuration and environment
export CYPHERHAWK_OUTPUT=certs.pem # Environment variable support via Viper
export CYPHERHAWK_LOG_LEVEL=debug  # Configure logging level
cypherhawk --silent --output certs.pem # Script-friendly silent mode

# Future enhanced modes (Phase 4+)
cypherhawk --mode paranoid         # Alert on ANY unknown certificates (untrusted networks)
cypherhawk --mode compliance --baseline certs.json  # Compare against approved baseline
cypherhawk --mode monitor --interval 60s --webhook https://...  # Continuous monitoring
cypherhawk --geoip-check          # Include geographic risk assessment
cypherhawk --output-format json   # Machine-readable output
```

**Custom Help System:**
CypherHawk features a comprehensive custom help system (`--help`) that includes:
- Detailed HawkScan integration examples and workflows
- PEM and JKS certificate format usage instructions
- Common corporate network troubleshooting guidance
- Maven, Gradle, and Java application integration examples
- Corporate proxy configuration examples

**Verbose Mode Security Output:**
When using `--verbose`, the tool provides detailed security analysis including:
- Certificate Transparency validation results
- Behavioral analysis findings (weak keys, suspicious patterns, etc.)
- Hostname validation results
- CA impersonation detection alerts
- Risk scoring when multiple suspicious indicators are detected
- Vendor-specific DPI detection details

**Future Enhanced Output (Phase 4+):**
- Network context analysis (public WiFi risk assessment)
- Geographic threat indicators (high-surveillance regions)
- Baseline comparison results (deviation from approved certificates)
- Real-time monitoring alerts and webhook notifications

### Key Functions (main.go)
- **Custom help system** - Comprehensive HawkScan integration guidance via `showCustomHelp()`
- **Mozilla CA download** - Downloads trusted CA bundle from multiple sources with cross-validation
- **HTTP client creation** - Uses InsecureSkipVerify to capture all certificate chains with proxy support
- **Certificate chain analysis** - Advanced security analysis with vendor detection and behavioral analysis
- **PEM conversion** - Converts unknown CA certificates to HawkScan-optimized PEM format

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
7. ✅ **Comprehensive test suite** - 4 specialized test files covering security, cross-platform, network conditions, and HawkScan integration
8. ✅ **Enhanced vendor detection** - 15+ DPI vendor patterns with confidence scoring
9. ✅ **Network reliability improvements** - Retry logic, timeout optimization (10s), proxy environment cleanup
10. ✅ **HawkScan integration optimization** - Custom help system, optimized PEM output, integration examples

**Phase 4 - Enhanced Modes & Use Cases (Future):**
1. **Detection modes** - Multiple operating modes for different scenarios:
   - `--mode corporate` (current behavior) - Extract corporate DPI certificates
   - `--mode paranoid` - Alert on ANY unknown certificates (untrusted networks)
   - `--mode compliance` - Compare against approved certificate baseline
   - `--mode monitor` - Continuous monitoring with configurable intervals
2. **Network context awareness** - Adapt behavior based on environment:
   - GeoIP-based risk assessment for high-surveillance regions
   - Network type detection (public WiFi, corporate, home)
   - Known-malicious hotspot fingerprinting
3. **Real-time monitoring** - Background operation capabilities:
   - Daemon mode for continuous certificate monitoring
   - System-wide HTTPS connection monitoring
   - Webhook/API alerting for security teams

**Phase 5 - Advanced Security Features (Future):**
1. **Threat intelligence integration** - Enhanced detection capabilities:
   - Direct Certificate Transparency log queries for recent certificates
   - Malicious CA database integration (known-compromised authorities)
   - IoC feeds for known MITM infrastructure signatures
2. **Behavioral analysis enhancements** - Pattern recognition:
   - Cross-site certificate change correlation
   - Geographic anomaly detection in certificate issuance
   - Timing analysis for suspicious certificate patterns
3. **Privacy & forensics** - Professional security features:
   - Baseline certificate storage and comparison
   - Forensic reporting for security investigations
   - Risk scoring algorithms for MITM probability assessment

**Phase 6 - Integration & Usability (Future):**
1. **Platform integrations** - Broader ecosystem support:
   - Browser extension for real-time certificate warnings
   - SIEM integration via REST APIs and webhooks
   - CI/CD pipeline security validation
2. **Output formats & reporting** - Enhanced data presentation:
   - JSON/YAML output for programmatic consumption
   - Executive summary reports for compliance teams
   - Machine-readable threat indicators for automated processing
3. **Configuration & deployment** - Enterprise-ready features:
   - Configuration file support for custom endpoint lists
   - Corporate proxy support with authentication
   - Embedded CA bundle backup for air-gapped environments

## Common Enhancement Areas

When modifying this project, common tasks include:

1. **DPI vendor detection** - Adding patterns for new enterprise security vendors (current: 15+ vendors)
2. **Certificate validation enhancements** - New behavioral analysis indicators and CA impersonation patterns
3. **Output format options** - Additional formats like JSON, YAML, or direct JKS generation
4. **Testing improvements** - Expanding mock DPI scenarios and edge case coverage
5. **HawkScan integration** - Optimizing PEM format compatibility and usage examples
6. **Network reliability** - Enhancing corporate network detection and error guidance
7. **Cross-platform support** - Ensuring compatibility across Windows, macOS, Linux environments
8. **DPI testing infrastructure** - Expanding validation scripts and mock DPI environments

## Target Audience

### **Current Primary Users (Phase 1-3+)**
- **Java developers** dealing with corporate environments
- **StackHawk users** evaluating the scanner in corporate environments
- **DevOps/SRE teams** dealing with corporate security infrastructure  
- **Security teams** who need to configure certificate trust for Java applications
- **Security researchers** testing DPI detection capabilities in controlled environments
- **Developers** building and testing certificate validation tools

### **Potential Expanded Users (Phase 4-6)**
- **General users** on untrusted networks (coffee shops, airports, hotels, public WiFi)
- **Privacy-conscious individuals** wanting to verify connection integrity
- **Travelers** checking for network interception in foreign countries
- **Security professionals & penetration testers** validating network security
- **Security auditors** detecting unauthorized MITM devices on corporate networks
- **Bug bounty hunters** looking for network-level vulnerabilities
- **Compliance teams** in financial services, healthcare, and government
- **Network administrators** monitoring for rogue proxies and unauthorized surveillance
- **CI/CD security teams** ensuring build environments aren't compromised

## Integration Examples

The generated PEM file works with various Java tools:

**StackHawk:**
```bash
hawk scan --ca-bundle cypherhawk-certs.pem
```

**Java applications (PEM format - Java 9+):**
```bash
java -Djavax.net.ssl.trustStoreType=PEM -Djavax.net.ssl.trustStore=cypherhawk-certs.pem MyApp
```

**Java applications (JKS format - all Java versions):**
```bash
# Convert PEM to JKS format
keytool -importcert -noprompt -file cypherhawk-certs.pem -keystore cypherhawk.jks -storepass changeit -alias cypher-ca

# Use JKS with Java application
java -Djavax.net.ssl.trustStore=cypherhawk.jks -Djavax.net.ssl.trustStorePassword=changeit MyApp
```

**Maven (PEM format):**
```bash
mvn -Djavax.net.ssl.trustStoreType=PEM -Djavax.net.ssl.trustStore=cypherhawk-certs.pem clean install
```

**Maven (JKS format):**
```bash
mvn -Djavax.net.ssl.trustStore=cypherhawk.jks -Djavax.net.ssl.trustStorePassword=changeit clean install
```

**Gradle:**
```bash
./gradlew build -Djavax.net.ssl.trustStoreType=PEM -Djavax.net.ssl.trustStore=cypherhawk-certs.pem
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
- **Connection timeouts** - 10-second timeout per endpoint with clear error messages
- **Retry logic** - Exponential backoff with 3 attempts max for retryable errors
- **DNS resolution failures** - Graceful handling with specific corporate network guidance
- **Certificate parsing errors** - Continue processing other certificates, report parsing failures
- **HTTP errors** - Distinguish between network issues and HTTP status errors
- **Proxy support** - Enhanced proxy authentication and configuration error handling

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