# DPI Hawk - Claude Code Context

## Project Overview

CLI utility to detect corporate Deep Packet Inspection (DPI) firewalls and extract CA certificates for Java applications and security tools. Targets Palo Alto Networks, Netskope, Zscaler, and other DPI environments commonly found in enterprise settings.

Built by StackHawk but designed for the broader Java ecosystem including Maven, Gradle, Spring Boot applications, and other security tools.

## Project Type
- Language: Go
- Type: CLI application
- Distribution: Single static binary (no dependencies)

## Build Commands

```bash
# Development
make build          # Build for current platform
make run ARGS="--debug"  # Run with debug mode
go test -v ./...    # Run tests

# Cross-platform builds
make build-all      # Build for all platforms
make package        # Create release archives
make clean          # Clean build artifacts
```

## Development Workflow

1. Use `make run ARGS="--debug"` for testing during development
2. Use `make build` to create local binary for testing
3. Use `make build-all` for cross-platform binaries
4. Test against various corporate environments when possible

## Architecture & Design Decisions

### Core Principles
- **Zero external dependencies** - Uses only Go standard library for easy distribution
- **Single binary** - Customers can download and run immediately
- **Cross-platform** - Supports Linux, macOS, Windows (AMD64/ARM64)
- **Enterprise-focused** - Designed for corporate environments with DPI

### Key Components
- **Certificate detection** - Compares received vs expected certificate chains
- **DPI vendor identification** - Recognizes major enterprise security vendors
- **PEM extraction** - Outputs CA certificates in format StackHawk scanner expects
- **Default endpoints** - Tests actual StackHawk required services

## Key Files

| File | Purpose |
|------|---------|
| `main.go` | Main CLI application with certificate detection and extraction logic |
| `go.mod` | Go module definition - intentionally no external dependencies |
| `Makefile` | Cross-platform build automation and packaging |
| `README.md` | User documentation and usage examples |
| `.github/workflows/build.yml` | Automated testing and release building |

## Testing Strategy

### Default Test Endpoints
- `auth.stackhawk.com` - StackHawk authentication service
- `api.stackhawk.com` - StackHawk API endpoint
- `s3.us-west-2.amazonaws.com` - AWS S3 (for pre-signed URLs)

### DPI Detection
- Identifies certificates from major vendors (Palo Alto, Netskope, Zscaler, etc.)
- Uses certificate chain analysis and issuer pattern matching
- Handles certificate deduplication across multiple endpoints

## Common Enhancement Areas

When modifying this project, common tasks include:

1. **Adding DPI vendor detection** - New patterns in `isIntercepted()` function
2. **Certificate validation improvements** - Enhanced chain analysis logic
3. **New command line options** - Additional flags for specific use cases
4. **Error handling** - Better network connectivity and timeout handling
5. **Proxy support** - Corporate environments often use proxies
6. **Output formats** - Alternative certificate bundle formats if needed

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

**Java applications:**
```bash
java -Djavax.net.ssl.trustStore=dpi-hawk-certs.pem MyApp
```

**Maven:**
```bash
mvn -Djavax.net.ssl.trustStore=dpi-hawk-certs.pem clean install
```

## Deployment Considerations

- GitHub Actions automatically builds releases on version tags
- No installation required - single binary distribution
- Works in air-gapped environments (no external dependencies)
- Minimal resource requirements for customer systems