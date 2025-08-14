# MidCert - Claude Context

## Project Overview
MidCert is a Go CLI tool for defensive security that detects man-in-the-middle (MitM) deep packet inspection (DPI) proxies and extracts their CA certificates. It's designed to help Java applications that can't directly access the operating system's trusted certificates.

## Repository Structure
```
/
├── LICENSE              # MIT License
├── README.md           # Comprehensive documentation with usage examples
├── go.mod             # Go module file (Go 1.21)
├── main.go            # Main implementation (~135 lines)
├── main_test.go       # Unit tests with mock certificate generation
└── CLAUDE.md          # This file
```

## Key Technical Details

### Main Functionality (main.go)
- **Entry Point**: `main()` function handles CLI parsing and orchestrates the detection process
- **MitM Detection**: Compares certificate chains against Mozilla's CA bundle downloaded from `https://curl.se/ca/cacert.pem`
- **Certificate Extraction**: Extracts unknown CA certificates and outputs them in PEM format
- **Key Functions**:
  - Downloads Mozilla CA bundle (lines 23-40)
  - Creates HTTP client with `InsecureSkipVerify` to capture cert chains (lines 43-49)
  - Analyzes certificate chain for unknown CAs (lines 67-94)
  - Converts certificates to PEM format via `certToPEM()` (lines 129-135)

### Command Line Interface
- `-o <file>`: Output file for CA certificates (use `-` for stdout)
- `-url <url>`: Target URL to check (default: https://www.google.com)

### Testing (main_test.go)
- Comprehensive test that creates mock CA and server certificates
- Simulates MitM scenario by creating a test TLS server
- Validates that the tool correctly detects and extracts unknown CA certificates

## Code Quality
- **High quality**: Clean, well-structured Go code
- **Security focused**: Uses Mozilla's trusted CA bundle for validation
- **Well tested**: Sophisticated unit tests with certificate generation
- **Production ready**: Professional documentation and packaging

## Development Commands
```bash
# Run the tool
go run main.go

# Run with custom target
go run main.go -url https://example.com

# Save certificates to file
go run main.go -o midcerts.pem

# Run tests
go test -v

# Build binary
go build -o midcert main.go
```

## Use Cases
1. **Corporate Environments**: Detect and extract CA certificates from corporate proxies
2. **Java Applications**: Provide CA certificates for applications that can't access OS trust store
3. **Security Analysis**: Identify unexpected SSL interception in network environments
4. **CI/CD Integration**: Automate certificate extraction in deployment pipelines

## Security Considerations
- This is a **defensive security tool** - it helps identify and adapt to MitM proxies rather than create them
- Uses legitimate Mozilla CA bundle for trust validation
- Proper handling of TLS configuration for certificate inspection
- No external dependencies beyond Go standard library