# CypherHawk - Build and Release Guide

This document describes how to build, test, and release CypherHawk across multiple platforms.

## Quick Start

### Prerequisites
- Go 1.21 or later
- Git
- Make (for convenience scripts)

### Development Build
```bash
# Clone and build
git clone https://github.com/kaakaww/cypherhawk.git
cd cypherhawk
make build

# Test it works
./cypherhawk --version
./cypherhawk --help
```

## Build System

### Local Development
```bash
make build          # Build for current platform
make test           # Run all tests
make run            # Build and run with --verbose
make run-url        # Test against Google
make clean          # Clean build artifacts
```

### Cross-Platform Builds
```bash
make build-all      # Build for all 6 platforms
make checksums      # Create SHA256 checksums
make verify         # Test all binaries execute
make package        # Create release archives
```

### Supported Platforms
- **Linux**: AMD64, ARM64
- **macOS**: AMD64 (Intel), ARM64 (Apple Silicon)  
- **Windows**: AMD64, ARM64

## Release Process

### Automated Releases (Recommended)

1. **Create and push a version tag:**
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

2. **GitHub Actions automatically:**
   - Builds for all 6 platforms
   - Runs tests on Linux, macOS, Windows
   - Creates GitHub release with binaries
   - Generates checksums and release notes

### Manual Release Script

```bash
# Interactive release script
./scripts/release.sh v1.0.0
```

This script will:
- Run tests
- Build all platforms
- Create checksums
- Create and push git tag
- Trigger GitHub Actions

### Manual Release Steps

1. **Prepare release:**
   ```bash
   # Ensure clean working directory
   git status
   
   # Run tests
   make test
   
   # Build all platforms
   make build-all
   make checksums
   ```

2. **Create release:**
   ```bash
   # Tag the release
   git tag -a v1.0.0 -m "Release v1.0.0"
   git push origin v1.0.0
   ```

3. **Upload to GitHub:**
   - Go to [Releases](https://github.com/kaakaww/cypherhawk/releases)
   - Click "Create a new release"
   - Upload all `cypherhawk-*` binaries and `.sha256` files

## Distribution

### For End Users

**Linux/macOS:**
```bash
# Download and install
curl -L -o cypherhawk https://github.com/kaakaww/cypherhawk/releases/latest/download/cypherhawk-linux-amd64
chmod +x cypherhawk
./cypherhawk --help
```

**Windows:**
```powershell
# Download cypherhawk-windows-amd64.exe from releases
# Run from Command Prompt or PowerShell
.\cypherhawk-windows-amd64.exe --help
```

**Go developers:**
```bash
go install github.com/kaakaww/cypherhawk/cmd/cypherhawk@latest
```

### Verification
```bash
# Verify checksum
sha256sum -c cypherhawk-linux-amd64.sha256

# Test functionality
./cypherhawk --version
./cypherhawk --verbose -url https://www.google.com
```

## CI/CD Workflows

### Build Workflow (`.github/workflows/build.yml`)
- **Triggers**: Push to main/develop, pull requests
- **Actions**: Test, lint, build matrix, integration tests
- **Platforms**: Builds and tests on Linux, macOS, Windows

### Release Workflow (`.github/workflows/release.yml`)
- **Triggers**: Version tags (`v*`), manual workflow dispatch
- **Actions**: Build all platforms, create GitHub release
- **Artifacts**: 6 binaries + checksums + release notes

## Build Configuration

### Version Information
Version and build time are embedded at compile time:
```bash
go build -ldflags="-X main.version=v1.0.0 -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

### Build Optimizations
- `CGO_ENABLED=0` - Static binaries, no C dependencies
- `-ldflags="-s -w"` - Strip debug info, reduce binary size
- Cross-compilation for all major platforms

## Troubleshooting

### Common Issues

**Build fails on missing dependencies:**
```bash
go mod download
go mod tidy
```

**Tests fail:**
```bash
# Run with verbose output
go test -v ./...

# Run specific test
go test -v -run TestSpecificFunction
```

**Cross-compilation issues:**
```bash
# Check Go environment
go env GOOS GOARCH

# Force clean build
make clean
make build-all
```

### Platform-Specific Notes

**macOS:**
- ARM64 binaries work on Apple Silicon (M1/M2)
- AMD64 binaries work on Intel Macs via Rosetta

**Windows:**
- ARM64 support requires Windows 11 on ARM
- AMD64 works on all Windows 10/11 systems

**Linux:**
- Static binaries work on any Linux distribution
- ARM64 supports Raspberry Pi, AWS Graviton, etc.

## Security

### Binary Verification
All releases include SHA256 checksums:
```bash
# Verify download integrity
sha256sum -c cypherhawk-linux-amd64.sha256
```

### Reproducible Builds
- Deterministic build flags
- No external dependencies
- Version information embedded at build time
- Clean, minimal attack surface