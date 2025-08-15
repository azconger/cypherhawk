# DPI Hawk - Cross-platform build automation
.PHONY: build build-all clean test help install dev

# Build variables
BINARY_NAME := dpi-hawk
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -ldflags="-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"

# Go build flags
GOFLAGS := CGO_ENABLED=0

# Default target
all: build

# Development build (current platform)
build:
	@echo "Building DPI Hawk $(VERSION) for $(shell go env GOOS)/$(shell go env GOARCH)..."
	$(GOFLAGS) go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/dpi-hawk

# Development with verbose output
dev: build
	@echo "Running DPI Hawk in development mode..."
	./$(BINARY_NAME) --version
	./$(BINARY_NAME) --help

# Run tests
test:
	@echo "Running tests..."
	go test -v -race ./...

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME)-*
	rm -f *.pem
	rm -f test-artifacts-*.pem

# Install locally (for developers)
install:
	@echo "Installing DPI Hawk..."
	$(GOFLAGS) go install $(LDFLAGS) ./cmd/dpi-hawk

# Cross-platform builds
build-all: clean
	@echo "Building DPI Hawk $(VERSION) for all platforms..."
	
	# Linux builds
	@echo "Building for Linux AMD64..."
	GOOS=linux GOARCH=amd64 $(GOFLAGS) go build $(LDFLAGS) -o $(BINARY_NAME)-linux-amd64 ./cmd/dpi-hawk
	@echo "Building for Linux ARM64..."
	GOOS=linux GOARCH=arm64 $(GOFLAGS) go build $(LDFLAGS) -o $(BINARY_NAME)-linux-arm64 ./cmd/dpi-hawk
	
	# macOS builds
	@echo "Building for macOS AMD64..."
	GOOS=darwin GOARCH=amd64 $(GOFLAGS) go build $(LDFLAGS) -o $(BINARY_NAME)-macos-amd64 ./cmd/dpi-hawk
	@echo "Building for macOS ARM64 (Apple Silicon)..."
	GOOS=darwin GOARCH=arm64 $(GOFLAGS) go build $(LDFLAGS) -o $(BINARY_NAME)-macos-arm64 ./cmd/dpi-hawk
	
	# Windows builds
	@echo "Building for Windows AMD64..."
	GOOS=windows GOARCH=amd64 $(GOFLAGS) go build $(LDFLAGS) -o $(BINARY_NAME)-windows-amd64.exe ./cmd/dpi-hawk
	@echo "Building for Windows ARM64..."
	GOOS=windows GOARCH=arm64 $(GOFLAGS) go build $(LDFLAGS) -o $(BINARY_NAME)-windows-arm64.exe ./cmd/dpi-hawk
	
	@echo ""
	@echo "✅ Cross-platform builds completed:"
	@ls -la $(BINARY_NAME)-*

# Create checksums for all binaries
checksums: build-all
	@echo "Creating SHA256 checksums..."
	@for file in $(BINARY_NAME)-*; do \
		if [ -f "$$file" ]; then \
			sha256sum "$$file" > "$$file.sha256"; \
			echo "✓ Created checksum for $$file"; \
		fi \
	done

# Package releases (checksums + archives)
package: checksums
	@echo "Creating release packages..."
	@mkdir -p dist
	@for file in $(BINARY_NAME)-*; do \
		if [[ "$$file" != *.sha256 ]]; then \
			platform=$$(echo "$$file" | sed 's/$(BINARY_NAME)-//'); \
			echo "📦 Packaging $$platform..."; \
			tar -czf "dist/$$file.tar.gz" "$$file" "$$file.sha256"; \
		fi \
	done
	@echo ""
	@echo "✅ Release packages created in dist/:"
	@ls -la dist/

# Quick verification that all binaries work
verify: build-all
	@echo "Verifying all binaries..."
	@for file in $(BINARY_NAME)-*; do \
		if [[ "$$file" == *".exe" ]]; then \
			echo "⏭️  Skipping Windows binary verification on Unix"; \
		elif [[ "$$file" != *.sha256 ]]; then \
			echo "🔍 Testing $$file..."; \
			chmod +x "$$file"; \
			if ./$$file --version >/dev/null 2>&1; then \
				echo "✅ $$file - OK"; \
			else \
				echo "❌ $$file - FAILED"; \
			fi \
		fi \
	done

# Development workflow shortcuts
run: build
	./$(BINARY_NAME) --verbose

run-url: build
	./$(BINARY_NAME) --verbose -url https://www.google.com

# Show help
help:
	@echo "DPI Hawk Build System"
	@echo ""
	@echo "Usage:"
	@echo "  make build       Build for current platform"
	@echo "  make build-all   Build for all platforms (Linux, macOS, Windows × AMD64, ARM64)"
	@echo "  make test        Run all tests"
	@echo "  make clean       Clean build artifacts"
	@echo "  make install     Install locally (go install)"
	@echo "  make dev         Build and show version/help"
	@echo "  make run         Build and run with --verbose"
	@echo "  make run-url     Build and test against Google"
	@echo "  make checksums   Create SHA256 checksums for all binaries"
	@echo "  make package     Create release packages with checksums"
	@echo "  make verify      Verify all binaries execute correctly"
	@echo "  make help        Show this help"
	@echo ""
	@echo "Current version: $(VERSION)"
	@echo "Build time: $(BUILD_TIME)"