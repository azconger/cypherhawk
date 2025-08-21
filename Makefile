# CypherHawk - Cross-platform build automation
.PHONY: build build-all clean test help install dev fmt fmt-check lint vet check pre-commit update-ca-bundle

# Build variables
BINARY_NAME := cypherhawk
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -ldflags="-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"

# Go build flags
GOFLAGS := CGO_ENABLED=0

# Default target
all: check build

# Format Go code
fmt:
	@echo "Formatting Go code..."
	@gofmt -s -w .
	@echo "✅ Code formatted"

# Check if code is formatted (CI-friendly)
fmt-check:
	@echo "Checking Go code formatting..."
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "❌ The following files are not formatted:"; \
		echo "$$unformatted"; \
		echo ""; \
		echo "Run 'make fmt' to fix formatting issues"; \
		exit 1; \
	fi
	@echo "✅ All files are properly formatted"

# Run go vet
vet:
	@echo "Running go vet..."
	@go vet ./...
	@echo "✅ go vet passed"

# Run staticcheck (if available)
lint:
	@echo "Running staticcheck..."
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
		echo "✅ staticcheck passed"; \
	else \
		echo "⚠️  staticcheck not installed, skipping (install with: go install honnef.co/go/tools/cmd/staticcheck@latest)"; \
	fi

# Comprehensive checks (formatting, vetting, linting)
check: fmt-check vet lint
	@echo "✅ All checks passed"

# Pre-commit hook (runs checks + tests)
pre-commit: check test
	@echo "✅ Pre-commit checks completed successfully"

# Update CA bundle with latest Mozilla certificates
update-ca-bundle:
	@echo "Updating Mozilla CA bundle..."
	@./scripts/update-ca-bundle.sh

# Development build (current platform)
build: update-ca-bundle check
	@echo "Building CypherHawk $(VERSION) for $(shell go env GOOS)/$(shell go env GOARCH)..."
	$(GOFLAGS) go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/cypherhawk

# Development with verbose output
dev: build
	@echo "Running CypherHawk in development mode..."
	./$(BINARY_NAME) --version
	./$(BINARY_NAME) --help

# Run tests (default - includes all important tests)
test:
	go test -v -count=1 -timeout=120s ./...

# Run fast tests (skips network-dependent tests for development)
test-fast:
	CYPHERHAWK_SKIP_NETWORK_TESTS=1 go test -v -count=1 -short -timeout=60s ./...

# Run tests without network dependencies (CI-friendly)
test-ci:
	CYPHERHAWK_SKIP_NETWORK_TESTS=1 go test -v -count=1 -short -race -timeout=120s ./...

# Run tests with enhanced output for development
test-watch:
	@echo "🧪 Running tests with real-time output (Ctrl+C to stop)..."
	go test -v -count=1 -timeout=120s ./... | tee test-output.log

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME)-*
	rm -f *.pem
	rm -f test-artifacts-*.pem
	rm -f internal/bundle/embedded/cacert.pem
	rm -f test-output.log
	rm -f output.txt
	rm -f errors.txt
	@echo "✅ Build artifacts cleaned (including embedded CA bundle for fresh download)"

# Install locally (for developers)
install:
	@echo "Installing CypherHawk..."
	$(GOFLAGS) go install $(LDFLAGS) ./cmd/cypherhawk

# Cross-platform builds
build-all: update-ca-bundle check clean
	@echo "Building CypherHawk $(VERSION) for all platforms..."
	
	# Linux builds
	@echo "Building for Linux AMD64..."
	GOOS=linux GOARCH=amd64 $(GOFLAGS) go build $(LDFLAGS) -o $(BINARY_NAME)-linux-amd64 ./cmd/cypherhawk
	@echo "Building for Linux ARM64..."
	GOOS=linux GOARCH=arm64 $(GOFLAGS) go build $(LDFLAGS) -o $(BINARY_NAME)-linux-arm64 ./cmd/cypherhawk
	
	# macOS builds
	@echo "Building for macOS AMD64..."
	GOOS=darwin GOARCH=amd64 $(GOFLAGS) go build $(LDFLAGS) -o $(BINARY_NAME)-macos-amd64 ./cmd/cypherhawk
	@echo "Building for macOS ARM64 (Apple Silicon)..."
	GOOS=darwin GOARCH=arm64 $(GOFLAGS) go build $(LDFLAGS) -o $(BINARY_NAME)-macos-arm64 ./cmd/cypherhawk
	
	# Windows builds
	@echo "Building for Windows AMD64..."
	GOOS=windows GOARCH=amd64 $(GOFLAGS) go build $(LDFLAGS) -o $(BINARY_NAME)-windows-amd64.exe ./cmd/cypherhawk
	@echo "Building for Windows ARM64..."
	GOOS=windows GOARCH=arm64 $(GOFLAGS) go build $(LDFLAGS) -o $(BINARY_NAME)-windows-arm64.exe ./cmd/cypherhawk
	
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
	@echo "CypherHawk Build System"
	@echo ""
	@echo "Code Quality:"
	@echo "  make fmt               Format Go code with gofmt"
	@echo "  make fmt-check         Check if code is formatted (CI-friendly)"
	@echo "  make vet               Run go vet"
	@echo "  make lint              Run staticcheck (if installed)"
	@echo "  make check             Run all code quality checks (fmt-check + vet + lint)"
	@echo "  make pre-commit        Run all checks + tests (recommended before commits)"
	@echo "  make update-ca-bundle  Download latest Mozilla CA bundle for embedding"
	@echo ""
	@echo "Build & Test:"
	@echo "  make build       Build for current platform (includes checks)"
	@echo "  make build-all   Build for all platforms (includes checks)"
	@echo "  make test        Run all tests with real-time output (includes network tests)"
	@echo "  make test-fast   Run fast tests with real-time output (skips network tests)"
	@echo "  make test-watch  Run tests with enhanced real-time output and logging"
	@echo "  make test-ci     Run CI tests (no network dependencies)"
	@echo "  make clean       Clean build artifacts (forces fresh CA bundle download)"
	@echo "  make install     Install locally (go install)"
	@echo ""
	@echo "Development:"
	@echo "  make dev         Build and show version/help"
	@echo "  make run         Build and run with --verbose"
	@echo "  make run-url     Build and test against Google"
	@echo ""
	@echo "Release:"
	@echo "  make checksums   Create SHA256 checksums for all binaries"
	@echo "  make package     Create release packages with checksums"
	@echo "  make verify      Verify all binaries execute correctly"
	@echo "  make help        Show this help"
	@echo ""
	@echo "Current version: $(VERSION)"
	@echo "Build time: $(BUILD_TIME)"
	@echo ""
	@echo "💡 Tip: Run 'make pre-commit' before pushing to ensure CI will pass"