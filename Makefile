# CypherHawk - Cross-platform build automation
.PHONY: build build-all clean test help install dev fmt fmt-check lint vet check pre-commit update-ca-bundle mod-download mod-tidy-check build-matrix build-release-binary create-checksum

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
pre-commit: fmt update-ca-bundle check test
	@echo "✅ Pre-commit checks completed successfully"

# Update CA bundle with latest Mozilla certificates
update-ca-bundle:
	@echo "Updating Mozilla CA bundle..."
	@./scripts/update-ca-bundle.sh

# Download Go dependencies
mod-download:
	@echo "Downloading Go dependencies..."
	@go mod download
	@echo "✅ Dependencies downloaded"

# Check if go mod tidy would make changes (CI-friendly)
mod-tidy-check:
	@echo "Checking go mod tidy..."
	@go mod tidy
	@CHANGES=$$(git diff --name-only); \
	if [ -n "$$CHANGES" ]; then \
		echo "❌ go mod tidy made changes to tracked files:"; \
		echo "$$CHANGES"; \
		git diff; \
		exit 1; \
	else \
		echo "✅ go mod tidy is clean - no changes to tracked files"; \
	fi

# Build binary for specific platform (used by CI matrix builds)
build-matrix:
	@echo "Building $(BINARY_NAME) for $(GOOS)/$(GOARCH)..."
	@if [ "$(GOOS)" = "windows" ]; then \
		EXT=".exe"; \
	else \
		EXT=""; \
	fi; \
	$(GOFLAGS) GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(LDFLAGS) -o $(BINARY_NAME)-$(GOOS)-$(GOARCH)$$EXT ./cmd/cypherhawk
	@echo "✅ Built $(BINARY_NAME)-$(GOOS)-$(GOARCH)"

# Build binary for release with custom suffix (used by release workflow)
build-release-binary:
	@echo "Building $(BINARY_NAME) for release ($(GOOS)/$(GOARCH))..."
	@LDFLAGS_TO_USE="$(LDFLAGS)"; \
	if [ -n "$(CUSTOM_LDFLAGS)" ]; then LDFLAGS_TO_USE="$(CUSTOM_LDFLAGS)"; fi; \
	$(GOFLAGS) GOOS=$(GOOS) GOARCH=$(GOARCH) go build $$LDFLAGS_TO_USE -o $(BINARY_NAME)-$(RELEASE_SUFFIX) ./cmd/cypherhawk
	@echo "✅ Built $(BINARY_NAME)-$(RELEASE_SUFFIX)"

# Create checksum for a specific binary
create-checksum:
	@echo "Creating checksum for $(BINARY_FILE)..."
	@sha256sum $(BINARY_FILE) > $(BINARY_FILE).sha256
	@echo "✅ Created checksum: $(BINARY_FILE).sha256"

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
test: update-ca-bundle
	@echo "🧪 Running comprehensive tests..."
	@go test -timeout=180s -count=1 ./... && echo "✅ All tests passed successfully" || (echo "❌ Tests failed" && exit 1)

# Run tests with coverage report (may be slower)
test-with-coverage: update-ca-bundle
	go test -v -timeout=300s -count=1 -race -coverprofile=coverage.out ./...
	@if [ -f coverage.out ] && [ -s coverage.out ]; then \
		echo "Generating coverage report..."; \
		go tool cover -html=coverage.out -o coverage.html; \
		echo "Coverage report: coverage.html"; \
	else \
		echo "No coverage data generated or file is empty"; \
	fi

# Run fast tests (skips network-dependent tests for development)
test-fast:
	CYPHERHAWK_SKIP_NETWORK_TESTS=1 go test -v -count=1 -short -timeout=60s ./...

# Run tests without race detector (if race detector causes issues)
test-basic: update-ca-bundle
	go test -v -timeout=180s -count=1 ./...
	@echo "✅ Basic tests completed"

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
	rm -f coverage.out
	rm -f coverage.html
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
	@echo "  make mod-download      Download Go dependencies"
	@echo "  make mod-tidy-check    Check if go mod tidy would make changes (CI-friendly)"
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
	@echo "CI/Release:"
	@echo "  make build-matrix        Build for specific platform (GOOS/GOARCH env vars)"
	@echo "  make build-release-binary Build with custom suffix (RELEASE_SUFFIX env var)"
	@echo "  make create-checksum     Create checksum for specific binary (BINARY_FILE env var)"
	@echo "  make checksums           Create SHA256 checksums for all binaries"
	@echo "  make package             Create release packages with checksums"
	@echo "  make verify              Verify all binaries execute correctly"
	@echo "  make help                Show this help"
	@echo ""
	@echo "Current version: $(VERSION)"
	@echo "Build time: $(BUILD_TIME)"
	@echo ""
	@echo "💡 Tip: Run 'make pre-commit' before pushing to ensure CI will pass"