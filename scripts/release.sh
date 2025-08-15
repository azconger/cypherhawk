#!/bin/bash

# DPI Hawk Release Script
# Creates a new release with proper versioning and cross-platform builds

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if version is provided
if [ $# -eq 0 ]; then
    log_error "Please provide a version number"
    echo "Usage: $0 <version>"
    echo "Example: $0 v1.0.0"
    exit 1
fi

VERSION=$1

# Validate version format
if [[ ! $VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+)?$ ]]; then
    log_error "Invalid version format. Use semantic versioning (e.g., v1.0.0)"
    exit 1
fi

log_info "Creating release $VERSION for DPI Hawk"

# Check if we're on a clean git state
if [[ -n $(git status --porcelain) ]]; then
    log_warning "Working directory has uncommitted changes"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Release cancelled"
        exit 1
    fi
fi

# Check if tag already exists
if git rev-parse "$VERSION" >/dev/null 2>&1; then
    log_error "Tag $VERSION already exists"
    exit 1
fi

# Run tests first
log_info "Running tests..."
if ! go test -v ./...; then
    log_error "Tests failed. Fix tests before releasing."
    exit 1
fi
log_success "All tests passed"

# Build all platforms
log_info "Building cross-platform binaries..."
if ! make build-all; then
    log_error "Cross-platform build failed"
    exit 1
fi
log_success "Cross-platform builds completed"

# Create checksums
log_info "Creating checksums..."
if ! make checksums; then
    log_error "Checksum creation failed"
    exit 1
fi
log_success "Checksums created"

# Show what we built
log_info "Built binaries:"
ls -la dpi-hawk-*

# Verify binaries
log_info "Verifying binaries..."
if ! make verify; then
    log_warning "Some binary verification failed, but continuing..."
else
    log_success "All binaries verified successfully"
fi

# Create and push tag
log_info "Creating git tag $VERSION..."
git tag -a "$VERSION" -m "Release $VERSION"
log_success "Tag created locally"

# Ask before pushing
echo
log_info "Ready to push tag and trigger release"
echo "This will:"
echo "  1. Push the tag to GitHub"
echo "  2. Trigger GitHub Actions release workflow"
echo "  3. Create a GitHub release with all binaries"
echo
read -p "Push tag and create release? (y/N): " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    log_info "Pushing tag to GitHub..."
    git push origin "$VERSION"
    log_success "Tag pushed successfully"
    
    echo
    log_success "Release $VERSION initiated!"
    log_info "Check GitHub Actions: https://github.com/kaakaww/dpi-hawk/actions"
    log_info "Release will be available at: https://github.com/kaakaww/dpi-hawk/releases/tag/$VERSION"
else
    log_info "Release cancelled. Tag created locally but not pushed."
    log_info "To clean up: git tag -d $VERSION"
fi

# Clean up local build artifacts
log_info "Cleaning up local build artifacts..."
make clean >/dev/null 2>&1 || true
log_success "Cleanup completed"

echo
log_success "Release script completed!"