#!/bin/bash
set -euo pipefail

# Update CA Bundle Script for CypherHawk
# Downloads the latest Mozilla CA bundle at build time to ensure fresh certificates

CA_BUNDLE_DIR="internal/bundle/embedded"
CA_BUNDLE_FILE="$CA_BUNDLE_DIR/cacert.pem"
TEMP_FILE="/tmp/cacert.pem.tmp"

# Primary Mozilla CA bundle source
PRIMARY_URL="https://curl.se/ca/cacert.pem"
# Backup source
BACKUP_URL="https://raw.githubusercontent.com/bagder/ca-bundle/master/ca-bundle.crt"

echo "🔄 Updating Mozilla CA bundle for build-time embedding..."

# Create directory if it doesn't exist
mkdir -p "$CA_BUNDLE_DIR"

# Function to download and validate a CA bundle
download_and_validate() {
    local url="$1"
    local description="$2"
    
    echo "📥 Downloading from $description: $url"
    
    # Download with timeout and retry
    if curl -f -L --max-time 30 --retry 3 --retry-delay 2 -o "$TEMP_FILE" "$url"; then
        # Basic validation - check it's a PEM file with certificates
        if grep -q "BEGIN CERTIFICATE" "$TEMP_FILE" && grep -q "END CERTIFICATE" "$TEMP_FILE"; then
            local cert_count=$(grep -c "BEGIN CERTIFICATE" "$TEMP_FILE")
            echo "✅ Downloaded valid CA bundle with $cert_count certificates"
            return 0
        else
            echo "❌ Downloaded file doesn't appear to be a valid PEM CA bundle"
            return 1
        fi
    else
        echo "❌ Failed to download from $description"
        return 1
    fi
}

# Try primary source first
if download_and_validate "$PRIMARY_URL" "curl.se (primary)"; then
    echo "✅ Successfully downloaded from primary source"
elif download_and_validate "$BACKUP_URL" "GitHub mirror (backup)"; then
    echo "✅ Successfully downloaded from backup source"
else
    echo "❌ Failed to download CA bundle from any source"
    echo "⚠️  Using existing embedded bundle (may be stale)"
    if [ ! -f "$CA_BUNDLE_FILE" ]; then
        echo "❌ No existing CA bundle found and unable to download"
        echo "   Build will likely fail"
        exit 1
    fi
    exit 0
fi

# Verify the downloaded bundle is newer/different than existing
if [ -f "$CA_BUNDLE_FILE" ]; then
    if cmp -s "$TEMP_FILE" "$CA_BUNDLE_FILE"; then
        echo "ℹ️  Downloaded bundle is identical to existing embedded bundle"
    else
        echo "🔄 Downloaded bundle differs from existing - updating embedded bundle"
    fi
else
    echo "📦 Creating new embedded CA bundle (no existing bundle found)"
fi

# Move the validated bundle into place
mv "$TEMP_FILE" "$CA_BUNDLE_FILE"

# Add build timestamp comment to the file
{
    echo "##"
    echo "## CypherHawk - Mozilla CA Bundle"
    echo "## Downloaded at build time: $(date -u)"
    echo "## Source: $PRIMARY_URL"
    echo "##"
    echo ""
    cat "$CA_BUNDLE_FILE"
} > "$TEMP_FILE"

mv "$TEMP_FILE" "$CA_BUNDLE_FILE"

# Show statistics
cert_count=$(grep -c "BEGIN CERTIFICATE" "$CA_BUNDLE_FILE")
file_size=$(wc -c < "$CA_BUNDLE_FILE" | tr -d ' ')

echo ""
echo "✅ CA bundle successfully updated:"
echo "   📁 File: $CA_BUNDLE_FILE"
echo "   📊 Certificates: $cert_count"
echo "   📏 Size: $file_size bytes"
echo "   🕒 Updated: $(date -u)"
echo ""
echo "🔨 Ready for build - embedded CA bundle is fresh!"