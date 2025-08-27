#!/bin/bash
set -e

echo "🚀 Starting Squid DPI proxy with SSL bumping..."

# Initialize SSL certificate database if not exists
if [ ! -f /var/lib/squid/ssl_db/index.txt ]; then
    echo "🔧 Initializing SSL certificate database..."
    /usr/lib/squid/security_file_certgen -c -s /var/lib/squid/ssl_db -M 4MB
    chown -R proxy:proxy /var/lib/squid/ssl_db
fi

# Generate corporate CA certificate if not exists
if [ ! -f /etc/squid/certs/corporate-ca.pem ]; then
    echo "🔐 Generating corporate CA certificate..."
    
    # Generate private key
    openssl genrsa -out /etc/squid/certs/corporate-ca-key.pem 2048
    
    # Generate CA certificate
    openssl req -new -x509 -key /etc/squid/certs/corporate-ca-key.pem \
        -out /etc/squid/certs/corporate-ca-cert.pem \
        -days 3650 \
        -subj "/C=US/ST=CA/L=San Francisco/O=Acme Corporation/CN=Acme Corporate Proxy CA"
    
    # Combine certificate and key for Squid
    cat /etc/squid/certs/corporate-ca-cert.pem /etc/squid/certs/corporate-ca-key.pem > /etc/squid/certs/corporate-ca.pem
    
    # Set permissions
    chown proxy:proxy /etc/squid/certs/*
    chmod 600 /etc/squid/certs/corporate-ca-key.pem
    chmod 644 /etc/squid/certs/corporate-ca-cert.pem
    chmod 600 /etc/squid/certs/corporate-ca.pem
    
    echo "✅ Corporate CA certificate generated"
fi

# Create Squid configuration if not exists
if [ ! -f /etc/squid/squid.conf ]; then
    echo "📝 Creating Squid configuration..."
    cat > /etc/squid/squid.conf << 'EOF'
# Squid DPI Configuration for CypherHawk Testing
# This simulates corporate DPI/proxy behavior

# SSL Bump configuration
http_port 3128 ssl-bump \
    cert=/etc/squid/certs/corporate-ca.pem \
    generate-host-certificates=on \
    dynamic_cert_mem_cache_size=4MB

# SSL database
sslcrtd_program /usr/lib/squid/security_file_certgen -s /var/lib/squid/ssl_db -M 4MB

# SSL bump rules
acl step1 at_step SslBump1
acl step2 at_step SslBump2
acl step3 at_step SslBump3

# Bump all HTTPS traffic to simulate corporate DPI
ssl_bump peek step1
ssl_bump bump step2
ssl_bump bump step3

# Allow all traffic (testing environment)
acl CONNECT method CONNECT
acl SSL_ports port 443
acl Safe_ports port 80          # http
acl Safe_ports port 21          # ftp
acl Safe_ports port 443         # https
acl Safe_ports port 70          # gopher
acl Safe_ports port 210         # wais
acl Safe_ports port 1025-65535  # unregistered ports
acl Safe_ports port 280         # http-mgmt
acl Safe_ports port 488         # gss-http
acl Safe_ports port 591         # filemaker
acl Safe_ports port 777         # multiling http
acl CONNECT method CONNECT

# Access rules
http_access allow all

# Logging
access_log /var/log/squid/access.log squid
cache_log /var/log/squid/cache.log

# Cache configuration (minimal for testing)
cache_mem 64 MB
cache_dir ufs /var/spool/squid 1000 16 256

# DNS
dns_nameservers 8.8.8.8 8.8.4.4

# Error page customization
error_directory /usr/share/squid/errors/English

# Process settings
workers 1
EOF
fi

echo "📋 Squid configuration:"
echo "   - HTTP/HTTPS Proxy: 0.0.0.0:3128"
echo "   - Corporate CA: /etc/squid/certs/corporate-ca-cert.pem"
echo "   - SSL Database: /var/lib/squid/ssl_db"
echo ""

# Test configuration
echo "🧪 Testing Squid configuration..."
squid -k parse

# Start Squid
echo "✅ Starting Squid proxy server..."
exec squid -N -d 1