# CypherHawk DPI Testing Guide

This guide explains how to create realistic test DPI environments for testing CypherHawk's detection capabilities.

## Overview

CypherHawk includes comprehensive test infrastructure for simulating various DPI/MitM scenarios, from legitimate corporate environments to malicious attacks.

## Test Infrastructure

### Running DPI Tests

```bash
# Test realistic corporate DPI environments
go test -v -run TestRealisticDPIEnvironments

# Test advanced DPI techniques
go test -v -run TestAdvancedDPITechniques

# Run all tests
go test -v
```

### Available Test Scenarios

#### 1. Realistic Corporate DPI Environments (`TestRealisticDPIEnvironments`)

Tests legitimate enterprise DPI solutions:

- **Palo Alto Networks**: Enterprise firewall with TLS inspection
- **Zscaler**: Cloud security platform with certificate inspection
- **Netskope**: Cloud access security broker
- **Generic Corporate**: Typical corporate DPI setup
- **Malicious DPI**: Suspicious/poorly configured DPI

#### 2. Advanced DPI Techniques (`TestAdvancedDPITechniques`)

Tests sophisticated DPI scenarios:

- **Certificate Chain Manipulation**: DPI that modifies intermediate certificates
- **SNI-based Certificate Swapping**: DPI that serves different certs based on SNI
- **Timing-based Detection Evasion**: DPI using realistic certificate lifetimes

## Creating Custom DPI Test Scenarios

### Basic DPI Simulation

```go
// Create a mock corporate CA
mockCA, mockCAKey := createRealisticDPICA(t, "YourCorp", "YourCorp Inc.", "YourCorp Root CA", DPIFeatures{
    hasCustomOIDs:     false,
    weakSignature:     false,
    suspiciousSerial:  false,
    recentIssuance:    true,
    longValidity:      true,
    corporateDomain:   "yourcorp.com",
    includesSCT:       false,
})

// Create server certificate signed by corporate CA
serverCert, serverKey := createServerCert(t, mockCA, mockCAKey)

// Start mock HTTPS server
server := createMockDPIServerWithCA(t, serverCert, serverKey, mockCA)
defer server.Close()

// Test CypherHawk detection
certs, err := network.GetCertificateChain(server.URL)
// ... perform detection tests
```

### DPI Feature Configuration

The `DPIFeatures` struct controls DPI characteristics:

```go
type DPIFeatures struct {
    hasCustomOIDs    bool   // Vendor-specific certificate extensions
    weakSignature    bool   // Use weak signature algorithms (SHA1)
    suspiciousSerial bool   // Use trivial serial numbers (1, 123, etc.)
    recentIssuance   bool   // Certificate issued recently
    longValidity     bool   // Certificate valid for 10+ years
    corporateDomain  string // Corporate domain for realistic naming
    includesSCT      bool   // Include Certificate Transparency evidence
}
```

### Real-World DPI Examples

#### Legitimate Corporate DPI (Should NOT be flagged as malicious)
```go
features := DPIFeatures{
    hasCustomOIDs:     false,
    weakSignature:     false,
    suspiciousSerial:  false,
    recentIssuance:    false, // Not recently issued
    longValidity:      true,  // Long validity is normal for corporate CAs
    corporateDomain:   "enterprise.com",
    includesSCT:       false, // Corporate CAs typically don't use public CT
}
```

#### Suspicious DPI (Should be flagged as malicious)
```go
features := DPIFeatures{
    hasCustomOIDs:     false,
    weakSignature:     true,  // Red flag: weak crypto
    suspiciousSerial:  true,  // Red flag: trivial serial
    recentIssuance:    true,  // Red flag: recently created
    longValidity:      false,
    corporateDomain:   "test.local",
    includesSCT:       false,
}
```

## Test Outputs

### Detection Results

Tests show detailed analysis of certificate chains:

```
=== RUN   TestRealisticDPIEnvironments/Palo_Alto_Networks
Testing Palo Alto Networks DPI simulation
Unknown CA detected: Palo Alto Networks Enterprise Root CA
✓ Palo Alto Networks DPI detection result correct: detected=false (CA suspicious count: 0)
CA-specific suspicious behaviors:
  - Certificate 1 (Palo Alto Networks Enterprise Root CA) issued within 24 hours (2h0m0s ago)
  - Certificate 1 (Palo Alto Networks Enterprise Root CA) hostname mismatch (cert: Palo Alto Networks Enterprise Root CA, expected: 127.0.0.1)
  - Certificate 1 (Palo Alto Networks Enterprise Root CA) is self-signed (leaf certificate)
```

### Security Analysis Features

The test framework validates:

- **Certificate Transparency**: Checks for SCT extensions in recent certificates
- **Behavioral Analysis**: Detects 10+ suspicious certificate indicators
- **CA Impersonation**: Identifies certificates falsely claiming to be from legitimate CAs
- **Chain Validation**: Browser-like certificate verification
- **Risk Scoring**: Combines multiple indicators for high-confidence detection

## Integration with CI/CD

Add to your CI pipeline:

```yaml
# .github/workflows/test.yml
- name: Test DPI Detection
  run: |
    go test -v -run TestRealisticDPIEnvironments
    go test -v -run TestAdvancedDPITechniques
```

## Test Artifacts

The `TestWithArtifacts` function creates actual certificate files for manual inspection:

```bash
go test -v -run TestWithArtifacts
# Creates:
# - test-artifacts-ca.pem (CA certificate)
# - test-artifacts-server.pem (Server certificate) 
# - test-artifacts-combined.pem (Full chain)
```

## Best Practices

1. **Test Realistic Scenarios**: Use corporate naming conventions and realistic validity periods
2. **Validate Detection Logic**: Ensure legitimate corporate DPI isn't flagged as malicious
3. **Test Edge Cases**: Include certificates with mixed suspicious/legitimate characteristics
4. **Monitor False Positives**: Corporate environments should be detected but not flagged as malicious
5. **Update Test Scenarios**: Add new DPI vendors and techniques as they emerge

## Extending the Framework

To add new DPI vendors or techniques:

1. Add new scenario to `TestRealisticDPIEnvironments`
2. Create appropriate `DPIFeatures` configuration
3. Implement custom certificate generation if needed
4. Add setup function to `TestAdvancedDPITechniques` for sophisticated techniques

This framework provides comprehensive testing for DPI detection across the spectrum from legitimate corporate security to malicious attacks.