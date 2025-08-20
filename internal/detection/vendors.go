package detection

import (
	"crypto/x509"
	"regexp"
	"strings"
)

// VendorMatch represents a detected DPI vendor with confidence scoring
type VendorMatch struct {
	Vendor      string            // Vendor name (e.g., "Palo Alto Networks")
	Product     string            // Specific product if identifiable
	Version     string            // Version information if available
	Confidence  int               // Confidence score (0-100)
	Indicators  []string          // List of detection indicators found
	Guidance    string            // HawkScan-specific configuration guidance
	Certificate *x509.Certificate // The certificate that triggered this match
}

// VendorPattern defines detection patterns for a specific DPI vendor
type VendorPattern struct {
	Name                 string
	Product              string
	SubjectPatterns      []string          // Regex patterns for certificate subject
	IssuerPatterns       []string          // Regex patterns for certificate issuer
	OrganizationPatterns []string          // Patterns for organization field
	ValidityPatterns     []ValidityPattern // Typical validity periods
	KeyUsagePatterns     []x509.KeyUsage   // Expected key usage patterns
	SerialPatterns       []string          // Serial number patterns
	Guidance             string            // HawkScan integration guidance
}

// ValidityPattern defines expected certificate validity characteristics
type ValidityPattern struct {
	MinDays     int
	MaxDays     int
	Description string
}

// knownVendors contains comprehensive patterns for major DPI vendors
var knownVendors = []VendorPattern{
	{
		Name:    "Palo Alto Networks",
		Product: "PAN-OS Next-Generation Firewall",
		SubjectPatterns: []string{
			`(?i)palo\s*alto`,
			`(?i)pan-\w+`,
			`(?i)PA-\d+`,
		},
		IssuerPatterns: []string{
			`(?i)palo\s*alto`,
			`(?i)pan[\s-]?ca`,
		},
		OrganizationPatterns: []string{
			`(?i)palo\s*alto\s*networks`,
		},
		ValidityPatterns: []ValidityPattern{
			{MinDays: 365, MaxDays: 365, Description: "Default 1-year validity"},
			{MinDays: 730, MaxDays: 730, Description: "2-year validity"},
		},
		KeyUsagePatterns: []x509.KeyUsage{
			x509.KeyUsageDigitalSignature,
			x509.KeyUsageKeyEncipherment,
		},
		SerialPatterns: []string{
			`^[0-9A-F]{16,32}$`, // Hex format
		},
		Guidance: "Extract CA certificate for HawkScan --ca-bundle. Check PAN-OS SSL/TLS Service Profile configuration.",
	},
	{
		Name:    "Zscaler",
		Product: "Zscaler Internet Access (ZIA)",
		SubjectPatterns: []string{
			`(?i)zscaler`,
			`(?i)zs(ca|ia)`,
			`(?i)zia[\s-]?ca`,
		},
		IssuerPatterns: []string{
			`(?i)zscaler`,
			`(?i)zs[\s-]?root`,
			`(?i)zia[\s-]?root`,
		},
		OrganizationPatterns: []string{
			`(?i)zscaler\s*inc`,
			`(?i)zscaler`,
		},
		ValidityPatterns: []ValidityPattern{
			{MinDays: 90, MaxDays: 90, Description: "Zscaler default 90-day rotation"},
			{MinDays: 365, MaxDays: 365, Description: "Annual certificate"},
		},
		KeyUsagePatterns: []x509.KeyUsage{
			x509.KeyUsageDigitalSignature,
			x509.KeyUsageCertSign,
		},
		Guidance: "Extract Zscaler CA for HawkScan. Verify Zscaler client connector and SSL inspection settings.",
	},
	{
		Name:    "Netskope",
		Product: "Netskope Security Cloud",
		SubjectPatterns: []string{
			`(?i)netskope`,
			`(?i)ns[\s-]?ca`,
			`(?i)netskope[\s-]?ca`,
		},
		IssuerPatterns: []string{
			`(?i)netskope`,
			`(?i)ns[\s-]?root`,
		},
		OrganizationPatterns: []string{
			`(?i)netskope\s*inc`,
			`(?i)netskope`,
		},
		ValidityPatterns: []ValidityPattern{
			{MinDays: 365, MaxDays: 365, Description: "Standard 1-year validity"},
		},
		KeyUsagePatterns: []x509.KeyUsage{
			x509.KeyUsageDigitalSignature,
			x509.KeyUsageKeyEncipherment,
		},
		Guidance: "Extract Netskope CA for HawkScan. Check Netskope client configuration and SSL decryption policies.",
	},
	{
		Name:    "Forcepoint",
		Product: "Forcepoint Web Security",
		SubjectPatterns: []string{
			`(?i)forcepoint`,
			`(?i)websense`, // Legacy Websense branding
			`(?i)fp[\s-]?ca`,
		},
		IssuerPatterns: []string{
			`(?i)forcepoint`,
			`(?i)websense`,
			`(?i)fp[\s-]?root`,
		},
		OrganizationPatterns: []string{
			`(?i)forcepoint`,
			`(?i)websense`,
		},
		ValidityPatterns: []ValidityPattern{
			{MinDays: 365, MaxDays: 730, Description: "1-2 year validity typical"},
		},
		Guidance: "Extract Forcepoint CA for HawkScan. Verify HTTPS inspection configuration in Forcepoint policy.",
	},
	{
		Name:    "Cisco BlueCoat",
		Product: "ProxySG / Web Security Appliance",
		SubjectPatterns: []string{
			`(?i)bluecoat`,
			`(?i)cisco`,
			`(?i)proxysg`,
			`(?i)wsa[\s-]?ca`,
		},
		IssuerPatterns: []string{
			`(?i)bluecoat`,
			`(?i)proxysg`,
			`(?i)cisco[\s-]?ca`,
		},
		OrganizationPatterns: []string{
			`(?i)blue\s*coat`,
			`(?i)cisco\s*systems`,
		},
		ValidityPatterns: []ValidityPattern{
			{MinDays: 365, MaxDays: 1095, Description: "1-3 year validity range"},
		},
		Guidance: "Extract BlueCoat/Cisco CA for HawkScan. Check ProxySG SSL inspection and certificate management.",
	},
	{
		Name:    "McAfee Web Gateway",
		Product: "McAfee Web Gateway (MWG)",
		SubjectPatterns: []string{
			`(?i)mcafee`,
			`(?i)mwg[\s-]?ca`,
			`(?i)web[\s-]?gateway`,
		},
		IssuerPatterns: []string{
			`(?i)mcafee`,
			`(?i)mwg[\s-]?root`,
		},
		OrganizationPatterns: []string{
			`(?i)mcafee`,
		},
		ValidityPatterns: []ValidityPattern{
			{MinDays: 365, MaxDays: 730, Description: "1-2 year validity"},
		},
		Guidance: "Extract McAfee CA for HawkScan. Verify MWG HTTPS scanning rule configuration.",
	},
	{
		Name:    "Symantec ProxySG",
		Product: "Symantec ProxySG",
		SubjectPatterns: []string{
			`(?i)symantec`,
			`(?i)proxysg`,
			`(?i)broadcom`, // New ownership
		},
		IssuerPatterns: []string{
			`(?i)symantec`,
			`(?i)proxysg[\s-]?root`,
		},
		OrganizationPatterns: []string{
			`(?i)symantec`,
			`(?i)broadcom`,
		},
		ValidityPatterns: []ValidityPattern{
			{MinDays: 365, MaxDays: 1095, Description: "1-3 year validity"},
		},
		Guidance: "Extract Symantec CA for HawkScan. Check ProxySG SSL intercept configuration.",
	},
	{
		Name:    "Checkpoint",
		Product: "Check Point Security Gateway",
		SubjectPatterns: []string{
			`(?i)check\s*point`,
			`(?i)checkpoint`,
			`(?i)cp[\s-]?ca`,
		},
		IssuerPatterns: []string{
			`(?i)check\s*point`,
			`(?i)checkpoint`,
		},
		OrganizationPatterns: []string{
			`(?i)check\s*point`,
		},
		ValidityPatterns: []ValidityPattern{
			{MinDays: 365, MaxDays: 365, Description: "Annual certificate renewal"},
		},
		Guidance: "Extract Check Point CA for HawkScan. Verify HTTPS Inspection blade configuration.",
	},
	{
		Name:    "Fortinet FortiGate",
		Product: "FortiGate Next-Generation Firewall",
		SubjectPatterns: []string{
			`(?i)fortinet`,
			`(?i)fortigate`,
			`(?i)forti[\s-]?ca`,
		},
		IssuerPatterns: []string{
			`(?i)fortinet`,
			`(?i)forti[\s-]?root`,
		},
		OrganizationPatterns: []string{
			`(?i)fortinet`,
		},
		ValidityPatterns: []ValidityPattern{
			{MinDays: 365, MaxDays: 1095, Description: "1-3 year validity"},
		},
		Guidance: "Extract Fortinet CA for HawkScan. Check FortiGate SSL/SSH inspection policy settings.",
	},
	{
		Name:    "Sophos",
		Product: "Sophos Web Appliance / UTM",
		SubjectPatterns: []string{
			`(?i)sophos`,
			`(?i)utm[\s-]?ca`,
			`(?i)swa[\s-]?ca`,
		},
		IssuerPatterns: []string{
			`(?i)sophos`,
			`(?i)utm[\s-]?root`,
		},
		OrganizationPatterns: []string{
			`(?i)sophos`,
		},
		ValidityPatterns: []ValidityPattern{
			{MinDays: 365, MaxDays: 730, Description: "1-2 year validity"},
		},
		Guidance: "Extract Sophos CA for HawkScan. Verify Web Protection HTTPS scanning configuration.",
	},
	{
		Name:    "pfSense",
		Product: "pfSense Firewall (Open Source)",
		SubjectPatterns: []string{
			`(?i)pfsense`,
			`(?i)netgate`,
			`(?i)opnsense`,
		},
		IssuerPatterns: []string{
			`(?i)pfsense`,
			`(?i)opnsense`,
			`(?i)netgate`,
		},
		OrganizationPatterns: []string{
			`(?i)pfsense`,
			`(?i)netgate`,
			`(?i)opnsense`,
		},
		ValidityPatterns: []ValidityPattern{
			{MinDays: 365, MaxDays: 3650, Description: "Variable validity (often 10 years)"},
		},
		Guidance: "Extract pfSense CA for HawkScan. Check Squid proxy and SSL/TLS inspection settings.",
	},
	{
		Name:    "Squid Proxy",
		Product: "Squid Caching Proxy (Open Source)",
		SubjectPatterns: []string{
			`(?i)squid`,
			`(?i)proxy[\s-]?ca`,
			`(?i)cache[\s-]?ca`,
		},
		IssuerPatterns: []string{
			`(?i)squid`,
			`(?i)proxy[\s-]?root`,
		},
		ValidityPatterns: []ValidityPattern{
			{MinDays: 365, MaxDays: 3650, Description: "Often long validity (10+ years)"},
		},
		Guidance: "Extract Squid CA for HawkScan. Check ssl_bump configuration and certificate generation settings.",
	},
	// Generic corporate patterns for internal CAs
	{
		Name:    "Corporate Internal CA",
		Product: "Internal Certificate Authority",
		SubjectPatterns: []string{
			`(?i)corporate[\s-]?ca`,
			`(?i)internal[\s-]?ca`,
			`(?i)company[\s-]?ca`,
			`(?i)enterprise[\s-]?ca`,
			`(?i)root[\s-]?ca`,
		},
		IssuerPatterns: []string{
			`(?i)corporate`,
			`(?i)internal`,
			`(?i)company`,
			`(?i)enterprise`,
		},
		OrganizationPatterns: []string{
			`(?i)corp`,
			`(?i)inc`,
			`(?i)ltd`,
			`(?i)llc`,
		},
		ValidityPatterns: []ValidityPattern{
			{MinDays: 30, MaxDays: 3650, Description: "Highly variable corporate policies"},
		},
		Guidance: "Extract corporate CA for HawkScan. Contact IT team for specific DPI/proxy configuration details.",
	},
	// Generic DPI/Proxy indicators
	{
		Name:    "Generic DPI/Proxy",
		Product: "Unknown DPI/MitM Device",
		SubjectPatterns: []string{
			`(?i)proxy`,
			`(?i)firewall`,
			`(?i)gateway`,
			`(?i)security`,
			`(?i)inspection`,
			`(?i)filter`,
		},
		IssuerPatterns: []string{
			`(?i)proxy`,
			`(?i)firewall`,
			`(?i)gateway`,
			`(?i)security`,
		},
		ValidityPatterns: []ValidityPattern{
			{MinDays: 1, MaxDays: 3650, Description: "Variable validity periods"},
		},
		Guidance: "Unknown DPI vendor detected. Extract CA for HawkScan and contact IT team for device details.",
	},
}

// DetectVendor analyzes a certificate and returns potential vendor matches
func DetectVendor(cert *x509.Certificate) []VendorMatch {
	var matches []VendorMatch

	for _, pattern := range knownVendors {
		match := analyzeVendorPattern(cert, pattern)
		if match.Confidence > 0 {
			matches = append(matches, match)
		}
	}

	return matches
}

// analyzeVendorPattern checks if a certificate matches a specific vendor pattern
func analyzeVendorPattern(cert *x509.Certificate, pattern VendorPattern) VendorMatch {
	match := VendorMatch{
		Vendor:      pattern.Name,
		Product:     pattern.Product,
		Guidance:    pattern.Guidance,
		Certificate: cert,
		Indicators:  []string{},
	}

	confidence := 0

	// Check subject patterns
	subject := cert.Subject.String()
	for _, subjectPattern := range pattern.SubjectPatterns {
		if matched, _ := regexp.MatchString(subjectPattern, subject); matched {
			confidence += 30
			match.Indicators = append(match.Indicators, "Subject pattern: "+subjectPattern)
		}
	}

	// Check issuer patterns
	issuer := cert.Issuer.String()
	for _, issuerPattern := range pattern.IssuerPatterns {
		if matched, _ := regexp.MatchString(issuerPattern, issuer); matched {
			confidence += 25
			match.Indicators = append(match.Indicators, "Issuer pattern: "+issuerPattern)
		}
	}

	// Check organization patterns
	for _, org := range cert.Subject.Organization {
		for _, orgPattern := range pattern.OrganizationPatterns {
			if matched, _ := regexp.MatchString(orgPattern, org); matched {
				confidence += 20
				match.Indicators = append(match.Indicators, "Organization: "+org)
			}
		}
	}

	// Check validity patterns
	validityDays := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
	for _, validityPattern := range pattern.ValidityPatterns {
		if validityDays >= validityPattern.MinDays && validityDays <= validityPattern.MaxDays {
			confidence += 10
			match.Indicators = append(match.Indicators,
				"Validity period: "+validityPattern.Description)
		}
	}

	// Check key usage patterns
	for _, expectedUsage := range pattern.KeyUsagePatterns {
		if cert.KeyUsage&expectedUsage != 0 {
			confidence += 5
			match.Indicators = append(match.Indicators, "Key usage match")
		}
	}

	// Check serial number patterns
	serialStr := cert.SerialNumber.String()
	for _, serialPattern := range pattern.SerialPatterns {
		if matched, _ := regexp.MatchString(serialPattern, serialStr); matched {
			confidence += 5
			match.Indicators = append(match.Indicators, "Serial number pattern match")
		}
	}

	// Additional confidence boosters
	if cert.Issuer.String() == cert.Subject.String() {
		// Self-signed certificates are common in DPI environments
		confidence += 5
		match.Indicators = append(match.Indicators, "Self-signed certificate")
	}

	// Version detection for some vendors
	match.Version = detectVersion(cert, pattern.Name)

	// Cap confidence at 100
	if confidence > 100 {
		confidence = 100
	}

	match.Confidence = confidence
	return match
}

// detectVersion attempts to detect version information from certificate details
func detectVersion(cert *x509.Certificate, vendor string) string {
	subject := strings.ToLower(cert.Subject.String())
	issuer := strings.ToLower(cert.Issuer.String())

	// Palo Alto version detection patterns
	if strings.Contains(vendor, "Palo Alto") {
		if strings.Contains(subject, "pan-os") || strings.Contains(issuer, "pan-os") {
			return "PAN-OS (version detection requires admin access)"
		}
		// Look for typical validity periods that correspond to PAN-OS versions
		validityYears := cert.NotAfter.Sub(cert.NotBefore).Hours() / 24 / 365
		if validityYears >= 0.9 && validityYears <= 1.1 {
			return "Likely PAN-OS 9.x+ (1-year default cert)"
		}
	}

	// Zscaler version detection
	if strings.Contains(vendor, "Zscaler") {
		validityDays := cert.NotAfter.Sub(cert.NotBefore).Hours() / 24
		if validityDays >= 85 && validityDays <= 95 {
			return "ZIA with 90-day rotation policy"
		}
	}

	return ""
}

// GetBestMatch returns the vendor match with highest confidence
func GetBestMatch(matches []VendorMatch) *VendorMatch {
	if len(matches) == 0 {
		return nil
	}

	best := matches[0]
	for _, match := range matches[1:] {
		if match.Confidence > best.Confidence {
			best = match
		}
	}

	return &best
}

// FilterByConfidence returns matches above a minimum confidence threshold
func FilterByConfidence(matches []VendorMatch, minConfidence int) []VendorMatch {
	var filtered []VendorMatch
	for _, match := range matches {
		if match.Confidence >= minConfidence {
			filtered = append(filtered, match)
		}
	}
	return filtered
}
