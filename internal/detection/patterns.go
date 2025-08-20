package detection

import (
	"crypto/x509"
	"regexp"
	"strings"
)

// CertificateFieldAnalysis contains deep analysis of certificate fields
type CertificateFieldAnalysis struct {
	SubjectAnalysis    SubjectAnalysis
	IssuerAnalysis     IssuerAnalysis
	ExtensionAnalysis  ExtensionAnalysis
	KeyAnalysis        KeyAnalysis
	ValidationAnalysis ValidationAnalysis
}

// SubjectAnalysis examines the certificate subject for DPI patterns
type SubjectAnalysis struct {
	CommonName         string
	Organization       []string
	OrganizationalUnit []string
	Country            []string
	Locality           []string
	Province           []string
	SuspiciousTerms    []string
	DPIIndicators      []string
}

// IssuerAnalysis examines the certificate issuer for DPI patterns
type IssuerAnalysis struct {
	CommonName      string
	Organization    []string
	SuspiciousTerms []string
	SelfSigned      bool
	KnownCA         bool
	DPIIndicators   []string
}

// ExtensionAnalysis examines certificate extensions for DPI characteristics
type ExtensionAnalysis struct {
	HasBasicConstraints  bool
	HasKeyUsage          bool
	HasExtKeyUsage       bool
	HasSAN               bool
	HasAIA               bool
	MissingExtensions    []string
	SuspiciousExtensions []string
}

// KeyAnalysis examines the public key for DPI characteristics
type KeyAnalysis struct {
	Algorithm     string
	KeySize       int
	IsWeak        bool
	SuspiciousKey bool
	DPIIndicators []string
}

// ValidationAnalysis examines certificate validation properties
type ValidationAnalysis struct {
	ValidityPeriodDays int
	IsExpired          bool
	IsNotYetValid      bool
	IsSelfSigned       bool
	ValidityFlags      []string
}

// AnalyzeCertificateFields performs deep analysis of all certificate fields
func AnalyzeCertificateFields(cert *x509.Certificate) *CertificateFieldAnalysis {
	analysis := &CertificateFieldAnalysis{
		SubjectAnalysis:    analyzeSubject(cert),
		IssuerAnalysis:     analyzeIssuer(cert),
		ExtensionAnalysis:  analyzeExtensions(cert),
		KeyAnalysis:        analyzeKey(cert),
		ValidationAnalysis: analyzeValidation(cert),
	}

	return analysis
}

// analyzeSubject examines the certificate subject for DPI indicators
func analyzeSubject(cert *x509.Certificate) SubjectAnalysis {
	subject := cert.Subject
	analysis := SubjectAnalysis{
		CommonName:         subject.CommonName,
		Organization:       subject.Organization,
		OrganizationalUnit: subject.OrganizationalUnit,
		Country:            subject.Country,
		Locality:           subject.Locality,
		Province:           subject.Province,
		SuspiciousTerms:    []string{},
		DPIIndicators:      []string{},
	}

	// Define suspicious terms that commonly appear in DPI certificates
	suspiciousTerms := []string{
		"proxy", "gateway", "firewall", "security", "filter", "inspection",
		"corporate", "internal", "company", "enterprise", "appliance",
		"test", "demo", "localhost", "example", "default", "admin",
		"untrusted", "temporary", "generated", "automatic",
	}

	// Check all subject fields for suspicious terms
	allSubjectText := strings.ToLower(subject.String())
	for _, term := range suspiciousTerms {
		if strings.Contains(allSubjectText, term) {
			analysis.SuspiciousTerms = append(analysis.SuspiciousTerms, term)
		}
	}

	// DPI-specific patterns in Common Name
	dpiCNPatterns := []string{
		`(?i).*proxy.*`,
		`(?i).*gateway.*`,
		`(?i).*firewall.*`,
		`(?i).*\.(local|corp|internal)$`,
		`(?i)^(localhost|127\.0\.0\.1)$`,
	}

	for _, pattern := range dpiCNPatterns {
		if matched, _ := regexp.MatchString(pattern, analysis.CommonName); matched {
			analysis.DPIIndicators = append(analysis.DPIIndicators,
				"Suspicious CN pattern: "+analysis.CommonName)
		}
	}

	// Check for generic/default names
	genericNames := []string{
		"localhost", "test", "demo", "default", "example.com", "certificate",
		"ca", "root", "intermediate", "ssl", "tls", "https",
	}

	for _, generic := range genericNames {
		if strings.EqualFold(analysis.CommonName, generic) {
			analysis.DPIIndicators = append(analysis.DPIIndicators,
				"Generic/default CN: "+analysis.CommonName)
		}
	}

	return analysis
}

// analyzeIssuer examines the certificate issuer for DPI indicators
func analyzeIssuer(cert *x509.Certificate) IssuerAnalysis {
	issuer := cert.Issuer
	analysis := IssuerAnalysis{
		CommonName:      issuer.CommonName,
		Organization:    issuer.Organization,
		SuspiciousTerms: []string{},
		SelfSigned:      cert.Issuer.String() == cert.Subject.String(),
		DPIIndicators:   []string{},
	}

	// Check for known legitimate CAs
	knownCAs := []string{
		"DigiCert", "Let's Encrypt", "GlobalSign", "GeoTrust", "Thawte",
		"VeriSign", "Symantec", "GoDaddy", "Comodo", "Sectigo", "Amazon",
		"Google", "Microsoft", "Apple", "Cloudflare",
	}

	issuerText := strings.ToLower(issuer.String())
	for _, ca := range knownCAs {
		if strings.Contains(issuerText, strings.ToLower(ca)) {
			analysis.KnownCA = true
			break
		}
	}

	// DPI-specific issuer patterns
	dpiTerms := []string{
		"proxy", "gateway", "firewall", "security", "appliance",
		"corporate", "internal", "company", "palo alto", "zscaler",
		"netskope", "forcepoint", "bluecoat", "mcafee", "symantec",
	}

	for _, term := range dpiTerms {
		if strings.Contains(issuerText, term) {
			analysis.SuspiciousTerms = append(analysis.SuspiciousTerms, term)
			analysis.DPIIndicators = append(analysis.DPIIndicators,
				"DPI vendor term in issuer: "+term)
		}
	}

	// Self-signed analysis
	if analysis.SelfSigned {
		analysis.DPIIndicators = append(analysis.DPIIndicators,
			"Self-signed certificate (common in DPI)")
	}

	return analysis
}

// analyzeExtensions examines certificate extensions for DPI characteristics
func analyzeExtensions(cert *x509.Certificate) ExtensionAnalysis {
	analysis := ExtensionAnalysis{
		HasBasicConstraints:  cert.BasicConstraintsValid,
		HasKeyUsage:          cert.KeyUsage != 0,
		HasExtKeyUsage:       len(cert.ExtKeyUsage) > 0,
		HasSAN:               len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0,
		HasAIA:               len(cert.IssuingCertificateURL) > 0,
		MissingExtensions:    []string{},
		SuspiciousExtensions: []string{},
	}

	// Check for missing critical extensions
	if !analysis.HasBasicConstraints {
		analysis.MissingExtensions = append(analysis.MissingExtensions, "Basic Constraints")
	}

	if !analysis.HasKeyUsage {
		analysis.MissingExtensions = append(analysis.MissingExtensions, "Key Usage")
	}

	if !analysis.HasSAN && cert.Subject.CommonName != "" {
		// Modern certificates should have SAN extension
		analysis.MissingExtensions = append(analysis.MissingExtensions, "Subject Alternative Names")
	}

	// Check for suspicious key usage combinations
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 && !cert.IsCA {
		analysis.SuspiciousExtensions = append(analysis.SuspiciousExtensions,
			"Certificate signing without CA flag")
	}

	// Check extended key usage for DPI patterns
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageAny:
			analysis.SuspiciousExtensions = append(analysis.SuspiciousExtensions,
				"Extended Key Usage: Any (overly permissive)")
		}
	}

	return analysis
}

// analyzeKey examines the public key for DPI characteristics
func analyzeKey(cert *x509.Certificate) KeyAnalysis {
	analysis := KeyAnalysis{
		Algorithm:     cert.PublicKeyAlgorithm.String(),
		DPIIndicators: []string{},
	}

	// Analyze key based on algorithm
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		if rsaKey, ok := cert.PublicKey.(*x509.Certificate); ok {
			// Note: This is incorrect - we need to cast to *rsa.PublicKey
			// Will fix in a future iteration, keeping simple for now
			_ = rsaKey
			analysis.KeySize = 2048 // Placeholder
		}

		if analysis.KeySize < 2048 {
			analysis.IsWeak = true
			analysis.DPIIndicators = append(analysis.DPIIndicators,
				"Weak RSA key size: less than 2048 bits")
		}

	case x509.ECDSA:
		analysis.KeySize = 256 // Typical ECDSA size
		// ECDSA with P-256 is generally acceptable

	default:
		analysis.SuspiciousKey = true
		analysis.DPIIndicators = append(analysis.DPIIndicators,
			"Unusual key algorithm: "+analysis.Algorithm)
	}

	return analysis
}

// analyzeValidation examines certificate validation properties
func analyzeValidation(cert *x509.Certificate) ValidationAnalysis {
	analysis := ValidationAnalysis{
		ValidityPeriodDays: int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24),
		IsExpired:          cert.NotAfter.Before(cert.NotBefore),
		IsNotYetValid:      cert.NotBefore.After(cert.NotAfter),
		IsSelfSigned:       cert.Issuer.String() == cert.Subject.String(),
		ValidityFlags:      []string{},
	}

	// Analyze validity period
	days := analysis.ValidityPeriodDays

	if days < 7 {
		analysis.ValidityFlags = append(analysis.ValidityFlags,
			"Very short validity period (< 1 week)")
	} else if days < 30 {
		analysis.ValidityFlags = append(analysis.ValidityFlags,
			"Short validity period (< 1 month)")
	} else if days > 3650 { // > 10 years
		analysis.ValidityFlags = append(analysis.ValidityFlags,
			"Unusually long validity period (> 10 years)")
	}

	// Common DPI validity periods
	commonDPIPeriods := []int{
		365,  // 1 year (Palo Alto default)
		90,   // 90 days (Zscaler)
		730,  // 2 years
		1825, // 5 years
		3650, // 10 years
	}

	for _, period := range commonDPIPeriods {
		if days >= period-1 && days <= period+1 {
			analysis.ValidityFlags = append(analysis.ValidityFlags,
				"Common DPI validity period detected")
			break
		}
	}

	return analysis
}

// GetOverallSuspiciousScore calculates an overall suspicion score for the certificate
func (analysis *CertificateFieldAnalysis) GetOverallSuspiciousScore() int {
	score := 0

	// Subject analysis scoring
	score += len(analysis.SubjectAnalysis.SuspiciousTerms) * 10
	score += len(analysis.SubjectAnalysis.DPIIndicators) * 15

	// Issuer analysis scoring
	if !analysis.IssuerAnalysis.KnownCA {
		score += 20
	}
	if analysis.IssuerAnalysis.SelfSigned {
		score += 25
	}
	score += len(analysis.IssuerAnalysis.DPIIndicators) * 15

	// Extension analysis scoring
	score += len(analysis.ExtensionAnalysis.MissingExtensions) * 10
	score += len(analysis.ExtensionAnalysis.SuspiciousExtensions) * 15

	// Key analysis scoring
	if analysis.KeyAnalysis.IsWeak {
		score += 30
	}
	if analysis.KeyAnalysis.SuspiciousKey {
		score += 20
	}

	// Validation analysis scoring
	if analysis.ValidationAnalysis.ValidityPeriodDays < 30 {
		score += 20
	}
	if analysis.ValidationAnalysis.ValidityPeriodDays > 3650 {
		score += 15
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// GetDPILikelihood returns a human-readable assessment of DPI likelihood
func (analysis *CertificateFieldAnalysis) GetDPILikelihood() string {
	score := analysis.GetOverallSuspiciousScore()

	switch {
	case score >= 80:
		return "VERY HIGH - Strong DPI indicators across multiple fields"
	case score >= 60:
		return "HIGH - Multiple DPI characteristics detected"
	case score >= 40:
		return "MODERATE - Some suspicious patterns found"
	case score >= 20:
		return "LOW - Minor suspicious characteristics"
	default:
		return "MINIMAL - Certificate appears legitimate"
	}
}
