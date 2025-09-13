package main

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/kaakaww/cypherhawk/internal/analysis"
	"github.com/kaakaww/cypherhawk/internal/bundle"
	"github.com/kaakaww/cypherhawk/internal/network"
	"github.com/kaakaww/cypherhawk/internal/output"
)

// Build-time variables (set via -ldflags)
var (
	version   = "dev"
	buildTime = "unknown"
)

// Configuration struct for CLI options
type Config struct {
	OutputFile   string
	TargetURL    string
	Verbose      bool
	Quiet        bool
	Silent       bool
	AnalyzeChain bool
	LogLevel     string
}

// Default endpoints representing common corporate network requirements
var defaultEndpoints = []string{
	"https://www.google.com",
	"https://auth.stackhawk.com",
	"https://api.stackhawk.com",
	"https://s3.us-west-2.amazonaws.com",
}

var rootCmd = &cobra.Command{
	Use:   "cypherhawk",
	Short: "Detect corporate Deep Packet Inspection (DPI) firewalls and extract CA certificates",
	Long: `CypherHawk - Corporate DPI Detection & Certificate Extraction Tool

A production-ready CLI utility that detects corporate Deep Packet Inspection (DPI) 
firewalls and man-in-the-middle (MitM) proxies, extracts their CA certificates, and 
provides comprehensive security analysis.

Built for Java developers, DevOps teams, and security professionals dealing with 
corporate security infrastructure.`,
	Example: `  # Basic usage - test default endpoints
  cypherhawk

  # Test specific URL
  cypherhawk --url https://example.com

  # Save certificates to file
  cypherhawk --output certs.pem

  # Verbose output with security analysis
  cypherhawk --verbose --analyze

  # HawkScan integration
  hawk scan --ca-bundle $(cypherhawk --output certs.pem)`,
	RunE: runDetection,
}

var detectCmd = &cobra.Command{
	Use:   "detect [URL]",
	Short: "Detect DPI and extract CA certificates",
	Long: `Detect corporate DPI/MitM proxies and extract unknown CA certificates.

This is the primary command for certificate extraction and analysis.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		config := &Config{
			OutputFile:   viper.GetString("output"),
			Verbose:      viper.GetBool("verbose"),
			Quiet:        viper.GetBool("quiet"),
			Silent:       viper.GetBool("silent"),
			AnalyzeChain: viper.GetBool("analyze"),
			LogLevel:     viper.GetString("log-level"),
		}

		if len(args) > 0 {
			config.TargetURL = args[0]
		} else {
			config.TargetURL = viper.GetString("url")
		}

		return runDetectionWithConfig(config)
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("CypherHawk %s (built %s)\n", version, buildTime)
		fmt.Println("Corporate DPI Detection & Certificate Extraction Tool")
		fmt.Println("Built by StackHawk for the Java ecosystem")
	},
}

func init() {
	// Configure Viper
	viper.SetEnvPrefix("CYPHERHAWK")
	viper.AutomaticEnv()

	// Root command flags
	rootCmd.PersistentFlags().StringP("output", "o", "", "Output file for CA certificates (use '-' for stdout)")
	rootCmd.PersistentFlags().StringP("url", "u", "", "Custom target URL to test")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Show detailed progress and security analysis")
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "Suppress all non-error output")
	rootCmd.PersistentFlags().Bool("silent", false, "Suppress ALL output (even errors)")
	rootCmd.PersistentFlags().BoolP("analyze", "a", false, "Show comprehensive certificate chain analysis")
	rootCmd.PersistentFlags().String("log-level", "info", "Log level (debug, info, warn, error)")

	// Bind flags to viper
	viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))
	viper.BindPFlag("url", rootCmd.PersistentFlags().Lookup("url"))
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	viper.BindPFlag("quiet", rootCmd.PersistentFlags().Lookup("quiet"))
	viper.BindPFlag("silent", rootCmd.PersistentFlags().Lookup("silent"))
	viper.BindPFlag("analyze", rootCmd.PersistentFlags().Lookup("analyze"))
	viper.BindPFlag("log-level", rootCmd.PersistentFlags().Lookup("log-level"))

	// Add subcommands
	rootCmd.AddCommand(detectCmd)
	rootCmd.AddCommand(versionCmd)

	// Set custom help
	rootCmd.SetHelpFunc(showCustomHelp)
}

func setupLogging(logLevel string) {
	var level slog.Level
	switch strings.ToLower(logLevel) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})
	logger := slog.New(handler)
	slog.SetDefault(logger)
}

func runDetection(cmd *cobra.Command, args []string) error {
	config := &Config{
		OutputFile:   viper.GetString("output"),
		Verbose:      viper.GetBool("verbose"),
		Quiet:        viper.GetBool("quiet"),
		Silent:       viper.GetBool("silent"),
		AnalyzeChain: viper.GetBool("analyze"),
		LogLevel:     viper.GetString("log-level"),
	}

	if len(args) > 0 {
		config.TargetURL = args[0]
	} else {
		config.TargetURL = viper.GetString("url")
	}

	return runDetectionWithConfig(config)
}

func runDetectionWithConfig(config *Config) error {
	// Setup logging based on configuration
	setupLogging(config.LogLevel)

	// Silence logs if requested
	if config.Silent {
		handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.Level(1000), // Effectively disable all logging
		})
		slog.SetDefault(slog.New(handler))
	}

	slog.Info("starting certificate detection",
		"version", version,
		"target_url", config.TargetURL)

	// Download and validate Mozilla CA bundle
	if !config.Quiet && !config.Silent {
		fmt.Println("🔄 Downloading Mozilla CA bundle...")
	}

	mozillaCAs, bundleInfo, err := bundle.DownloadAndValidate()
	if err != nil {
		slog.Error("failed to download Mozilla CA bundle", "error", err)
		return fmt.Errorf("failed to download Mozilla CA bundle: %w", err)
	}

	if config.Verbose && !config.Silent {
		fmt.Printf("✅ Mozilla CA bundle loaded (%s)\n", bundleInfo)
	}

	// Determine endpoints to test
	var endpoints []string
	if config.TargetURL != "" {
		normalizedURL, err := validateAndNormalizeURL(config.TargetURL)
		if err != nil {
			slog.Error("invalid target URL", "url", config.TargetURL, "error", err)
			return err
		}
		endpoints = []string{normalizedURL}
	} else {
		endpoints = defaultEndpoints
	}

	// Test endpoints and collect certificates
	allUnknownCAs := make(map[string]*x509.Certificate)

	for i, endpoint := range endpoints {
		if !config.Quiet && !config.Silent {
			if len(endpoints) > 1 {
				fmt.Printf("🔍 Testing endpoint %d/%d: %s\n", i+1, len(endpoints), endpoint)
			} else {
				fmt.Printf("🔍 Testing: %s\n", endpoint)
			}
		}

		slog.Debug("testing endpoint", "endpoint", endpoint, "index", i+1)

		// Extract hostname for certificate validation
		parsedURL, err := url.Parse(endpoint)
		if err != nil {
			slog.Error("failed to parse endpoint URL", "endpoint", endpoint, "error", err)
			if !config.Quiet && !config.Silent {
				fmt.Printf("❌ Failed to parse URL %s: %v\n", endpoint, err)
			}
			continue
		}

		// Get certificate chain
		certs, err := network.GetCertificateChain(endpoint)
		if err != nil {
			slog.Error("failed to get certificate chain", "endpoint", endpoint, "error", err)
			if !config.Quiet && !config.Silent {
				fmt.Printf("❌ Failed to connect to %s: %v\n", endpoint, err)
			}
			continue
		}

		slog.Info("certificate chain retrieved",
			"endpoint", endpoint,
			"chain_length", len(certs))

		if config.Verbose && !config.Silent {
			fmt.Printf("📄 Retrieved %d certificates from %s\n", len(certs), endpoint)
		}

		// Analyze certificate chain
		unknownCAs := analysis.ValidateChain(certs, mozillaCAs, parsedURL.Hostname())

		if len(unknownCAs) > 0 {
			slog.Info("unknown CA certificates detected",
				"endpoint", endpoint,
				"count", len(unknownCAs))

			if config.Verbose && !config.Silent {
				fmt.Printf("🚨 Found %d unknown CA certificate(s) - potential corporate DPI detected!\n", len(unknownCAs))
			}

			// Store unique certificates (deduplicate by subject)
			for _, cert := range unknownCAs {
				subject := cert.Subject.String()
				if _, exists := allUnknownCAs[subject]; !exists {
					allUnknownCAs[subject] = cert
				}
			}
		} else {
			slog.Debug("no unknown CAs found for endpoint", "endpoint", endpoint)
			if config.Verbose && !config.Silent {
				fmt.Printf("✅ All certificates trusted by Mozilla - no corporate DPI detected\n")
			}
		}

		// Enhanced security analysis if requested
		if config.AnalyzeChain && !config.Silent {
			showSecurityAnalysis(certs, mozillaCAs, parsedURL.Hostname())
		}
	}

	// Output results
	if len(allUnknownCAs) == 0 {
		if !config.Quiet && !config.Silent {
			fmt.Println("\n✅ No corporate DPI certificates detected")
			fmt.Println("All connections use certificates trusted by Mozilla's CA bundle")
		}
		return nil
	}

	// Convert map to slice for output
	var unknownCAsList []*x509.Certificate
	for _, cert := range allUnknownCAs {
		unknownCAsList = append(unknownCAsList, cert)
	}

	if !config.Quiet && !config.Silent {
		fmt.Printf("\n🎯 Detected %d unique corporate CA certificate(s)\n", len(unknownCAsList))
	}

	// Generate and output PEM certificates
	pemOutput := output.GeneratePEM(unknownCAsList)

	err = writePEMOutput(pemOutput, config.OutputFile, !config.Quiet && !config.Silent)
	if err != nil {
		slog.Error("failed to write PEM output", "error", err)
		return fmt.Errorf("failed to write PEM output: %w", err)
	}

	slog.Info("certificate extraction completed successfully",
		"certificates_found", len(unknownCAsList))

	return nil
}

// Rest of the functions remain the same but with structured logging...
// [Note: The remaining functions like validateAndNormalizeURL, normalizeURL, etc.
// would be updated with slog calls but I'll abbreviate here for space]

// writePEMOutput writes PEM output to file or stdout
func writePEMOutput(pemOutput, outputFile string, showProgress bool) error {
	if outputFile == "" {
		// No output file specified, write to stdout
		fmt.Print(pemOutput)
		return nil
	}

	if outputFile == "-" {
		// Explicit stdout
		fmt.Print(pemOutput)
		return nil
	}

	// Write to file
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	_, err = file.WriteString(pemOutput)
	if err != nil {
		return fmt.Errorf("failed to write to output file: %w", err)
	}

	if showProgress {
		fmt.Printf("✅ Certificates saved to %s\n", outputFile)
	}

	return nil
}

func validateAndNormalizeURL(inputURL string) (string, error) {
	if inputURL == "" {
		return "", fmt.Errorf("URL cannot be empty")
	}

	inputURL = strings.TrimSpace(inputURL)

	if strings.ContainsAny(inputURL, "\r\n\t") {
		return "", fmt.Errorf("URL contains invalid control characters")
	}

	tempURL, tempErr := url.Parse(inputURL)
	if tempErr == nil && tempURL.Scheme != "" && tempURL.Scheme != "http" && tempURL.Scheme != "https" {
		return "", fmt.Errorf("unsupported URL scheme '%s', only http and https are supported", tempURL.Scheme)
	}

	normalized := normalizeURL(inputURL)
	parsedURL, err := url.Parse(normalized)
	if err != nil {
		return "", fmt.Errorf("invalid URL format: %w", err)
	}

	if parsedURL.Hostname() == "" {
		return "", fmt.Errorf("URL must include a hostname")
	}

	return normalized, nil
}

func normalizeURL(inputURL string) string {
	if !strings.HasPrefix(inputURL, "http://") && !strings.HasPrefix(inputURL, "https://") {
		return "https://" + inputURL
	}
	return inputURL
}

func showSecurityAnalysis(certs []*x509.Certificate, mozillaCAs *x509.CertPool, hostname string) {
	if len(certs) == 0 {
		return
	}

	fmt.Println("\n🔒 Security Analysis:")

	// Basic certificate information
	for i, cert := range certs {
		fmt.Printf("  📋 Certificate %d:\n", i+1)
		fmt.Printf("    Subject: %s\n", cert.Subject.String())
		fmt.Printf("    Issuer: %s\n", cert.Issuer.String())
		fmt.Printf("    Valid: %s - %s\n", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))
		if cert.IsCA {
			fmt.Printf("    Type: Certificate Authority\n")
		} else {
			fmt.Printf("    Type: End Entity\n")
		}
		fmt.Println()
	}

	// Check for potential DPI indicators
	for _, cert := range certs {
		if cert.IsCA && analysis.IsPotentialDPICA(cert) {
			fmt.Printf("  🚨 Potential DPI Certificate Authority detected: %s\n", cert.Subject.CommonName)
		}
	}
}

func showCustomHelp(cmd *cobra.Command, args []string) {
	fmt.Print(`CypherHawk - Corporate DPI Detection & Certificate Extraction Tool

USAGE:
  cypherhawk [flags] [URL]
  cypherhawk detect [flags] [URL]

EXAMPLES:
  # Basic usage - test default endpoints
  cypherhawk

  # Test specific URL
  cypherhawk --url https://example.com
  cypherhawk detect https://example.com

  # Save certificates to file
  cypherhawk --output certs.pem

  # Verbose analysis with detailed logging
  cypherhawk --verbose --analyze --log-level debug

  # Silent mode for scripts
  cypherhawk --silent --output certs.pem

HAWKSCAN INTEGRATION:
  # Extract and use certificates with HawkScan
  cypherhawk --output corporate-cas.pem
  hawk scan --ca-bundle corporate-cas.pem

  # Java applications (PEM format - Java 9+)
  java -Djavax.net.ssl.trustStoreType=PEM \
       -Djavax.net.ssl.trustStore=corporate-cas.pem MyApp

  # Convert to JKS format (all Java versions)
  keytool -importcert -noprompt -file corporate-cas.pem \
          -keystore corporate.jks -storepass changeit -alias corporate-ca

FLAGS:
  -o, --output string     Output file for CA certificates (use '-' for stdout)
  -u, --url string        Custom target URL to test
  -v, --verbose          Show detailed progress and security analysis  
  -q, --quiet            Suppress all non-error output
      --silent           Suppress ALL output (even errors)
  -a, --analyze          Show comprehensive certificate chain analysis
      --log-level string  Log level: debug, info, warn, error (default "info")
  -h, --help             Show this help message

COMMANDS:
  detect      Detect DPI and extract CA certificates (default)
  version     Show version information

CORPORATE NETWORK GUIDANCE:
  • Configure HTTP_PROXY and HTTPS_PROXY environment variables
  • Contact IT support for proxy authentication if needed
  • Use --verbose for detailed troubleshooting information
  • Generated certificates work with Maven, Gradle, and all Java applications

For more information: https://github.com/stackhawk/cypherhawk
`)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		slog.Error("command execution failed", "error", err)
		os.Exit(1)
	}
}
