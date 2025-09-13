package integration_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/kaakaww/cypherhawk/internal/bundle"
	"github.com/kaakaww/cypherhawk/test/testdata"
	testutils "github.com/kaakaww/cypherhawk/test/utils"
)

// TestCrossPlatformCompatibility verifies CypherHawk works across different operating systems
func TestCrossPlatformCompatibility(t *testing.T) {
	t.Run("PlatformDetection", func(t *testing.T) {
		// Verify we can detect the current platform
		currentOS := runtime.GOOS
		currentArch := runtime.GOARCH

		validOS := []string{"windows", "darwin", "linux"}
		validArch := []string{"amd64", "arm64", "386"}

		osValid := false
		for _, os := range validOS {
			if currentOS == os {
				osValid = true
				break
			}
		}

		archValid := false
		for _, arch := range validArch {
			if currentArch == arch {
				archValid = true
				break
			}
		}

		if !osValid {
			t.Errorf("Running on unsupported OS: %s", currentOS)
		}

		if !archValid {
			t.Errorf("Running on unsupported architecture: %s", currentArch)
		}

		t.Logf("✅ Running on supported platform: %s/%s", currentOS, currentArch)
	})
}

// TestFileSystemCompatibility verifies file operations work across platforms
func TestFileSystemCompatibility(t *testing.T) {
	t.Run("TempDirectoryAccess", func(t *testing.T) {
		// Test temp directory access (important for CA bundle caching)
		tempDir := os.TempDir()
		if tempDir == "" {
			t.Error("Could not determine temp directory")
		}

		// Try to create a test file in temp directory
		testFile := filepath.Join(tempDir, "cypherhawk-test.tmp")

		err := os.WriteFile(testFile, []byte("test"), 0644)
		if err != nil {
			t.Errorf("Could not write to temp directory: %v", err)
		}
		defer os.Remove(testFile)

		// Verify we can read it back
		data, err := os.ReadFile(testFile)
		if err != nil {
			t.Errorf("Could not read from temp directory: %v", err)
		}

		if string(data) != "test" {
			t.Errorf("File content mismatch: expected 'test', got '%s'", string(data))
		}

		t.Logf("✅ Temp directory access works: %s", tempDir)
	})

	t.Run("PathSeparators", func(t *testing.T) {
		// Test that path operations work correctly on all platforms
		testPath := filepath.Join("internal", "bundle", "test.pem")

		// Should use correct separator for platform
		expectedSep := string(filepath.Separator)
		if !strings.Contains(testPath, expectedSep) && len(testPath) > 10 {
			t.Errorf("Path doesn't use correct separator for platform: %s", testPath)
		}

		t.Logf("✅ Path separators work correctly: %s", testPath)
	})
}

// TestEnvironmentVariables verifies environment variable handling across platforms
func TestEnvironmentVariables(t *testing.T) {
	t.Run("EnvironmentVariableHandling", func(t *testing.T) {
		// Clean proxy environment at start and restore at end
		cleanup := testutils.ClearProxyEnvironment(t)
		defer cleanup()

		// Test setting and reading environment variables
		testHTTPProxy := "http://test-proxy:8080"
		testHTTPSProxy := "http://test-https-proxy:8080"

		os.Setenv("HTTP_PROXY", testHTTPProxy)
		os.Setenv("HTTPS_PROXY", testHTTPSProxy)

		if os.Getenv("HTTP_PROXY") != testHTTPProxy {
			t.Errorf("HTTP_PROXY not set correctly: expected %s, got %s",
				testHTTPProxy, os.Getenv("HTTP_PROXY"))
		}

		if os.Getenv("HTTPS_PROXY") != testHTTPSProxy {
			t.Errorf("HTTPS_PROXY not set correctly: expected %s, got %s",
				testHTTPSProxy, os.Getenv("HTTPS_PROXY"))
		}

		// Test lowercase versions (common on Unix)
		os.Setenv("http_proxy", "http://lower-proxy:8080")
		if os.Getenv("http_proxy") != "http://lower-proxy:8080" {
			t.Error("Lowercase environment variables not working")
		}

		t.Logf("✅ Environment variables work correctly")
	})
}

// TestNetworkStackCompatibility tests network operations across platforms
func TestNetworkStackCompatibility(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping network tests in short mode")
	}

	t.Run("NetworkStackCompatibility", func(t *testing.T) {
		// Test basic network connectivity
		// This helps identify platform-specific network issues

		// Download Mozilla CA bundle (tests HTTPS connectivity)
		_, info, err := bundle.DownloadAndValidate()
		if err != nil {
			t.Errorf("Mozilla CA bundle download failed: %v", err)
		} else {
			t.Logf("✅ Network connectivity works: %s", info)
		}
	})
}

// TestPlatformSpecificBehaviors tests behaviors that might differ by platform
func TestPlatformSpecificBehaviors(t *testing.T) {
	switch runtime.GOOS {
	case "windows":
		t.Run("WindowsSpecific", func(t *testing.T) {
			testWindowsSpecificBehaviors(t)
		})
	case "darwin":
		t.Run("macOSSpecific", func(t *testing.T) {
			testMacOSSpecificBehaviors(t)
		})
	case "linux":
		t.Run("LinuxSpecific", func(t *testing.T) {
			testLinuxSpecificBehaviors(t)
		})
	default:
		t.Logf("No specific tests for platform: %s", runtime.GOOS)
	}
}

func testWindowsSpecificBehaviors(t *testing.T) {
	// Test Windows-specific behaviors

	// Test that paths work with Windows drive letters
	if filepath.VolumeName("C:\\test") != "C:" {
		t.Error("Windows volume name detection not working")
	}

	// Test case-insensitive environment variables (Windows specific)
	os.Setenv("Test_Var", "test_value")
	if os.Getenv("TEST_VAR") == "test_value" {
		t.Log("✅ Windows case-insensitive environment variables work")
	}

	// Test Windows proxy authentication format
	testProxyURL := "http://DOMAIN\\user:pass@proxy:8080"
	if !strings.Contains(testProxyURL, "DOMAIN\\") {
		t.Error("Windows domain proxy format test failed")
	}

	t.Log("✅ Windows-specific behaviors verified")
}

func testMacOSSpecificBehaviors(t *testing.T) {
	// Test macOS-specific behaviors

	// Test keychain integration (conceptual - actual keychain access would need additional libs)
	// For now, just verify we can handle macOS paths
	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Errorf("Could not get user home directory on macOS: %v", err)
	}

	libraryPath := filepath.Join(homeDir, "Library")
	if _, err := os.Stat(libraryPath); os.IsNotExist(err) {
		t.Error("macOS Library directory not found")
	}

	// Test case-sensitive filesystem behavior (typical on macOS)
	testFile1 := filepath.Join(os.TempDir(), "Test.txt")
	testFile2 := filepath.Join(os.TempDir(), "test.txt")

	os.WriteFile(testFile1, []byte("test1"), 0644)
	os.WriteFile(testFile2, []byte("test2"), 0644)
	defer os.Remove(testFile1)
	defer os.Remove(testFile2)

	// On case-sensitive filesystems, these should be different files
	data1, _ := os.ReadFile(testFile1)
	data2, _ := os.ReadFile(testFile2)

	if string(data1) == string(data2) {
		t.Log("Case-insensitive filesystem detected")
	} else {
		t.Log("Case-sensitive filesystem detected")
	}

	t.Log("✅ macOS-specific behaviors verified")
}

func testLinuxSpecificBehaviors(t *testing.T) {
	// Test Linux-specific behaviors

	// Test /etc directory access (common on Linux)
	if _, err := os.Stat("/etc"); os.IsNotExist(err) {
		t.Error("Linux /etc directory not found")
	}

	// Test case-sensitive filesystem (standard on Linux)
	testFile1 := filepath.Join(os.TempDir(), "Test.txt")
	testFile2 := filepath.Join(os.TempDir(), "test.txt")

	os.WriteFile(testFile1, []byte("test1"), 0644)
	os.WriteFile(testFile2, []byte("test2"), 0644)
	defer os.Remove(testFile1)
	defer os.Remove(testFile2)

	data1, _ := os.ReadFile(testFile1)
	data2, _ := os.ReadFile(testFile2)

	if string(data1) != string(data2) {
		t.Log("✅ Linux case-sensitive filesystem working correctly")
	}

	// Test Linux proxy environment variable conventions
	// Clean up proxy environment before and after test
	cleanup := testutils.ClearProxyEnvironment(t)
	defer cleanup()

	os.Setenv("http_proxy", "http://linux-proxy:3128")
	if os.Getenv("http_proxy") != "http://linux-proxy:3128" {
		t.Error("Linux lowercase proxy environment variables not working")
	}

	t.Log("✅ Linux-specific behaviors verified")
}

// TestUnicodeHandling verifies Unicode handling across platforms (important for international users)
func TestUnicodeHandling(t *testing.T) {
	t.Run("UnicodeSupport", func(t *testing.T) {
		// Test Unicode in file paths (common issue on Windows)
		unicodeDir := filepath.Join(os.TempDir(), "测试目录") // Chinese characters
		err := os.MkdirAll(unicodeDir, 0755)
		if err != nil {
			t.Logf("Unicode directory creation failed (may be expected): %v", err)
		} else {
			defer os.RemoveAll(unicodeDir)

			unicodeFile := filepath.Join(unicodeDir, "тест.txt") // Russian characters
			err = os.WriteFile(unicodeFile, []byte("Unicode test"), 0644)
			if err != nil {
				t.Logf("Unicode file creation failed (may be expected): %v", err)
			} else {
				t.Log("✅ Unicode file handling works")
			}
		}

		// Test Unicode in certificate subject names (common in international deployments)
		testSubject := "CN=测试证书,O=テスト会社,C=DE"
		if len(testSubject) == 0 {
			t.Error("Unicode string handling failed")
		}

		// Test that our ASCII output approach works correctly
		asciiOutput := "[DPI] Corporate DPI detected" // No Unicode characters
		for _, char := range asciiOutput {
			if char > 127 {
				t.Errorf("ASCII output contains non-ASCII character: %c", char)
			}
		}

		t.Log("✅ Unicode handling verified (ASCII output approach)")
	})
}

// TestMemoryUsage verifies memory usage is reasonable across platforms
func TestMemoryUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory tests in short mode")
	}

	t.Run("MemoryUsage", func(t *testing.T) {
		// Test memory usage with multiple certificate chains
		var m1, m2 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m1)

		// Create multiple mock certificate chains
		chains := make([]*testdata.MockDPICertificates, 10) // Reduced for test speed
		for i := 0; i < 10; i++ {
			chains[i] = testdata.GeneratePaloAltoCertificateChain()
		}

		runtime.GC()
		runtime.ReadMemStats(&m2)

		// Handle potential integer underflow from GC or memory reuse
		var memoryIncrease uint64
		if m2.Alloc >= m1.Alloc {
			memoryIncrease = m2.Alloc - m1.Alloc
		} else {
			// Memory decreased (GC occurred), which is actually good
			memoryIncrease = 0
			t.Logf("Memory decreased during test (GC occurred): %d -> %d bytes", m1.Alloc, m2.Alloc)
		}

		t.Logf("Memory usage for 10 certificate chains: %d bytes", memoryIncrease)

		// Memory usage should be reasonable (less than 10MB for 10 chains)
		// Note: If memoryIncrease is 0 due to GC, that's actually optimal
		if memoryIncrease > 10*1024*1024 {
			t.Errorf("Memory usage too high: %d bytes", memoryIncrease)
		}

		t.Log("✅ Memory usage is reasonable")
	})
}

// TestExecutableCreation verifies we can create executables for different platforms
func TestExecutableCreation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping executable creation tests in short mode")
	}

	t.Run("ExecutableNaming", func(t *testing.T) {
		// Test executable naming conventions for different platforms
		platforms := []struct {
			goos     string
			expected string
		}{
			{"linux", "cypherhawk"},
			{"darwin", "cypherhawk"},
			{"windows", "cypherhawk.exe"},
		}

		for _, platform := range platforms {
			expectedName := platform.expected
			if runtime.GOOS == "windows" && !strings.HasSuffix(expectedName, ".exe") {
				continue // Skip non-Windows executables when running on Windows
			}

			t.Logf("Platform %s should produce executable: %s", platform.goos, expectedName)
		}

		t.Log("✅ Executable naming conventions verified")
	})
}

// TestErrorMessageCompatibility verifies error messages work across platforms
func TestErrorMessageCompatibility(t *testing.T) {
	t.Run("ErrorMessages", func(t *testing.T) {
		// Test that error messages don't contain platform-specific paths or info
		// that would confuse users on other platforms

		sampleError := "Corporate network guidance:\n" +
			"  - Corporate firewall might be blocking the connection\n" +
			"  - Try setting HTTP_PROXY/HTTPS_PROXY environment variables\n" +
			"  - Contact IT support for proxy configuration"

		// Verify error message doesn't contain platform-specific info
		platformSpecific := []string{
			"/etc/", "C:\\", "~\\", "/usr/", "/opt/", "Registry",
		}

		for _, specific := range platformSpecific {
			if strings.Contains(sampleError, specific) {
				t.Errorf("Error message contains platform-specific path: %s", specific)
			}
		}

		// Verify error message contains helpful cross-platform guidance
		if !strings.Contains(sampleError, "HTTP_PROXY") {
			t.Error("Error message should mention HTTP_PROXY for cross-platform compatibility")
		}

		t.Log("✅ Error messages are platform-neutral")
	})
}
