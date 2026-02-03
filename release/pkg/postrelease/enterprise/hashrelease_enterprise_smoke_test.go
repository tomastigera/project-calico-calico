package enterprise

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
)

// Test configuration constants
// These define the standardized cluster configuration for hashrelease smoke tests
const (
	installerType      = "operator"
	k8sE2EFlags        = `--ginkgo.focus=(\[SmokeTest\]) --ginkgo.skip=(\[Disabled\]|\[Slow\]|\[Disruptive\])`
	enableSkimble      = "false"
	functionalArea     = "smoke"
	releaseStream      = "master"
	useHashRelease     = "true"
	useLatestRelease   = "false"
	provisionerType    = "gcp-kubeadm"
	k8sVersionStable   = "stable-1"
	dataplaneType      = "CalicoIptables"
)

var (
	hashreleaseMetadataFile string
	skipSmokeTests          bool
	
	// hashreleaseMetadata stores the parsed metadata from the hashrelease metadata file
	hashreleaseMetadata map[string]string
)

func init() {
	flag.StringVar(&hashreleaseMetadataFile, "hashrelease-metadata-file", "hashrelease-metadata-file.txt", "Path to hashrelease metadata file for setting URL environment variables")
	flag.BoolVar(&skipSmokeTests, "skip-smoke-tests", false, "Skip running smoke tests")
}

// TestHashreleaseSmokeTests runs the smoke tests specifically for enterprise hashreleases.
// This test validates the enterprise hashrelease by executing end-to-end smoke test scenarios
// that were previously configured in the Semaphore YAML file (.semaphore/release/hashrelease_enterprise.yml).
//
// The test uses a single, standardized cluster configuration (defined as constants) to validate
// the hashrelease. This ensures consistent testing across all hashrelease builds.
//
// Configuration:
//   - Provisioner: gcp-kubeadm
//   - K8s Version: stable-1
//   - Dataplane: CalicoIptables
//   - Installer: operator
//
// The only configurable parameter is the hashrelease-metadata-file flag, which points to the
// metadata file containing the hashrelease URL and other information needed for testing.
//
// NOTE: This is an enterprise-specific hashrelease smoke test and is designed to verify
// the integrity and functionality of enterprise hashrelease builds before production deployment.
func TestHashreleaseSmokeTests(t *testing.T) {
	// Check if we should skip smoke tests before any other initialization
	if skipSmokeTests {
		t.Skip("Skipping smoke tests as skip-smoke-tests flag is set")
		return
	}

	// Validate environment setup
	checkEnvironmentSetup(t)

	// Define test configuration using constants
	// Hashrelease smoke tests use a single, standardized cluster configuration
	testConfigs := []struct {
		name        string
		provisioner string
		k8sVersion  string
		dataplane   string
	}{
		{
			name:        fmt.Sprintf("%s %s %s", provisionerType, k8sVersionStable, dataplaneType),
			provisioner: provisionerType,
			k8sVersion:  k8sVersionStable,
			dataplane:   dataplaneType,
		},
	}

	// Set environment variables from constants
	commonEnvVars := map[string]string{
		"INSTALLER":          installerType,
		"K8S_E2E_FLAGS":      k8sE2EFlags,
		"ENABLE_SKIMBLE":     enableSkimble,
		"FUNCTIONAL_AREA":    functionalArea,
		"RELEASE_STREAM":     releaseStream,
		"USE_HASH_RELEASE":   useHashRelease,
		"USE_LATEST_RELEASE": useLatestRelease,
	}

	// Load and set URL environment variables from hashrelease metadata file if provided
	if hashreleaseMetadataFile != "" {
		// Check if the file exists before parsing
		if _, err := os.Stat(hashreleaseMetadataFile); err == nil {
			if err := parseHashreleaseMetadataFile(t, hashreleaseMetadataFile); err != nil {
				t.Fatalf("Failed to parse hashrelease metadata: %v", err)
			}
			if err := setURLEnvironmentVariables(t); err != nil {
				t.Fatalf("Failed to set URL environment variables: %v", err)
			}
		} else {
			t.Logf("Hashrelease metadata file not found at %s, skipping URL environment variable setup", hashreleaseMetadataFile)
		}
	}

	// Set common environment variables
	for key, value := range commonEnvVars {
		t.Setenv(key, value)
	}

	// Run each test configuration
	for _, tc := range testConfigs {
		t.Run(tc.name, func(t *testing.T) {
			// Set test-specific environment variables
			t.Setenv("PROVISIONER", tc.provisioner)
			t.Setenv("K8S_VERSION", tc.k8sVersion)
			t.Setenv("DATAPLANE", tc.dataplane)

			logrus.Infof("Running smoke test: %s", tc.name)
			logrus.Infof("  Provisioner: %s", tc.provisioner)
			logrus.Infof("  K8S Version: %s", tc.k8sVersion)
			logrus.Infof("  Dataplane: %s", tc.dataplane)

			// Get the repository root directory
			// Go test runs from the test package directory:
			// /go/src/github.com/projectcalico/calico/release/pkg/postrelease/enterprise
			// Repo root is 4 levels up at /go/src/github.com/projectcalico/calico
			repoRoot := os.Getenv("REPO_ROOT")
			if repoRoot == "" {
				repoRoot = filepath.Join("..", "..", "..", "..")
			}

			// Check if the end-to-end scripts exist
			prologueScript := filepath.Join(repoRoot, ".semaphore/end-to-end/scripts/global_prologue.sh")
			bodyScript := filepath.Join(repoRoot, ".semaphore/end-to-end/scripts/body_standard.sh")
			epilogueScript := filepath.Join(repoRoot, ".semaphore/end-to-end/scripts/global_epilogue.sh")

			// Run prologue
			if err := runScript(prologueScript); err != nil {
				t.Logf("Warning: Prologue script failed or not found: %v", err)
				// Check if we should skip if scripts are not available
				if _, err := os.Stat(prologueScript); os.IsNotExist(err) {
					t.Skip("End-to-end test scripts not found, skipping smoke tests")
				}
			}

			// Run the main test body
			bodyErr := runScript(bodyScript)

			// Run epilogue after body script
			if err := runScript(epilogueScript); err != nil {
				t.Logf("Warning: Epilogue script failed: %v", err)
			}

			// Run cleanup after epilogue (note: cleanup is handled by runCleanup function)
			if true {
				logrus.Info("Running cleanup jobs...")
				if err := runCleanup(); err != nil {
					t.Logf("Warning: Cleanup failed: %v", err)
				}
			}

			// Check if body script failed
			if bodyErr != nil {
				t.Fatalf("Smoke test failed for %s: %v", tc.name, bodyErr)
			}

			logrus.Infof("Smoke test passed: %s", tc.name)
		})
	}
}

// parseHashreleaseMetadataFile parses the hashrelease metadata text file
// and stores the key-value pairs in the global hashreleaseMetadata variable
func parseHashreleaseMetadataFile(t *testing.T, metadataFilePath string) error {
	t.Helper()
	logrus.Infof("Parsing hashrelease metadata from: %s", metadataFilePath)

	// Check if file exists
	if _, err := os.Stat(metadataFilePath); os.IsNotExist(err) {
		return fmt.Errorf("hashrelease metadata file not found: %s", metadataFilePath)
	}

	// Open the file
	file, err := os.Open(metadataFilePath)
	if err != nil {
		return fmt.Errorf("failed to open metadata file: %w", err)
	}
	defer file.Close()

	// Parse the file line by line and create key-value map
	hashreleaseMetadata = make(map[string]string)
	scanner := bufio.NewScanner(file)
	var currentParent string
	
	for scanner.Scan() {
		line := scanner.Text()
		trimmedLine := strings.TrimSpace(line)
		
		// Skip empty lines
		if trimmedLine == "" {
			continue
		}
		
		// Check if line is indented (nested value)
		isIndented := len(line) > 0 && (line[0] == ' ' || line[0] == '\t')
		
		// Split by colon to get key and value
		parts := strings.SplitN(trimmedLine, ":", 2)
		if len(parts) >= 1 {
			key := strings.TrimSpace(parts[0])
			var value string
			if len(parts) == 2 {
				value = strings.TrimSpace(parts[1])
			}
			
			if isIndented && currentParent != "" {
				// Nested value - combine with parent key
				fullKey := currentParent + "." + key
				hashreleaseMetadata[fullKey] = value
			} else {
				// Top-level key
				hashreleaseMetadata[key] = value
				// If value is empty, this might be a parent key for nested values
				if value == "" {
					currentParent = key
				} else {
					currentParent = ""
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading metadata file: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"hashrelease_name": hashreleaseMetadata["name"],
		"hash":             hashreleaseMetadata["hash"],
		"stream":           hashreleaseMetadata["stream"],
		"version":          hashreleaseMetadata["version"],
		"operator":         hashreleaseMetadata["operator"],
		"url":              hashreleaseMetadata["url"],
	}).Info("Hashrelease metadata parsed successfully")

	return nil
}

// setURLEnvironmentVariables sets the URL-related environment variables
// using the url value from the global hashreleaseMetadata variable
func setURLEnvironmentVariables(t *testing.T) error {
	t.Helper()
	logrus.Info("Setting URL environment variables from hashrelease metadata")

	// Check if metadata has been parsed
	if hashreleaseMetadata == nil || len(hashreleaseMetadata) == 0 {
		return fmt.Errorf("hashrelease metadata not parsed yet")
	}

	// Get the URL from metadata
	url, ok := hashreleaseMetadata["url"]
	if !ok || url == "" {
		return fmt.Errorf("url field not found or empty in metadata")
	}

	// Ensure URL ends with exactly one trailing slash
	url = strings.TrimRight(url, "/")

	// Set environment variables based on the URL
	releaseArtifactsURL := url + "/"
	docsManifestURL := url + "/" + "manifests"
	docsURL := url + "/"

	t.Setenv("RELEASE_ARTIFACTS_URL", releaseArtifactsURL)
	t.Setenv("DOCS_MANIFEST_URL", docsManifestURL)
	t.Setenv("DOCS_URL", docsURL)

	logrus.WithFields(logrus.Fields{
		"RELEASE_ARTIFACTS_URL": releaseArtifactsURL,
		"DOCS_MANIFEST_URL":     docsManifestURL,
		"DOCS_URL":              docsURL,
	}).Info("URL environment variables set successfully")

	return nil
}

// runScript executes a shell script and returns any error
func runScript(scriptPath string) error {
	// Check if script exists
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		return fmt.Errorf("script not found: %s", scriptPath)
	}

	logrus.Infof("Executing: %s", scriptPath)
	// Execute the script using command.RunInDirNoCapture which properly handles env vars
	// Get the directory containing the script
	scriptDir := filepath.Dir(scriptPath)
	scriptName := filepath.Base(scriptPath)
	
	// Use /bin/bash to execute the script, passing current environment
	if err := command.RunInDirNoCapture(scriptDir, "/bin/bash", []string{scriptName}, os.Environ()); err != nil {
		return fmt.Errorf("script execution failed: %w", err)
	}

	return nil
}

// runCleanup executes cleanup jobs to remove test resources
// This replaces the Semaphore promotion cleanup pipeline
func runCleanup() error {
	logrus.Info("Starting cleanup of test resources...")
	
	// The cleanup logic from cleanup.yml involves:
	// 1. Getting all jobs from the workflow
	// 2. Restoring cache for each job
	// 3. Running bz destroy to clean up clusters
	// 4. Deleting the cache
	
	logrus.Info("Executing cleanup commands...")
	// For now, we'll execute a simplified cleanup that calls the banzai cleanup
	cleanupCmd := `if command -v bz &> /dev/null; then
		echo "Running banzai cleanup..."
		bz destroy || echo "Cleanup command failed or no resources to clean"
	else
		echo "bz command not found, skipping cleanup"
	fi`
	
	// Use command.RunInDirNoCapture which properly handles environment variables
	if err := command.RunInDirNoCapture("", "/bin/bash", []string{"-c", cleanupCmd}, os.Environ()); err != nil {
		return fmt.Errorf("cleanup execution failed: %w", err)
	}
	
	logrus.Info("Cleanup completed successfully")
	return nil
}

// checkEnvironmentSetup validates that required environment is set up
// for enterprise hashrelease smoke tests.
func checkEnvironmentSetup(t *testing.T) {
	t.Helper()
	
	requiredEnvVars := []string{
		"INSTALLER",
		"K8S_E2E_FLAGS",
		"FUNCTIONAL_AREA",
		"RELEASE_STREAM",
		"USE_HASH_RELEASE",
	}

	var missingVars []string
	for _, envVar := range requiredEnvVars {
		if os.Getenv(envVar) == "" {
			missingVars = append(missingVars, envVar)
		}
	}

	if len(missingVars) > 0 {
		t.Logf("Note: The following environment variables are not set: %s", strings.Join(missingVars, ", "))
		t.Logf("These will be set automatically when running the full smoke test suite")
	} else {
		t.Logf("All required environment variables are configured")
	}
}
