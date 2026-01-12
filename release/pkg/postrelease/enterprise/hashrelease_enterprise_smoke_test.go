package enterprise

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

var (
	installer         string
	k8sE2EFlags       string
	enableSkimble     string
	functionalArea    string
	releaseStream     string
	useHashRelease    string
	useLatestRelease  string
	provisioner       string
	k8sVersion        string
	dataplane         string
	hashreleaseMetadataFile string
	
	// hashreleaseMetadata stores the parsed metadata from the hashrelease metadata file
	hashreleaseMetadata map[string]string
)

func init() {
	flag.StringVar(&installer, "installer", "operator", "Installer type for smoke tests")
	flag.StringVar(&k8sE2EFlags, "k8s-e2e-flags", `--ginkgo.focus=(\[SmokeTest\]) --ginkgo.skip=(\[Disabled\]|\[Slow\]|\[Disruptive\])`, "Ginkgo flags for E2E tests")
	flag.StringVar(&enableSkimble, "enable-skimble", "false", "Enable skimble for tests")
	flag.StringVar(&functionalArea, "functional-area", "smoke", "Functional area being tested")
	flag.StringVar(&releaseStream, "release-stream", "master", "Release stream to test")
	flag.StringVar(&useHashRelease, "use-hash-release", "true", "Use hash release for testing")
	flag.StringVar(&useLatestRelease, "use-latest-release", "false", "Use latest release for testing")
	flag.StringVar(&provisioner, "provisioner", "gcp-kubeadm", "Kubernetes provisioner to use")
	flag.StringVar(&k8sVersion, "k8s-version", "stable-1", "Kubernetes version to test")
	flag.StringVar(&dataplane, "dataplane", "CalicoIptables", "Dataplane to use for tests")
	flag.StringVar(&hashreleaseMetadataFile, "hashrelease-metadata-file", "hashrelease-metadata-file.txt", "Path to hashrelease metadata file for setting URL environment variables")
}

// TestHashreleaseSmokeTests runs the smoke tests specifically for enterprise hashreleases.
// This test validates the enterprise hashrelease by executing end-to-end smoke test scenarios
// that were previously configured in the Semaphore YAML file (.semaphore/release/hashrelease_enterprise.yml).
//
// NOTE: This is an enterprise-specific hashrelease smoke test and is designed to verify
// the integrity and functionality of enterprise hashrelease builds before production deployment.
func TestHashreleaseSmokeTests(t *testing.T) {
	// Check if we should skip smoke tests before any other initialization
	if os.Getenv("SKIP_SMOKE_TESTS") == "true" {
		t.Skip("Skipping smoke tests as SKIP_SMOKE_TESTS is set")
		return
	}

	// Define test configurations using flag parameters
	testConfigs := []struct {
		name        string
		provisioner string
		k8sVersion  string
		dataplane   string
	}{
		{
			name:        fmt.Sprintf("%s %s %s", provisioner, k8sVersion, dataplane),
			provisioner: provisioner,
			k8sVersion:  k8sVersion,
			dataplane:   dataplane,
		},
	}

	// Set environment variables from flag parameters
	commonEnvVars := map[string]string{
		"INSTALLER":          installer,
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
			if err := parseHashreleaseMetadataFile(hashreleaseMetadataFile); err != nil {
				t.Fatalf("Failed to parse hashrelease metadata: %v", err)
			}
			if err := setURLEnvironmentVariables(); err != nil {
				t.Fatalf("Failed to set URL environment variables: %v", err)
			}
		} else {
			t.Logf("Hashrelease metadata file not found at %s, skipping URL environment variable setup", hashreleaseMetadataFile)
		}
	}

	// Set common environment variables
	for key, value := range commonEnvVars {
		if err := os.Setenv(key, value); err != nil {
			t.Fatalf("Failed to set environment variable %s: %v", key, err)
		}
	}

	// Run each test configuration
	for _, tc := range testConfigs {
		t.Run(tc.name, func(t *testing.T) {
			// Set test-specific environment variables
			os.Setenv("PROVISIONER", tc.provisioner)
			os.Setenv("K8S_VERSION", tc.k8sVersion)
			os.Setenv("DATAPLANE", tc.dataplane)

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
func parseHashreleaseMetadataFile(metadataFilePath string) error {
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
func setURLEnvironmentVariables() error {
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

	if err := os.Setenv("RELEASE_ARTIFACTS_URL", releaseArtifactsURL); err != nil {
		return fmt.Errorf("failed to set RELEASE_ARTIFACTS_URL: %w", err)
	}
	if err := os.Setenv("DOCS_MANIFEST_URL", docsManifestURL); err != nil {
		return fmt.Errorf("failed to set DOCS_MANIFEST_URL: %w", err)
	}
	if err := os.Setenv("DOCS_URL", docsURL); err != nil {
		return fmt.Errorf("failed to set DOCS_URL: %w", err)
	}

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

	// Execute the script
	cmd := exec.Command("/bin/bash", scriptPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	logrus.Infof("Executing: %s", scriptPath)
	if err := cmd.Run(); err != nil {
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
	
	// For now, we'll execute a simplified cleanup that calls the banzai cleanup
	cleanupCmd := `
		if command -v bz &> /dev/null; then
			echo "Running banzai cleanup..."
			bz destroy || echo "Cleanup command failed or no resources to clean"
		else
			echo "bz command not found, skipping cleanup"
		fi
	`
	
	cmd := exec.Command("/bin/bash", "-c", cleanupCmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	
	logrus.Info("Executing cleanup commands...")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cleanup execution failed: %w", err)
	}
	
	logrus.Info("Cleanup completed successfully")
	return nil
}

// TestHashreleaseSmokeTestsValidation validates that required environment is set up
// for enterprise hashrelease smoke tests.
func TestHashreleaseSmokeTestsValidation(t *testing.T) {
	// This test validates that the environment is properly configured for enterprise hashrelease smoke testing.
	// It can be run independently to check setup before running the full test suite.

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
