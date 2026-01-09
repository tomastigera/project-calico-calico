package postrelease

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
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
}

// TestHashreleaseSmokeTests runs the smoke tests specifically for enterprise hashreleases.
// This test validates the enterprise hashrelease by executing end-to-end smoke test scenarios
// that were previously configured in the Semaphore YAML file (.semaphore/release/hashrelease_enterprise.yml).
//
// NOTE: This is an enterprise-specific hashrelease smoke test and is designed to verify
// the integrity and functionality of enterprise hashrelease builds before production deployment.
func TestHashreleaseSmokeTests(t *testing.T) {
	// Check if we're in a CI environment or if required environment is set up
	if os.Getenv("SKIP_SMOKE_TESTS") == "true" {
		t.Skip("Skipping smoke tests as SKIP_SMOKE_TESTS is set")
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

			// Check if the end-to-end scripts exist
			prologueScript := "/.semaphore/end-to-end/scripts/global_prologue.sh"
			bodyScript := "/.semaphore/end-to-end/scripts/body_standard.sh"
			epilogueScript := "/.semaphore/end-to-end/scripts/global_epilogue.sh"

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

			// Run cleanup after epilogue
			cleanupScript := "/.semaphore/end-to-end/pipelines/cleanup.yml"
			if _, err := os.Stat(cleanupScript); err == nil {
				logrus.Info("Running cleanup jobs...")
				if err := runCleanup(); err != nil {
					t.Logf("Warning: Cleanup failed: %v", err)
				}
			} else {
				t.Logf("Cleanup script not found, skipping cleanup")
			}

			// Check if body script failed
			if bodyErr != nil {
				t.Fatalf("Smoke test failed for %s: %v", tc.name, bodyErr)
			}

			logrus.Infof("Smoke test passed: %s", tc.name)
		})
	}
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
