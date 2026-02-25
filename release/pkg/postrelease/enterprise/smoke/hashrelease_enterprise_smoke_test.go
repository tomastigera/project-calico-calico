package smoke

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/outputs"
)

// Test configuration constants.
// The end-to-end bash scripts read these values from environment variables.
const (
	installerType    = "operator"
	k8sE2EFlags      = `--ginkgo.focus=(\[SmokeTest\]) --ginkgo.skip=(\[Disabled\]|\[Slow\]|\[Disruptive\])`
	enableSkimble    = "false"
	functionalArea   = "smoke"
	releaseStream    = "master"
	useHashRelease   = "true"
	useLatestRelease = "false"
	provisionerType  = "gcp-kubeadm"
	k8sVersionStable = "stable-1"
	dataplaneType    = "CalicoIptables"
)

var hashreleaseMetadataFile string

func init() {
	flag.StringVar(&hashreleaseMetadataFile, "hashrelease-metadata-file", "", "Path to hashrelease metadata YAML file")
}

// TestHashreleaseSmokeTests validates an enterprise hashrelease by running
// end-to-end smoke tests using the scripts in .semaphore/end-to-end/scripts/.
//
// All configuration is defined as constants above. The only external input is
// the -hashrelease-metadata-file flag pointing to the published hashrelease YAML.
func TestHashreleaseSmokeTests(t *testing.T) {
	// Set all environment variables for the end-to-end bash scripts
	t.Setenv("INSTALLER", installerType)
	t.Setenv("K8S_E2E_FLAGS", k8sE2EFlags)
	t.Setenv("ENABLE_SKIMBLE", enableSkimble)
	t.Setenv("FUNCTIONAL_AREA", functionalArea)
	t.Setenv("RELEASE_STREAM", releaseStream)
	t.Setenv("USE_HASH_RELEASE", useHashRelease)
	t.Setenv("USE_LATEST_RELEASE", useLatestRelease)
	t.Setenv("PROVISIONER", provisionerType)
	t.Setenv("K8S_VERSION", k8sVersionStable)
	t.Setenv("DATAPLANE", dataplaneType)

	// Load URL environment variables from hashrelease metadata file if provided
	if hashreleaseMetadataFile != "" {
		metadata, err := outputs.LoadPublishedHashrelease(hashreleaseMetadataFile)
		if err != nil {
			t.Fatalf("Failed to load hashrelease metadata from %s: %v", hashreleaseMetadataFile, err)
		}
		url := strings.TrimRight(metadata.HashreleaseURL, "/")
		t.Setenv("RELEASE_ARTIFACTS_URL", url+"/")
		t.Setenv("DOCS_MANIFEST_URL", url+"/manifests")
		t.Setenv("DOCS_URL", url+"/")
		logrus.Infof("Hashrelease URL: %s", url)
	}

	// Resolve repo root
	repoRoot, err := command.GitDir()
	if err != nil {
		t.Fatalf("Failed to determine repo root: %v", err)
	}

	scriptsDir := filepath.Join(repoRoot, ".semaphore", "end-to-end", "scripts")
	bodyScript := filepath.Join(scriptsDir, "body_standard.sh")

	// Run prologue
	if err := runScript(filepath.Join(scriptsDir, "global_prologue.sh")); err != nil {
		t.Fatalf("Prologue script failed: %v", err)
	}

	// Run the main test body
	bodyErr := runScript(bodyScript)

	// Always run epilogue and cleanup, even if body failed
	if err := runScript(filepath.Join(scriptsDir, "global_epilogue.sh")); err != nil {
		t.Errorf("Epilogue script failed: %v", err)
	}
	if err := runCleanup(); err != nil {
		t.Errorf("Cleanup failed: %v", err)
	}

	if bodyErr != nil {
		t.Fatalf("Smoke test failed: %v", bodyErr)
	}
}

// runScript executes a shell script and returns any error.
func runScript(scriptPath string) error {
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		return fmt.Errorf("script not found: %s", scriptPath)
	}
	logrus.Infof("Executing: %s", scriptPath)
	_, err := command.RunInDir(filepath.Dir(scriptPath), "/bin/bash", []string{filepath.Base(scriptPath)})
	if err != nil {
		return fmt.Errorf("script %s failed: %w", filepath.Base(scriptPath), err)
	}
	return nil
}

// runCleanup removes test resources by running banzai destroy.
func runCleanup() error {
	logrus.Info("Running cleanup...")
	cleanupCmd := `if command -v bz &> /dev/null; then
		bz destroy || echo "Cleanup failed or no resources to clean"
	else
		echo "bz command not found, skipping cleanup"
	fi`
	_, err := command.RunInDir("", "/bin/bash", []string{"-c", cleanupCmd})
	if err != nil {
		return fmt.Errorf("cleanup failed: %w", err)
	}
	return nil
}
