package smoke

import (
	"flag"
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

	// Load URL environment variables from hashrelease metadata file
	if hashreleaseMetadataFile == "" {
		t.Fatal("The -hashrelease-metadata-file flag is required")
	}
	metadata, err := outputs.LoadPublishedHashrelease(hashreleaseMetadataFile)
	if err != nil {
		t.Fatalf("Failed to load hashrelease metadata from %s: %v", hashreleaseMetadataFile, err)
	}
	url := strings.TrimRight(metadata.HashreleaseURL, "/")
	t.Setenv("RELEASE_ARTIFACTS_URL", url+"/")
	t.Setenv("DOCS_MANIFEST_URL", url+"/manifests")
	t.Setenv("DOCS_URL", url+"/")
	logrus.Infof("Hashrelease URL: %s", url)

	// Resolve repo root
	repoRoot, err := command.GitDir()
	if err != nil {
		t.Fatalf("Failed to determine repo root: %v", err)
	}

	scriptsDir := filepath.Join(repoRoot, ".semaphore", "end-to-end", "scripts")
	bodyScript := filepath.Join(scriptsDir, "body_standard.sh")

	// Register cleanup to run after test completes (even on Fatalf).
	// Uses t.Errorf (non-fatal) so both epilogue and cleanup always execute.
	t.Cleanup(func() {
		epiloguePath := filepath.Join(scriptsDir, "global_epilogue.sh")
		if _, statErr := os.Stat(epiloguePath); statErr == nil {
			logrus.Infof("Executing: %s", epiloguePath)
			if _, err := command.RunInDir(filepath.Dir(epiloguePath), "/bin/bash", []string{filepath.Base(epiloguePath)}); err != nil {
				t.Errorf("Epilogue script failed: %v", err)
			}
		}
		runCleanup(t)
	})

	// Run prologue
	runScript(t, filepath.Join(scriptsDir, "global_prologue.sh"))

	// Run the main test body
	runScript(t, bodyScript)
}

// runScript executes a shell script, calling t.Fatalf on failure.
func runScript(t *testing.T, scriptPath string) {
	t.Helper()
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		t.Fatalf("script not found: %s", scriptPath)
	}
	logrus.Infof("Executing: %s", scriptPath)
	if _, err := command.RunInDir(filepath.Dir(scriptPath), "/bin/bash", []string{filepath.Base(scriptPath)}); err != nil {
		t.Fatalf("script %s failed: %v", filepath.Base(scriptPath), err)
	}
}

// runCleanup removes test resources by running banzai destroy.
// It uses t.Errorf (non-fatal) so other cleanup steps can still run.
func runCleanup(t *testing.T) {
	t.Helper()
	logrus.Info("Running cleanup...")
	cleanupCmd := `if command -v bz &> /dev/null; then
		bz destroy || echo "Cleanup failed or no resources to clean"
	else
		echo "bz command not found, skipping cleanup"
	fi`
	if _, err := command.RunInDir("", "/bin/bash", []string{"-c", cleanupCmd}); err != nil {
		t.Errorf("cleanup failed: %v", err)
	}
}
