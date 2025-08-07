package pinnedversion

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	approvals "github.com/approvals/go-approval-tests"
)

func TestEnterpriseReleaseVersions(t *testing.T) {
	_, p, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to get current file path")
	}
	fakeRepoRoot := t.TempDir()
	fakeTmpDir := filepath.Dir(p) // Use the directory of the test file as the temporary directory
	v := &EnterpriseReleaseVersions{
		Hashrelease:     "2025-07-24-v3-22-1-handiness",
		RepoRootDir:     fakeRepoRoot,
		TmpDir:          filepath.Join(fakeTmpDir, "testdata"),
		ProductVersion:  "v3.22.1",
		OperatorVersion: "v1.22.1",
		OperatorCfg: OperatorConfig{
			Image:    "tigera/operator",
			Registry: "docker.io/tigera",
		},
		HelmReleaseVersion: "0",
	}

	if err := v.generateVersions(); err != nil {
		t.Fatalf("failed to generate versions: %v", err)
	}

	if err := v.updateVersionsFile(); err != nil {
		t.Fatalf("failed to update versions file: %v", err)
	}
	c, err := os.ReadFile(filepath.Join(v.RepoRootDir, relVersionsFilePath))
	if err != nil {
		t.Fatalf("failed to read versions file: %v", err)
	}
	approvals.VerifyString(t, string(c))

	ev, err := LoadEnterpriseVersionsFromDataFile(v.RepoRootDir, v.ProductVersion)
	if err != nil {
		t.Fatalf("failed to load enterprise versions: %v", err)
	}
	if !reflect.DeepEqual(ev, &v.versions) {
		t.Fatalf("loaded versions do not match expected versions: got %+v, want %+v", ev, &v.versions)
	}
}
