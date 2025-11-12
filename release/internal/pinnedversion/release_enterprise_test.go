package pinnedversion

import (
	"os"
	"path/filepath"
	"testing"

	approvals "github.com/approvals/go-approval-tests"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
	"github.com/projectcalico/calico/release/pkg/manager/manager"
)

func TestEnterpriseReleaseVersions(t *testing.T) {
	rootDir, err := command.GitDir()
	if err != nil {
		t.Fatalf("failed to get git root dir: %v", err)
	}
	for _, tc := range []struct {
		name            string
		releaseDirs     []string
		wantGenerateErr bool
	}{
		{name: "standard"},
		{name: "duplicate dirs", releaseDirs: []string{"linseed", "linseed"}, wantGenerateErr: true},
		{name: "all dirs", releaseDirs: append(utils.EnterpriseImageReleaseDirs, manager.ReleaseDir)},
		{name: "no manager", releaseDirs: []string{"linseed", "guardian"}},
		{name: "with manager", releaseDirs: []string{"linseed", manager.ReleaseDir, "guardian"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, cleanup := fakeHashreleasePinnedVersions(t, rootDir)
			t.Cleanup(cleanup)
			fakeRepoRoot, cleanup := fakeReleaseRepo(t)
			t.Cleanup(cleanup)
			v := &EnterpriseReleaseVersions{
				Hashrelease:     p.releaseName,
				RepoRootDir:     rootDir,
				TmpDir:          p.Dir,
				ProductVersion:  "v3.22.0-1.0",
				OperatorVersion: "v1.40.0",
				OperatorCfg: OperatorConfig{
					Image:    "tigera/operator",
					Registry: "quay.io",
				},
				HelmReleaseVersion: "0",
				outDir:             filepath.Join(fakeRepoRoot, relVersionsDirPath),
				ReleaseDirs:        tc.releaseDirs,
			}
			err := v.generateVersions()
			if tc.wantGenerateErr {
				if err == nil {
					t.Fatalf("expected error generating versions, but got none")
				}
				return
			}

			if err := v.updateVersionsFile(); err != nil {
				t.Fatalf("failed to update versions file: %v", err)
			}
			c, err := os.ReadFile(filepath.Join(fakeRepoRoot, relVersionsFilePath))
			if err != nil {
				t.Fatalf("failed to read versions file: %v", err)
			}
			approvals.VerifyString(t, string(c))
		})
	}
}

func fakeHashreleasePinnedVersions(t testing.TB, rootDir string) (*EnteprisePinnedVersions, func()) {
	tmpDir := t.TempDir()
	productBranch := "release-calient-v3.22-1"
	managerDir := fakeManagerRepo(t, rootDir, productBranch)
	p := &EnteprisePinnedVersions{
		CalicoPinnedVersions: CalicoPinnedVersions{
			Dir:                 tmpDir,
			RootDir:             rootDir,
			ReleaseBranchPrefix: "release-calient",
			OperatorCfg: OperatorConfig{
				Image:    "tigera/operator",
				Registry: "docker.io",
				Branch:   "release-v1.40",
			},
		},
		ManagerCfg: ManagerConfig{
			Branch: productBranch,
			Dir:    managerDir,
		},
		releaseName:   "test-release-name",
		productBranch: productBranch,
		calicoStream:  "v3.31",
		versionData:   version.NewEnterpriseHashreleaseVersions(version.New("v3.22.0-1.0-calient-0.dev-741-gde13c547862d"), "0", "v1.40.0-0.dev-41-g2c4e573cd894", "v3.22.0-1.0-calient-0.dev-48-gc89d7d35db76"),
	}
	if err := generateEnterprisePinnedVersionFile(p); err != nil {
		t.Fatalf("failed to generate pinned versions file: %v", err)
	}
	return p, func() { _ = os.RemoveAll(tmpDir) }
}

func fakeReleaseRepo(t testing.TB) (string, func()) {
	t.Helper()
	dir := t.TempDir()
	fakeRepoRoot := filepath.Join(dir, utils.CalicoPrivateRepo)

	if err := os.MkdirAll(fakeRepoRoot, 0o755); err != nil {
		t.Fatalf("failed to create test data dir: %v", err)
	}
	return fakeRepoRoot, func() { _ = os.RemoveAll(dir) }
}
