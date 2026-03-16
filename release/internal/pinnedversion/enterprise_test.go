package pinnedversion

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	approvals "github.com/approvals/go-approval-tests"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/version"
)

func TestEnterprisePinnedVersion(t *testing.T) {
	t.Run("GetComponentImagesNames", func(t *testing.T) {
		v := &EnterprisePinnedVersion{
			PinnedVersion: PinnedVersion{
				TigeraOperator: registry.Component{
					Image:    "tigera/operator",
					Registry: "docker.io/tigera",
					Version:  "v1.0.0",
				},
				Components: map[string]registry.Component{
					"alertmanager": {
						Version: "v1.0.0",
					},
					"compliance-server": {
						Version: "v1.0.0",
					},
					"calico-private": {
						Version: "v1.0.0",
					},
					managerComponentName: {
						Version: "v1.0.0",
					},
					fmt.Sprintf("%s-proxy", managerComponentName): {
						Version: "v1.0.0",
					},
				},
			},
		}
		t.Run("without operator", func(t *testing.T) {
			got := v.GetComponentImageNames(false)
			want := []string{"alertmanager", "compliance-server", managerComponentName}
			if diff := cmp.Diff(got, want, cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			})); diff != "" {
				t.Errorf("images do not match:\n%s", diff)
			}
		})
		t.Run("with operator", func(t *testing.T) {
			got := v.GetComponentImageNames(true)
			want := []string{"alertmanager", "compliance-server", managerComponentName, "tigera/operator"}
			if diff := cmp.Diff(got, want, cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			})); diff != "" {
				t.Errorf("images do not match:\n%s", diff)
			}
		})
	})
}

func TestGenerateEnterprisePinnedVersionFile(t *testing.T) {
	rootDir, err := command.GitDir()
	if err != nil {
		t.Fatalf("failed to get git root dir: %v", err)
	}
	t.Run("no manager", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		productBranch := "release-calient-v3.22"
		p := &EnteprisePinnedVersions{
			CalicoPinnedVersions: CalicoPinnedVersions{
				Dir:                 dir,
				RootDir:             rootDir,
				ReleaseBranchPrefix: "release",
				OperatorCfg: OperatorConfig{
					Image:    "tigera/operator",
					Registry: "quay.io",
					Branch:   "release-v1.41",
				},
			},
			releaseName:   "test-release",
			productBranch: productBranch,
			calicoStream:  "v3.31",
			versionData:   version.NewEnterpriseHashreleaseVersions(version.New("v3.22.1-calient-0.dev-741-gde13c547862d"), "0", "v1.41.1-0.dev-41-g2c4e573cd894", ""),
		}
		err = generateEnterprisePinnedVersionFile(p)
		if err != nil {
			t.Fatalf("failed to generate pinned version file: %v", err)
		}
		pinnedVersionPath := PinnedVersionFilePath(dir)
		if _, err := os.Stat(pinnedVersionPath); err != nil {
			t.Fatalf("pinned version file not created: %v", err)
		}
		content, err := os.ReadFile(pinnedVersionPath)
		if err != nil {
			t.Fatalf("failed to read pinned version file: %v", err)
		}
		approvals.VerifyString(t, string(content), approvals.Options().WithScrubber(dateApprovalScrubber))
	})

	t.Run("all", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		productBranch := "release-calient-v3.22-1"
		managerDir := fakeManagerRepo(t, rootDir, productBranch)
		p := &EnteprisePinnedVersions{
			CalicoPinnedVersions: CalicoPinnedVersions{
				Dir:                 dir,
				RootDir:             rootDir,
				ReleaseBranchPrefix: "release",
				OperatorCfg: OperatorConfig{
					Image:    "tigera/operator",
					Registry: "docker.io",
					Branch:   "release-v1.40",
				},
			},
			ManagerCfg: ManagerConfig{
				Dir:    managerDir,
				Branch: productBranch,
			},
			releaseName:   "test-release",
			productBranch: productBranch,
			calicoStream:  "v3.31",
			versionData:   version.NewEnterpriseHashreleaseVersions(version.New("v3.22.0-1.0-calient-0.dev-741-gde13c547862d"), "0", "v1.40.0-0.dev-41-g2c4e573cd894", "v3.22.0-1.0-calient-0.dev-48-gc89d7d35db76"),
		}
		err = generateEnterprisePinnedVersionFile(p)
		if err != nil {
			t.Fatalf("failed to generate pinned version file: %v", err)
		}
		pinnedVersionPath := PinnedVersionFilePath(dir)
		if _, err := os.Stat(pinnedVersionPath); err != nil {
			t.Fatalf("pinned version file not created: %v", err)
		}
		content, err := os.ReadFile(pinnedVersionPath)
		if err != nil {
			t.Fatalf("failed to read pinned version file: %v", err)
		}
		approvals.VerifyString(t, string(content), approvals.Options().WithScrubber(dateApprovalScrubber))
	})

	t.Run("hashrelease", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		productBranch := "release-calient-v3.22-1"
		managerDir := fakeManagerRepo(t, rootDir, productBranch)
		p := &EnteprisePinnedVersions{
			CalicoPinnedVersions: CalicoPinnedVersions{
				Dir:                 dir,
				RootDir:             rootDir,
				ReleaseBranchPrefix: "release",
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
			releaseName:   "test-release",
			productBranch: productBranch,
			calicoStream:  "v3.31",
			versionData:   version.NewEnterpriseHashreleaseVersions(version.New("v3.22.0-1.0-calient-0.dev-741-gde13c547862d"), "0", "v1.40.0-0.dev-41-g2c4e573cd894", "v3.22.0-1.0-calient-0.dev-48-gc89d7d35db76"),
		}
		err = generateEnterprisePinnedVersionFile(p)
		if err != nil {
			t.Fatalf("failed to generate pinned version file: %v", err)
		}
		pinnedVersionPath := PinnedVersionFilePath(dir)
		if _, err := os.Stat(pinnedVersionPath); err != nil {
			t.Fatalf("pinned version file not created: %v", err)
		}
		content, err := os.ReadFile(pinnedVersionPath)
		if err != nil {
			t.Fatalf("failed to read pinned version file: %v", err)
		}
		approvals.VerifyString(t, string(content), approvals.Options().WithScrubber(dateApprovalScrubber))
	})
}

func TestGenerateEnterpriseOperatorComponents(t *testing.T) {
	dir := t.TempDir()
	rootDir, err := command.GitDir()
	if err != nil {
		t.Fatalf("failed to get git root dir: %v", err)
	}
	productBranch := "release-calient-v3.22"
	managerDir := fakeManagerRepo(t, rootDir, productBranch)
	p := &EnteprisePinnedVersions{
		CalicoPinnedVersions: CalicoPinnedVersions{
			Dir:                 dir,
			RootDir:             rootDir,
			ReleaseBranchPrefix: "release",
			OperatorCfg: OperatorConfig{
				Image:    "tigera/operator",
				Registry: "quay.io",
				Branch:   "release-v1.40",
			},
		},
		ManagerCfg: ManagerConfig{
			Dir:    managerDir,
			Branch: productBranch,
		},
		releaseName:   "test-release",
		productBranch: "release-calient-v3.22",
		calicoStream:  "v3.31",
		versionData:   version.NewEnterpriseHashreleaseVersions(version.New("v3.22.0"), "0", "v1.40.0", "v3.22.0"),
	}
	err = generateEnterprisePinnedVersionFile(p)
	if err != nil {
		t.Fatalf("failed to generate pinned version file: %v", err)
	}
	err = GenerateEnterpriseOperatorComponents(dir, "")
	if err != nil {
		t.Fatalf("failed to generate operator components: %v", err)
	}
	f, err := os.ReadFile(filepath.Join(dir, operatorComponentsFileName))
	if err != nil {
		t.Fatalf("failed to read generated file: %v", err)
	}
	approvals.VerifyString(t, string(f), approvals.Options().WithScrubber(dateApprovalScrubber))
}

func fakeManagerRepo(t testing.TB, monoRepoDir, branch string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "manager")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("failed to create temp dir for manager: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	// create a git repo
	if _, err := command.GitInDir(dir, "init", "-b", branch); err != nil {
		t.Fatalf("failed to init git repo: %v", err)
	}
	// create Makefile with lib.Makefile
	makefilePath := filepath.Join(dir, "Makefile")
	makefileContent := fmt.Sprintf(`MANAGER_IMAGE         ?=manager
BUILD_IMAGES          ?=$(MANAGER_IMAGE)

include %s/lib.Makefile
`, monoRepoDir)
	if err := os.WriteFile(makefilePath, []byte(makefileContent), 0o644); err != nil {
		t.Fatalf("failed to write Makefile: %v", err)
	}
	return dir
}
