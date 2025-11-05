package pinnedversion

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	approvals "github.com/approvals/go-approval-tests"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/projectcalico/calico/release/internal/registry"
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
					managerComponent: {
						Version: "v1.0.0",
					},
					fmt.Sprintf("%s-proxy", managerComponent): {
						Version: "v1.0.0",
					},
				},
			},
		}
		t.Run("without operator", func(t *testing.T) {
			got := v.GetComponentImageNames(false)
			want := []string{"alertmanager", "compliance-server", managerComponent}
			if diff := cmp.Diff(got, want, cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			})); diff != "" {
				t.Errorf("images do not match:\n%s", diff)
			}
		})
		t.Run("with operator", func(t *testing.T) {
			got := v.GetComponentImageNames(true)
			want := []string{"alertmanager", "compliance-server", managerComponent, "tigera/operator", "tigera/operator-init"}
			if diff := cmp.Diff(got, want, cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			})); diff != "" {
				t.Errorf("images do not match:\n%s", diff)
			}
		})
	})
}

func TestGenerateEnterpriseOperatorComponents(t *testing.T) {
	dir := t.TempDir()
	data := &enterpriseTemplateData{
		ReleaseName:    "test-release",
		BaseDomain:     "example.com",
		ProductVersion: "vX.Y.Z",
		Operator: registry.Component{
			Version:  "vA.B.C",
			Image:    "tigera/operator",
			Registry: "quay.io",
		},
		Hash:               "vX.Y.Z-vA.B.C-vD.E.F",
		Note:               "Test note",
		ReleaseBranch:      "release-calient-v1.0",
		CalicoMinorVersion: "vF.G",
		ManagerVersion:     "vD.E.F",
	}
	err := generateEnterprisePinnedVersionFile(data, dir)
	if err != nil {
		t.Fatalf("failed to generate pinned version file: %v", err)
	}
	op, expectedPath, err := GenerateEnterpriseOperatorComponents(dir, "")
	if err != nil {
		t.Fatalf("failed to generate operator components: %v", err)
	}
	expectedOperator := registry.OperatorComponent{
		Component: registry.Component{
			Version:  "vA.B.C",
			Image:    "tigera/operator",
			Registry: "quay.io",
		},
	}
	if diff := cmp.Diff(op, expectedOperator); diff != "" {
		t.Errorf("operator does not match expected:\n%s", diff)
	}
	if expectedPath != filepath.Join(dir, operatorComponentsFileName) {
		t.Errorf("path does not match expected: got %s, want %s", expectedPath, filepath.Join(dir, operatorComponentsFileName))
	}
	f, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("failed to read generated file: %v", err)
	}
	approvals.VerifyString(t, string(f))
}
