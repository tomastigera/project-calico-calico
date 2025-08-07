package pinnedversion

import (
	"fmt"
	"testing"

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
		got := v.GetComponentImageNames()
		want := []string{"alertmanager", "compliance-server", managerComponent}
		if diff := cmp.Diff(got, want, cmpopts.SortSlices(func(a, b string) bool {
			return a < b
		})); diff != "" {
			t.Errorf("images do not match:\n%s", diff)
		}
	})
}
