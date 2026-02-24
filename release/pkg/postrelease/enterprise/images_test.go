package enterprise

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/pkg/manager/operator"
)

var cloudImages = []string{"kibana", "kube-controllers"}

func TestImagesPublished(t *testing.T) {
	t.Parallel()

	if skipImages {
		t.Skip("Skipping image validation as per flag")
		return
	}

	checkVersion(t, releaseVersion)
	checkImages(t, images)

	for image := range strings.SplitSeq(images, " ") {
		fqImage := fmt.Sprintf("%s/%s:%s", releaseRegistry, image, releaseVersion)
		t.Run(fqImage, func(t *testing.T) {
			if ok, err := registry.CheckImage(fqImage); err != nil {
				t.Fatalf("failed to check image %s: %v", fqImage, err)
			} else if !ok {
				t.Fatalf("image (%s) not found", fqImage)
			}
			t.Logf("Image %s found", fqImage)
			if !strings.HasSuffix(image, "windows") {
				for _, arch := range arches {
					t.Run(fmt.Sprintf("linux %s", arch), func(t *testing.T) {
						fqArchImage := fmt.Sprintf("%s-%s", fqImage, arch)
						if ok, err := registry.CheckImage(fqArchImage); err != nil {
							t.Fatalf("failed to check image %s: %v", fqArchImage, err)
						} else if !ok {
							t.Fatalf("image (%s) not found", fqArchImage)
						}
						t.Logf("Image %s found for architecture %s", fqImage, arch)
					})
				}
			}
			if slices.Contains(cloudImages, image) {
				fqCloudImage := fmt.Sprintf("%s/%s:tesla-%s", releaseRegistry, image, releaseVersion)
				if ok, err := registry.CheckImage(fqCloudImage); err != nil {
					t.Fatalf("failed to check image %s: %v", fqCloudImage, err)
				} else if !ok {
					t.Fatalf("image (%s) not found", fqCloudImage)
				}
				t.Logf("Cloud image %s found", fqCloudImage)
			}
		})
	}

	t.Run("Tigera Operator", func(t *testing.T) {
		t.Parallel()

		if skipOperator {
			t.Skip("Skipping Tigera Operator validation as per flag")
			return
		}

		checkVersion(t, operatorVersion)

		fqOperatorImage := fmt.Sprintf("%s/%s:%s", operator.DefaultRegistry, operator.DefaultImage, operatorVersion)
		if ok, err := registry.CheckImage(fqOperatorImage); err != nil {
			t.Fatalf("failed to check image %s: %v", fqOperatorImage, err)
		} else if !ok {
			t.Fatalf("image (%s) not found", fqOperatorImage)
		}
		t.Logf("Tigera Operator image %s found", fqOperatorImage)

		for _, arch := range arches {
			t.Run(fmt.Sprintf("linux %s", arch), func(t *testing.T) {
				fqImage := fmt.Sprintf("%s-%s", fqOperatorImage, arch)
				if ok, err := registry.CheckImage(fqImage); err != nil {
					t.Fatalf("failed to check image %s: %v", fqImage, err)
				} else if !ok {
					t.Fatalf("image (%s) not found", fqImage)
				}
				t.Logf("Tigera Operator image %s found for architecture %s", fqOperatorImage, arch)
			})
		}
	})
}
