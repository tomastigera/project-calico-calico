package enterprise

import (
	"flag"
	"strings"
	"testing"

	"github.com/projectcalico/calico/release/pkg/manager/operator"
)

var arches = []string{"amd64", "arm64"}

var (
	repoRootDir                                   string
	releaseVersion, operatorVersion, chartVersion string
	images                                        string
	githubToken                                   string
)

func init() {
	flag.StringVar(&repoRootDir, "repo-root", "", "Root directory of the repository")
	flag.StringVar(&releaseVersion, "release-version", "", "Version for the release")
	flag.StringVar(&operatorVersion, "operator-version", "", "Version for Tigera operator")
	flag.StringVar(&chartVersion, "chart-version", "", "Version for the Helm chart")
	flag.StringVar(&githubToken, "github-token", "", "GitHub token for API access")
	flag.StringVar(&images, "images", "", "List of images to check")
}

func checkVersion(t testing.TB, version string) {
	t.Helper()
	if version == "" {
		t.Fatal("No version provided")
	}
}

func checkImages(t testing.TB, images string) {
	t.Helper()
	if images == "" {
		t.Fatal("No images provided")
	}
	list := strings.Split(images, " ")
	if len(list) == 0 {
		t.Fatal("No images provided")
	}
	for _, image := range list {
		if strings.Contains(image, operator.DefaultImage) {
			t.Fatal("Operator image should not be included in the images list")
		}
	}
}
