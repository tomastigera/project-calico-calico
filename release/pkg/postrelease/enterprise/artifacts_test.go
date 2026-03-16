package enterprise

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cloud.google.com/go/storage"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
	"github.com/projectcalico/calico/release/pkg/manager/calico"
)

var aptRepoExpectedFiles = []string{
	"Contents-%s.gz",
	"InRelease",
	"Release",
	"Release.gpg",
	"main/Contents-%s.gz",
	"main/binary-%s/Packages",
	"main/binary-%s/Packages.gz",
	"main/binary-%s/Release",
}

var (
	fluentBitVersionKey = "FLUENT_BIT_VERSION"
	fluentBitPath       = "fluent-bit"
)

func validateURL(t testing.TB, url, desc string) {
	t.Helper()
	resp, err := http.Head(url)
	if err != nil {
		t.Fatalf("failed to check for %s: %v", desc, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("could not access %s via %s: URL returned HTTP status code %d", desc, url, resp.StatusCode)
	}
	t.Logf("Successfully accessed %s at %s", desc, url)
}

func TestWindowsArchive(t *testing.T) {
	t.Parallel()

	checkVersion(t, releaseVersion)

	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		t.Fatalf("failed to create GCS client: %v", err)
	}

	parts := strings.Split(windowsBucket, "/")
	bucket := client.Bucket(parts[0])
	objName := fmt.Sprintf("tigera-calico-windows-%s.zip", releaseVersion)
	if len(parts) > 1 {
		objName = filepath.Join(parts[1], objName)
	}
	obj := bucket.Object(objName)
	_, err = obj.Attrs(ctx)
	if err != nil {
		if err == storage.ErrObjectNotExist {
			t.Fatalf("Windows archive for version %s does not exist in GCS bucket %s", releaseVersion, windowsBucket)
		}
		t.Fatalf("failed to get attributes for Windows archive: %v", err)
	}
	t.Logf("Windows archive for version %s exists in GCS bucket %s", releaseVersion, windowsBucket)
}

func TestManifests(t *testing.T) {
	checkVersion(t, releaseVersion)

	manifestsDir := filepath.Join(repoRootDir, "manifests")
	err := filepath.Walk(manifestsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			t.Fatalf("failed to access path %s: %v", path, err)
		}
		if info.IsDir() {
			return nil // Skip directories
		}
		if filepath.Ext(path) != ".yaml" && filepath.Ext(path) != ".yml" {
			return nil // Skip non-YAML files
		}
		relPath, err := filepath.Rel(manifestsDir, path)
		if err != nil {
			t.Fatalf("failed to get relative path for %s: %v", path, err)
		}
		t.Run(relPath, func(t *testing.T) {
			t.Parallel()
			validateURL(t, fmt.Sprintf("%s/%s/manifests/%s", artifactsBaseURL, releaseVersion, relPath), "manifest file "+relPath)
		})
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk manifests directory: %v", err)
	}

	t.Run("OCP bundle", func(t *testing.T) {
		t.Parallel()
		validateURL(t, fmt.Sprintf("%s/%s/manifests/ocp.tgz", artifactsBaseURL, releaseVersion), "OCP bundle")
	})
}

func TestHelmChart(t *testing.T) {
	t.Parallel()

	checkVersion(t, releaseVersion)
	if chartVersion == "" {
		t.Fatal("No chart version provided")
	}

	for _, chart := range utils.EnterpriseHelmCharts {
		t.Run(chart, func(t *testing.T) {
			t.Parallel()
			validateURL(t, fmt.Sprintf("%s/charts/%s-%s-%s.tgz", artifactsBaseURL, releaseVersion, chart, chartVersion), chart+" Helm chart")
		})
	}
}

func TestReleaseArchive(t *testing.T) {
	t.Parallel()

	checkVersion(t, releaseVersion)

	validateURL(t, fmt.Sprintf("%s/archives/release-%s-%s.tgz", artifactsBaseURL, releaseVersion, operatorVersion), "release archive")
}

func TestBinaries(t *testing.T) {
	checkVersion(t, releaseVersion)

	t.Run("calicoctl", func(t *testing.T) {
		t.Parallel()

		t.Run("linux", func(t *testing.T) {
			validateURL(t, fmt.Sprintf("%s/binaries/%s/calicoctl", artifactsBaseURL, releaseVersion), "calicoctl binary for Linux")
		})

		t.Run("mac", func(t *testing.T) {
			validateURL(t, fmt.Sprintf("%s/binaries/%s/calicoctl-darwin-amd64", artifactsBaseURL, releaseVersion), "calicoctl binary for Mac OSX")
		})

		t.Run("windows", func(t *testing.T) {
			validateURL(t, fmt.Sprintf("%s/binaries/%s/calicoctl-windows-amd64.exe", artifactsBaseURL, releaseVersion), "calicoctl binary for Windows")
		})
	})

	t.Run("calicoq", func(t *testing.T) {
		t.Parallel()

		validateURL(t, fmt.Sprintf("%s/binaries/%s/calicoq", artifactsBaseURL, releaseVersion), "calicoq binary")
	})
}

func resolveRPMVersion(t testing.TB, rpmVersion string) string {
	t.Helper()

	// hack/generate-package-version.sh
	v, err := command.RunInDir(repoRootDir, filepath.Join(repoRootDir, "hack", "generate-package-version.sh"), []string{repoRootDir, "rpm", "", rpmVersion})
	if err != nil {
		t.Fatalf("failed to determine full RPM version for %s: %v", rpmVersion, err)
	}
	return strings.TrimSpace(v)
}

func fetchFluentBitVersion(t testing.TB) string {
	t.Helper()

	args := []string{"-Po", fmt.Sprintf(`%s.*=\K(.*)`, fluentBitVersionKey), "Makefile"}
	out, err := command.RunInDir(filepath.Join(repoRootDir, fluentBitPath), "grep", args)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to determine fluent-bit version version from %s/Makefile: %w", fluentBitPath, err))
	}
	return out
}

// resolveDebVersion uses the generate-package-version.sh script to figure out what version should
// be in the target filename. Note that we have to call url.QueryEscape, and not url.PathEscape
// as one might normally assume, in order for S3/CloudFront to accept the URL, as some path-safe
// characters, such as `+`, may be in the filename but S3 will not accept them.
func resolveDEBVersion(t testing.TB, debVersion, debComponent string) string {
	t.Helper()

	// hack/generate-package-version.sh
	v, err := command.RunInDir(repoRootDir, filepath.Join(repoRootDir, "hack", "generate-package-version.sh"), []string{repoRootDir, "deb", debComponent, debVersion})
	if err != nil {
		t.Fatalf("failed to determine full debian package version for %s: %v", debComponent, err)
	}
	return url.QueryEscape(strings.TrimSpace(v))
}

func determineRPMVersion(t testing.TB, dir, key string) string {
	t.Helper()

	args := []string{"-Po", fmt.Sprintf(`%s.*=\K(.*)`, key), "Makefile"}
	out, err := command.RunInDir(filepath.Join(repoRootDir, dir), "grep", args)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to determine RPM version (via %s) for %s: %w", key, dir, err))
	}
	return out
}

func TestRPMS(t *testing.T) {
	checkVersion(t, releaseVersion)

	ver := version.New(releaseVersion)
	stream := ver.PrimaryStream()
	selinuxVersion := determineRPMVersion(t, "selinux", "CALICO_SELINUX_VERSION")
	fluentBitVersion := determineRPMVersion(t, "fluent-bit", fluentBitVersionKey)

	t.Run("RHEL yum/dnf repo file", func(t *testing.T) {
		t.Parallel()
		for _, rhel := range calico.RHELVersions {
			validateURL(t, fmt.Sprintf("%s/rpms/%s/calico_rhel%s.repo", artifactsBaseURL, stream, rhel), fmt.Sprintf("yum/dnf repo file for RHEL %s", rhel))
		}
	})

	t.Run("selinux", func(t *testing.T) {
		t.Parallel()
		for _, rhel := range calico.RHELVersions {
			validateURL(t, fmt.Sprintf("%s/rpms/%s/rhel%s/RPMS/noarch/calico-selinux-%s-1.el%s.noarch.rpm", artifactsBaseURL, stream, rhel, resolveRPMVersion(t, selinuxVersion), rhel), fmt.Sprintf("SELinux RPM for RHEL %s", rhel))
		}
	})

	t.Run("calico-node", func(t *testing.T) {
		t.Parallel()
		// https://downloads.tigera.io/ee/rpms/v3.20/rhel8/RPMS/x86_64/calico-node-3.20.4-1.el8.x86_64.rpm
		for _, rhel := range calico.RHELVersions {
			validateURL(t, fmt.Sprintf("%s/rpms/%s/rhel%s/RPMS/x86_64/calico-node-%s-1.el%s.x86_64.rpm", artifactsBaseURL, stream, rhel, resolveRPMVersion(t, ""), rhel), fmt.Sprintf("calico-node RPM for RHEL %s", rhel))
		}
	})
	t.Run("calico-fluent-bit", func(t *testing.T) {
		t.Parallel()
		for _, rhel := range calico.RHELVersions {
			validateURL(t, fmt.Sprintf("%s/rpms/%s/rhel%s/RPMS/x86_64/calico-fluent-bit-%s-1.el%s.x86_64.rpm", artifactsBaseURL, stream, rhel, resolveRPMVersion(t, fluentBitVersion), rhel), fmt.Sprintf("calico-fluent-bit RPM for RHEL %s", rhel))
		}
	})
}

func TestDEBS(t *testing.T) {
	checkVersion(t, releaseVersion)

	ver := version.New(releaseVersion)
	stream := ver.PrimaryStream()
	fluentBitVersion := fetchFluentBitVersion(t)

	t.Run("Apt sources file", func(t *testing.T) {
		t.Parallel()
		for _, component := range calico.NonClusterHostDebComponents {
			validateURL(t, fmt.Sprintf("%s/debs/%s/%s.sources", artifactsBaseURL, stream, component), fmt.Sprintf("apt sources file for component %s", component))
		}
	})

	t.Run("Apt repository structure", func(t *testing.T) {
		t.Parallel()
		for _, component := range calico.NonClusterHostDebComponents {
			baseURL := fmt.Sprintf("%s/debs/%s/dists/%s", artifactsBaseURL, stream, component)
			for _, arch := range calico.NonClusterHostArchs {
				for _, fileName := range aptRepoExpectedFiles {
					if strings.Contains(fileName, "%s") {
						fileName = fmt.Sprintf(fileName, arch)
					}
					url := fmt.Sprintf("%s/%s", baseURL, fileName)
					validateURL(t, url, fmt.Sprintf("apt repo file %s", component))
				}
			}
		}
	})

	t.Run("Uploaded calico-node", func(t *testing.T) {
		t.Parallel()
		for _, arch := range calico.NonClusterHostArchs {
			for _, component := range calico.NonClusterHostDebComponents {
				packageVersion := resolveDEBVersion(t, releaseVersion, component)
				URL := fmt.Sprintf("%s/debs/%s/pool/main/c/calico-node/calico-node_%s_%s.deb", artifactsBaseURL, stream, packageVersion, arch)
				validateURL(t, URL, fmt.Sprintf("calico-node deb for %s on %s", component, arch))
			}
		}
	})
	t.Run("Uploaded calico-fluent-bit", func(t *testing.T) {
		t.Parallel()
		for _, arch := range calico.NonClusterHostArchs {
			for _, component := range calico.NonClusterHostDebComponents {
				fluentBitVersion := resolveDEBVersion(t, fluentBitVersion, component)
				URL := fmt.Sprintf("%s/debs/%s/pool/main/c/calico-fluent-bit/calico-fluent-bit_%s_%s.deb", artifactsBaseURL, stream, fluentBitVersion, arch)
				validateURL(t, URL, fmt.Sprintf("calico-fluent-bit deb for %s on %s", component, arch))
			}
		}
	})

}
