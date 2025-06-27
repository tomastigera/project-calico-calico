package enterprise

import (
	"context"
	"fmt"
	"net/http"
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

const downloadBaseURL = "https://downloads.tigera.io/ee"

func validateURL(t testing.TB, url, desc string) {
	t.Helper()
	resp, err := http.Head(url)
	if err != nil {
		t.Fatalf("failed to check for %s: %v", desc, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("could not access %s via %s: %v", desc, url, err)
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

	bucket := client.Bucket(utils.WindowsGCSBucketName)
	obj := bucket.Object(fmt.Sprintf("tigera-calico-windows-%s.zip", releaseVersion))
	_, err = obj.Attrs(ctx)
	if err != nil {
		if err == storage.ErrObjectNotExist {
			t.Fatalf("Windows archive for version %s does not exist in GCS bucket %s", releaseVersion, utils.WindowsGCSBucketName)
		}
		t.Fatalf("failed to get attributes for Windows archive: %v", err)
	}
	t.Logf("Windows archive for version %s exists in GCS bucket %s", releaseVersion, utils.WindowsGCSBucketName)
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
			validateURL(t, fmt.Sprintf("%s/%s/manifests/%s", downloadBaseURL, releaseVersion, relPath), "manifest file "+relPath)
		})
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk manifests directory: %v", err)
	}

	t.Run("OCP bundle", func(t *testing.T) {
		t.Parallel()
		validateURL(t, fmt.Sprintf("%s/%s/manifests/ocp.tgz", downloadBaseURL, releaseVersion), "OCP bundle")
	})
}

func TestHelmChart(t *testing.T) {
	t.Parallel()

	checkVersion(t, releaseVersion)
	if chartVersion == "" {
		t.Fatal("No chart version provided")
	}

	validateURL(t, fmt.Sprintf("%s/charts/tigera-operator-%s-%s.tgz", downloadBaseURL, releaseVersion, chartVersion), "Helm chart")
}

func TestReleaseArchive(t *testing.T) {
	t.Parallel()

	checkVersion(t, releaseVersion)

	validateURL(t, fmt.Sprintf("%s/archives/release-%s-%s.tgz", downloadBaseURL, releaseVersion, operatorVersion), "release archive")
}

func TestBinaries(t *testing.T) {
	checkVersion(t, releaseVersion)

	t.Run("calicoctl", func(t *testing.T) {
		t.Parallel()

		t.Run("linux", func(t *testing.T) {
			validateURL(t, fmt.Sprintf("%s/binaries/%s/calicoctl", downloadBaseURL, releaseVersion), "calicoctl binary for Linux")
		})

		t.Run("mac", func(t *testing.T) {
			validateURL(t, fmt.Sprintf("%s/binaries/%s/calicoctl-darwin-amd64", downloadBaseURL, releaseVersion), "calicoctl binary for Mac OSX")
		})

		t.Run("windows", func(t *testing.T) {
			validateURL(t, fmt.Sprintf("%s/binaries/%s/calicoctl-windows-amd64.exe", downloadBaseURL, releaseVersion), "calicoctl binary for Windows")
		})
	})

	t.Run("calicoq", func(t *testing.T) {
		t.Parallel()

		validateURL(t, fmt.Sprintf("%s/binaries/%s/calicoq", downloadBaseURL, releaseVersion), "calicoq binary")
	})
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
	fluentBitVersion := determineRPMVersion(t, "fluent-bit", "FLUENT_BIT_VERSION")

	t.Run("RHEL yum/dnf repo file", func(t *testing.T) {
		t.Parallel()
		for _, rhel := range calico.RHELVersions {
			validateURL(t, fmt.Sprintf("%s/rpms/%s/calico_rhel%s.repo", downloadBaseURL, stream, rhel), fmt.Sprintf("yum/dnf repo file for RHEL %s", rhel))
		}
	})

	t.Run("selinux", func(t *testing.T) {
		t.Parallel()
		for _, rhel := range calico.RHELVersions {
			validateURL(t, fmt.Sprintf("%s/rpms/%s/rhel%s/RPMS/noarch/calico-selinux-%s-1.el%s.noarch.rpm", downloadBaseURL, stream, rhel, selinuxVersion, rhel), fmt.Sprintf("SELinux RPM for RHEL %s", rhel))
		}
	})

	t.Run("calico-node", func(t *testing.T) {
		t.Parallel()
		// https://downloads.tigera.io/ee/rpms/v3.20/rhel8/RPMS/x86_64/calico-node-3.20.4-1.el8.x86_64.rpm
		for _, rhel := range calico.RHELVersions {
			validateURL(t, fmt.Sprintf("%s/rpms/%s/rhel%s/RPMS/x86_64/calico-node-%s-1.el%s.x86_64.rpm", downloadBaseURL, stream, rhel, strings.TrimPrefix(releaseVersion, "v"), rhel), fmt.Sprintf("calico-node RPM for RHEL %s", rhel))
		}
	})
	t.Run("calico-fluent-bit", func(t *testing.T) {
		t.Parallel()
		for _, rhel := range calico.RHELVersions {
			validateURL(t, fmt.Sprintf("%s/rpms/%s/rhel%s/RPMS/x86_64/calico-fluent-bit-%s-1.el%s.x86_64.rpm", downloadBaseURL, stream, rhel, fluentBitVersion, rhel), fmt.Sprintf("calico-fluent-bit RPM for RHEL %s", rhel))
		}
	})
}
