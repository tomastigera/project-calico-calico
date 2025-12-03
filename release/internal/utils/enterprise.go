package utils

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
)

const (
	CalicoEnterprise = "calico enterprise"

	EnterpriseProductName = "Calico Enterprise"

	// CalicoPrivateRepo is the name of the private repo in Tigera.
	CalicoPrivateRepo = "calico-private"

	TigeraManager = "manager"

	// EnterpriseProductCode is the code for calico enterprise.
	EnterpriseProductCode = "cnx"

	EnterpriseWindowsGCSBucketName = "tigera-windows"

	// EnterpriseArtifactsBaseURL is the base URL for accessing enterprise artifacts.
	EnterpriseArtifactsBaseURL = "https://downloads.tigera.io/ee"
)

var onceEnterprise sync.Once

var (
	EnterpriseImageReleaseDirs = []string{
		"apiserver",
		"app-policy",
		"calicoctl",
		"cni-plugin",
		"kube-controllers",
		"node",
		"typha",
		"calicoq",
		"compliance",
		"deep-packet-inspection",
		"egress-gateway",
		"elasticsearch-metrics",
		"elasticsearch",
		"es-gateway",
		"ui-apis",
		"firewall-integration",
		"fluentd",
		"gateway",
		"ingress-collector",
		"intrusion-detection-controller",
		"istio",
		"key-cert-provisioner",
		"kibana",
		"l7-admission-controller",
		"l7-collector",
		"license-agent",
		"linseed",
		"packetcapture",
		"pod2daemon",
		"policy-recommendation",
		"prometheus-service",
		"queryserver",
		"voltron",
		"webhooks-processor",
		"third_party/alertmanager",
		"third_party/dex",
		"third_party/eck-operator",
		"third_party/envoy-gateway",
		"third_party/envoy-proxy",
		"third_party/envoy-ratelimit",
		"third_party/istio-ztunnel",
		"third_party/prometheus-operator",
		"third_party/prometheus",
	}

	enterpriseReleaseImages = []string{}
)

func DetermineCalicoVersion(repoRoot string) (string, error) {
	args := []string{"-Po", `CALICO_VERSION=\K(.*)`, "metadata.mk"}
	out, err := command.RunInDir(repoRoot, "grep", args)
	if err != nil {
		return "", err
	}
	return out, nil
}

func CheckoutHashreleaseVersion(hashVersion string, repoRootDir string) error {
	verParts := strings.Split(hashVersion, "-")
	gitHash := strings.TrimPrefix(verParts[len(verParts)-1], "g")
	if _, err := command.GitInDir(repoRootDir, "checkout", gitHash); err != nil {
		return fmt.Errorf("failed to checkout %s repo at hash %s: %w", filepath.Base(repoRootDir), gitHash, err)
	}
	return nil
}

func EnterpriseReleaseImages() []string {
	onceEnterprise.Do(func() {
		initEnterpriseImages()
	})
	return slices.Clone(enterpriseReleaseImages)
}

func initEnterpriseImages() {
	rootDir, err := command.GitDir()
	if err != nil {
		logrus.Panicf("Failed to get root dir: %v", err)
	}
	images, err := BuildReleaseImageList(rootDir, EnterpriseImageReleaseDirs...)
	if err != nil {
		logrus.Panicf("Failed to get images for enterprise release dirs: %v", err)
	}
	enterpriseReleaseImages = images
}
