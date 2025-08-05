package utils

import (
	"fmt"
	"path/filepath"
	"strings"

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
