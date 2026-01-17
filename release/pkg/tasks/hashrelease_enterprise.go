package tasks

import (
	"fmt"
	"path/filepath"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/pinnedversion"
	"github.com/projectcalico/calico/release/internal/utils"
)

func ReformatEnterpriseHashrelease(hashreleaseOutputDir, tmpDir string) error {
	logrus.Info("Modifying hashrelease output to match legacy format")
	versions, err := pinnedversion.RetrieveEnterpriseVersions(tmpDir)
	if err != nil {
		return fmt.Errorf("failed to retrieve pinned versions: %w", err)
	}

	// Copy the operator tarball to tigera-operator.tgz
	operatorTarball := filepath.Join(hashreleaseOutputDir, "charts", fmt.Sprintf("tigera-operator-%s.tgz", versions.HelmChartVersion()))
	operatorTarballDst := filepath.Join(hashreleaseOutputDir, "tigera-operator.tgz")
	if err := utils.CopyFile(operatorTarball, operatorTarballDst); err != nil {
		return err
	}
	return nil
}
