package tasks

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/pinnedversion"
	"github.com/projectcalico/calico/release/internal/slack"
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

// Update the Slack announcement for a hashrelease to indicate that it has passed smoke tests.
func AnnounceTestedHashrelease(cfg *slack.Config, path string, passed bool, testCIURL string) error {
	if !passed {
		logrus.Warn("Hashrelease did not pass smoke test, not updating message")
		return nil
	}
	logrus.Info("Updating hashrelease Slack message to indicate tests have passed")
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("unable to read hashrelease details from %s: %w", path, err)
	}
	var hashrel outputs.PublishedHashrelease
	if err := yaml.Unmarshal(b, &hashrel); err != nil {
		return fmt.Errorf("unable to unmarshal hashrelease details from %s: %w", path, err)
	}
	if hashrel.SlackResponse == nil || hashrel.SlackResponse.Timestamp == "" {
		logrus.Warn("No Slack message to update for hashrelease")
		return nil
	}
	if hashrel.SlackResponse.Channel == "" {
		hashrel.SlackResponse.Channel = cfg.Channel
	}
	msgData := &slack.ValidatedHashreleaseMessageData{
		ReleaseName:        hashrel.Hashrelease.Name,
		Product:            product,
		Stream:             hashrel.Hashrelease.Stream,
		ProductVersion:     hashrel.Hashrelease.ProductVersion,
		OperatorVersion:    hashrel.Hashrelease.OperatorVersion,
		ReleaseType:        "hashrelease",
		CIURL:              hashrel.CIURL,
		TestResultURL:      testCIURL,
		DocsURL:            hashrel.Hashrelease.URL(),
		ImageScanResultURL: hashrel.Hashrelease.ImageScanResultURL,
	}
	return slack.UpdateHashreleaseAnnouncement(cfg, hashrel.SlackResponse, msgData)
}
