package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v3"

	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/pkg/manager/manager"
)

var (
	managerFlags = []cli.Flag{managerRemoteFlag, managerOrgFlag, managerRepoFlag, managerBranchFlag, managerDevTagSuffixFlag}

	managerOrgFlag = &cli.StringFlag{
		Name:    "manager-org",
		Usage:   "The GitHub organization of the manager repository",
		Sources: cli.EnvVars("MANAGER_ORG", "MANAGER_ORGANIZATION"),
		Value:   manager.DefaultOrg,
	}

	managerRepoFlag = &cli.StringFlag{
		Name:    "manager-repo",
		Usage:   "The GitHub repository of the manager",
		Sources: cli.EnvVars("MANAGER_REPO", "MANAGER_GIT_REPO"),
		Value:   manager.DefaultRepoName,
	}

	managerBranchFlag = &cli.StringFlag{
		Name:    "manager-branch",
		Usage:   "The branch of the manager repository",
		Sources: cli.EnvVars("MANAGER_BRANCH"),
		Value:   manager.DefaultBranchName,
	}

	managerBaseBranchFlag = &cli.StringFlag{
		Name:    "manager-base-branch",
		Usage:   "The base branch to cut the Tigera manager release branch from",
		Sources: cli.EnvVars("MANAGER_BASE_BRANCH"),
		Value:   manager.DefaultBranchName,
		Action: func(_ context.Context, c *cli.Command, str string) error {
			if str != manager.DefaultBranchName {
				logrus.Warnf("The new branch will be created from %s which is not the default branch %s", str, manager.DefaultBranchName)
			}
			return nil
		},
	}

	managerRemoteFlag = &cli.StringFlag{
		Name:    "manager-remote",
		Usage:   "The remote of the manager repository",
		Sources: cli.EnvVars("MANAGER_REMOTE", "MANAGER_GIT_REMOTE"),
		Value:   manager.DefaultRemote,
	}

	managerDevTagSuffixFlag = &cli.StringFlag{
		Name:    "manager-dev-tag-suffix",
		Usage:   "The suffix used to denote development tags",
		Sources: cli.EnvVars("MANAGER_DEV_TAG_SUFFIX"),
		Value:   manager.DefaultDevTagSuffix,
	}

	managerReleaseBranchPrefixFlag = &cli.StringFlag{
		Name:    "manager-release-branch-prefix",
		Usage:   "The prefix to use for release branches",
		Sources: cli.EnvVars("MANAGER_RELEASE_BRANCH_PREFIX"),
		Value:   releaseBranchPrefixFlag.Value,
	}

	skipManagerFlag = &cli.BoolFlag{
		Name:    "skip-manager",
		Usage:   "Skip the manager step",
		Sources: cli.EnvVars("SKIP_MANAGER"),
		Value:   false,
	}
)

var hashReleaseRegistryFlag = &cli.StringFlag{
	Name:    "hashrelease-registry",
	Aliases: []string{"hr-registry"},
	Usage:   "The registry to get hashrelease images from to use for release",
	Sources: cli.EnvVars("HASHRELEASE_REGISTRY"),
}

var (
	publishWindowsArchiveFlag = &cli.BoolFlag{
		Name:    "publish-windows-archive",
		Usage:   "Publish the Windows archive to GCS",
		Sources: cli.EnvVars("PUBLISH_WINDOWS_ARCHIVE"),
		Value:   true,
	}

	publishToS3Flag = &cli.BoolFlag{
		Name:    "publish-to-s3",
		Usage:   "Publish the release to S3",
		Sources: cli.EnvVars("PUBLISH_TO_S3"),
		Value:   true,
	}
)

var skipRPMsFlag = &cli.BoolFlag{
	Name:    "skip-rpms",
	Usage:   "Skip building or publishing RPMs",
	Sources: cli.EnvVars("SKIP_RPMS"),
	Value:   false,
}

var hashreleaseNameFlag = &cli.StringFlag{
	Name:     "hashrelease",
	Usage:    "The name of the hashrelease the release is based on",
	Sources:  cli.EnvVars("HASHRELEASE"),
	Required: true,
}

var operatorVersionFlag = &cli.StringFlag{
	Name:     "operator-version",
	Usage:    "The version of operator used in the release",
	Sources:  cli.EnvVars("OPERATOR_VERSION"),
	Required: true,
}

var releaseVersionFlag = &cli.StringFlag{
	Name:     "version",
	Usage:    "The version of Enterprise to release",
	Sources:  cli.EnvVars("RELEASE_VERSION"),
	Required: true,
}

// chartVersionFlag is only used for releases.
var chartVersionFlag = &cli.StringFlag{
	Name:     "chart-version",
	Usage:    "The version suffix for the helm charts",
	Sources:  cli.EnvVars("HELM_RELEASE", "CHART_VERSION"),
	Required: true,
}

var confirmFlag = &cli.BoolFlag{
	Name:    "confirm",
	Usage:   "Perform all the steps. If not set, it will be a dry-run",
	Sources: cli.EnvVars("CONFIRM"),
	Value:   false,
}

var windowsArchiveBucketFlag = &cli.StringFlag{
	Name:    "windows-gcs-bucket",
	Usage:   "The GCS bucket to publish the Windows archive to",
	Sources: cli.EnvVars("WINDOWS_GCS_BUCKET"),
}

var skipReleaseVersionCheckFlag = &cli.BoolFlag{
	Name:    "skip-version-check",
	Usage:   "Skip checking the release version matches the determined version",
	Sources: cli.EnvVars("SKIP_VERSION_CHECK"),
	Value:   false,
	Action: func(_ context.Context, c *cli.Command, b bool) error {
		if c.Bool(skipValidationFlag.Name) && !b {
			return fmt.Errorf("must skip branch check if %s is set", skipValidationFlag.Name)
		}
		return nil
	},
}

var baseArtifactsURLFlag = &cli.StringFlag{
	Name:    "artifacts-base-url",
	Usage:   "Base URL for accessing enterprise artifacts",
	Sources: cli.EnvVars("ARTIFACTS_BASE_URL"),
}

var skipImageValidationFlag = &cli.BoolFlag{
	Name:    "skip-image-validation",
	Usage:   "Skip validation of images",
	Sources: cli.EnvVars("SKIP_IMAGE_VALIDATION"),
	Value:   false,
}

var skipOperatorValidationFlag = &cli.BoolFlag{
	Name:    "skip-operator-validation",
	Usage:   "Skip validation of the Tigera operator image",
	Sources: cli.EnvVars("SKIP_OPERATOR_VALIDATION"),
	Value:   false,
}

var imageReleaseDirsFlag = &cli.StringSliceFlag{
	Name:    "image-release-dir",
	Usage:   "Override list of directories that publish images. Repeat for multiple directories.",
	Sources: cli.EnvVars("IMAGE_RELEASE_DIRS"),
	Action: func(ctx context.Context, c *cli.Command, dirs []string) error {
		parentReleaseDirs := make(map[string]struct{})
		for _, dir := range utils.EnterpriseImageReleaseDirs {
			parentReleaseDirs[dir] = struct{}{}
		}
		diff := []string{}
		for _, dir := range dirs {
			if _, ok := parentReleaseDirs[dir]; !ok {
				diff = append(diff, dir)
			}
		}
		if len(diff) > 0 {
			return fmt.Errorf("invalid image release dirs specified: %v", strings.Join(diff, ", "))
		}
		return nil
	},
}
