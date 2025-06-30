package main

import (
	"fmt"

	cli "github.com/urfave/cli/v2"

	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/pkg/manager/manager"
)

var (
	managerFlags = []cli.Flag{managerRemoteFlag, managerOrgFlag, managerRepoFlag, managerBranchFlag, managerDevTagSuffixFlag}

	managerOrgFlag = &cli.StringFlag{
		Name:    "manager-org",
		Usage:   "The GitHub organization of the manager repository",
		EnvVars: []string{"MANAGER_ORG"},
		Value:   manager.DefaultOrg,
	}

	managerRepoFlag = &cli.StringFlag{
		Name:    "manager-repo",
		Usage:   "The GitHub repository of the manager",
		EnvVars: []string{"MANAGER_REPO"},
		Value:   manager.DefaultRepoName,
	}

	managerBranchFlag = &cli.StringFlag{
		Name:    "manager-branch",
		Usage:   "The branch of the manager repository",
		EnvVars: []string{"MANAGER_BRANCH"},
		Value:   manager.DefaultBranchName,
	}

	managerRemoteFlag = &cli.StringFlag{
		Name:    "manager-remote",
		Usage:   "The remote of the manager repository",
		EnvVars: []string{"MANAGER_REMOTE"},
		Value:   manager.DefaultRemote,
	}

	managerDevTagSuffixFlag = &cli.StringFlag{
		Name:    "manager-dev-tag-suffix",
		Usage:   "The suffix used to denote development tags",
		EnvVars: []string{"MANAGER_DEV_TAG_SUFFIX"},
		Value:   manager.DefaultDevTagSuffix,
	}
)

var helmRegistryFlag = &cli.StringFlag{
	Name:    "helm-registry",
	Usage:   "The registry to publish the helm charts (hashrelease ONLY)",
	EnvVars: []string{"HELM_REGISTRY"},
	Value:   registry.HelmDevRegistry,
}

var (
	publishWindowsArchiveFlag = &cli.BoolFlag{
		Name:    "publish-windows-archive",
		Usage:   "Publish the Windows archive to GCS",
		EnvVars: []string{"PUBLISH_WINDOWS_ARCHIVE"},
		Value:   true,
	}

	publishChartsFlag = &cli.BoolFlag{
		Name:    "publish-charts",
		Usage:   "Publish the helm charts",
		EnvVars: []string{"PUBLISH_CHARTS"},
		Value:   true,
	}

	publishToS3Flag = &cli.BoolFlag{
		Name:    "publish-to-s3",
		Usage:   "Publish the release to S3",
		EnvVars: []string{"PUBLISH_TO_S3"},
		Value:   true,
	}

	publishGitFlag = &cli.BoolFlag{
		Name:    "publish-git",
		Usage:   "Publish git changes to remote",
		EnvVars: []string{"PUBLISH_GIT"},
		Value:   true,
	}
)

var skipRPMsFlag = &cli.BoolFlag{
	Name:    "skip-rpms",
	Usage:   "Skip building or publishing RPMs",
	EnvVars: []string{"SKIP_RPMS"},
	Value:   false,
}

var hashreleaseNameFlag = &cli.StringFlag{
	Name:     "hashrelease",
	Usage:    "The name of the hashrelease the release is based on",
	EnvVars:  []string{"HASHRELEASE"},
	Required: true,
}

var operatorVersionFlag = &cli.StringFlag{
	Name:     "operator-version",
	Usage:    "The version of operator used in the release",
	EnvVars:  []string{"OPERATOR_VERSION"},
	Required: true,
}

var releaseVersionFlag = &cli.StringFlag{
	Name:     "version",
	Usage:    "The version of Enterprise to release",
	EnvVars:  []string{"RELEASE_VERSION"},
	Required: true,
}

// chartVersionFlag is only used for releases.
var chartVersionFlag = &cli.StringFlag{
	Name:     "chart-version",
	Usage:    "The version suffix for the helm charts",
	EnvVars:  []string{"HELM_RELEASE", "CHART_VERSION"},
	Required: true,
}

var confirmFlag = &cli.BoolFlag{
	Name:    "confirm",
	Usage:   "Perform all the steps. If not set, it will be a dry-run",
	EnvVars: []string{"CONFIRM"},
	Value:   false,
}

var awsProfileFlag = &cli.StringFlag{
	Name:     "aws-profile",
	Usage:    "The AWS profile to use",
	EnvVars:  []string{"AWS_PROFILE"},
	Value:    "default",
	Required: true,
}

var skipReleaseVersionCheckFlag = &cli.BoolFlag{
	Name:    "skip-version-check",
	Usage:   "Skip checking the release version matches the determined version",
	EnvVars: []string{"SKIP_VERSION_CHECK"},
	Value:   false,
	Action: func(ctx *cli.Context, b bool) error {
		if ctx.Bool(skipValidationFlag.Name) && !b {
			return fmt.Errorf("must skip branch check if %s is set", skipValidationFlag.Name)
		}
		return nil
	},
}
