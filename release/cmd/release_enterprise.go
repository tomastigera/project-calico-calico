package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/pinnedversion"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
	"github.com/projectcalico/calico/release/pkg/manager/calico"
	"github.com/projectcalico/calico/release/pkg/manager/manager"
	"github.com/projectcalico/calico/release/pkg/manager/operator"
)

func enterpriseReleaseSubCommand(cfg *Config) []*cli.Command {
	return []*cli.Command{
		enterpriseReleasePrepCommand(cfg),
		enterpriseReleaseBuildCommand(cfg),
		enterpriseReleasePublishCommand(cfg),
		enterpriseReleaseValidationSubCommand(cfg),
	}
}

func enterpriseReleasePrepCommand(cfg *Config) *cli.Command {
	return &cli.Command{
		Name:  "prep",
		Usage: "Run steps to prepare for an enterprise release",
		Flags: []cli.Flag{
			orgFlag,
			repoFlag,
			repoRemoteFlag,
			releaseBranchPrefixFlag,
			devTagSuffixFlag,
			hashreleaseNameFlag,
			releaseVersionFlag,
			operatorVersionFlag,
			chartVersionFlag,
			registryFlag,
			confirmFlag,
			skipReleaseVersionCheckFlag,
			skipValidationFlag,
			githubTokenFlag,
		},
		Action: func(c *cli.Context) error {
			configureLogging("release-prep.log")

			ver := c.String(releaseVersionFlag.Name)

			// Validate the release version.
			if err := validateReleaseVersion(c, ver); err != nil {
				return err
			}

			// Download the pinned versions of the hashrel.
			hashrel, err := pinnedversion.LoadEnterpriseHashreleaseFromRemote(c.String(hashreleaseNameFlag.Name), cfg.TmpDir, cfg.RepoRootDir)
			if err != nil {
				return err
			}

			calicoOpts := []calico.Option{
				calico.WithRepoRoot(cfg.RepoRootDir),
				calico.WithVersion(ver),
				calico.WithOperatorVersion(c.String(operatorVersionFlag.Name)),
				calico.WithReleaseBranchPrefix(c.String(releaseBranchPrefixFlag.Name)),
				calico.WithGithubOrg(c.String(orgFlag.Name)),
				calico.WithRepoName(c.String(repoFlag.Name)),
				calico.WithRepoRemote(c.String(repoRemoteFlag.Name)),
				calico.WithValidate(!c.Bool(skipValidationFlag.Name)),
				calico.WithTmpDir(cfg.TmpDir),
			}
			if reg := c.StringSlice(registryFlag.Name); len(reg) > 0 {
				calicoOpts = append(calicoOpts, calico.WithImageRegistries(reg))
			}
			enterpriseOpts := []calico.EnterpriseOption{
				calico.WithDevTagIdentifier(c.String(devTagSuffixFlag.Name)),
				calico.WithChartVersion(c.String(chartVersionFlag.Name)),
				calico.WithEnterpriseHashrelease(*hashrel, hashreleaseserver.Config{}),
				calico.WithDryRun(!c.Bool(confirmFlag.Name)),
			}

			m := calico.NewEnterpriseManager(calicoOpts, enterpriseOpts...)

			return m.PrepareRelease()
		},
	}
}

func enterpriseReleaseBuildCommand(cfg *Config) *cli.Command {
	flags := []cli.Flag{
		orgFlag,
		repoFlag,
		repoRemoteFlag,
		devTagSuffixFlag,
		chartVersionFlag,
		skipReleaseVersionCheckFlag,
		skipValidationFlag,
		confirmFlag,
	}

	return &cli.Command{
		Name:  "build",
		Usage: "Run steps to build an enterprise release",
		Flags: flags,
		Action: func(c *cli.Context) error {
			configureLogging("release-build.log")
			// Load version from manifests.
			ver, operatorVer, err := version.VersionsFromManifests(cfg.RepoRootDir)
			if err != nil {
				return err
			}

			// Validate the release version.
			if err := validateReleaseVersion(c, ver.FormattedString()); err != nil {
				return err
			}

			// Build the release.
			opts := []calico.Option{
				calico.WithVersion(ver.FormattedString()),
				calico.WithOperatorVersion(operatorVer.FormattedString()),
				calico.WithOutputDir(releaseOutputDir(cfg.RepoRootDir, ver.FormattedString())),
				calico.WithRepoRoot(cfg.RepoRootDir),
				calico.WithGithubOrg(c.String(orgFlag.Name)),
				calico.WithRepoName(c.String(repoFlag.Name)),
				calico.WithRepoRemote(c.String(repoRemoteFlag.Name)),
				calico.WithValidate(!c.Bool(skipValidationFlag.Name)),
			}
			entOpts := []calico.EnterpriseOption{
				calico.WithDevTagIdentifier(c.String(devTagSuffixFlag.Name)),
				calico.WithChartVersion(c.String(chartVersionFlag.Name)),
				calico.WithDryRun(!c.Bool(confirmFlag.Name)),
			}
			m := calico.NewEnterpriseManager(opts, entOpts...)
			return m.Build()
		},
	}
}

func enterpriseReleasePublishCommand(cfg *Config) *cli.Command {
	flags := []cli.Flag{
		orgFlag,
		repoFlag,
		repoRemoteFlag,
		releaseBranchPrefixFlag,
		devTagSuffixFlag,
		hashreleaseNameFlag,
		chartVersionFlag,
		publishImagesFlag,
		hashReleaseRegistryFlag,
		publishGitFlag,
		publishToS3Flag,
		publishWindowsArchiveFlag,
		skipValidationFlag,
		skipReleaseVersionCheckFlag,
	}
	flags = append(flags, managerFlags...)
	flags = append(flags, awsProfileFlag, skipReleaseVersionCheckFlag, skipValidationFlag, confirmFlag)
	return &cli.Command{
		Name:  "publish",
		Usage: "Run steps to publish an enterprise release",
		Flags: flags,
		Action: func(c *cli.Context) error {
			configureLogging("release-publish.log")

			// Load the versions.
			ver, operatorVer, err := version.VersionsFromManifests(cfg.RepoRootDir)
			if err != nil {
				return err
			}

			// Validate the release version.
			if err := validateReleaseVersion(c, ver.FormattedString()); err != nil {
				return err
			}

			// Clone the manager repository.
			managerDir := filepath.Join(cfg.TmpDir, manager.DefaultRepoName)
			if err := manager.Clone(c.String(managerOrgFlag.Name), c.String(managerRepoFlag.Name), c.String(managerBranchFlag.Name), managerDir); err != nil {
				return fmt.Errorf("failed to clone manager repository: %v", err)
			}

			// Download the pinned versions of the hashrelease.
			hashrel, err := pinnedversion.LoadEnterpriseHashreleaseFromRemote(c.String(hashreleaseNameFlag.Name), cfg.TmpDir, cfg.RepoRootDir)
			if err != nil {
				return err
			}

			hashrelRegistry := c.String(hashReleaseRegistryFlag.Name)

			// Release the tigera-manager image(s).
			managerOpts := []manager.Option{
				manager.WithDirectory(managerDir),
				manager.WithCalicoDirectory(cfg.RepoRootDir),
				manager.WithRepoName(c.String(managerRepoFlag.Name)),
				manager.WithRepoRemote(c.String(managerRemoteFlag.Name)),
				manager.WithGithubOrg(c.String(managerOrgFlag.Name)),
				manager.WithBranch(c.String(managerBranchFlag.Name)),
				manager.WithDevTagIdentifier(c.String(managerDevTagSuffixFlag.Name)),
				manager.WithValidate(!c.Bool(skipValidationFlag.Name)),
				manager.WithPublish(!c.Bool(confirmFlag.Name)),
				manager.WithVersion(ver.FormattedString()),
				manager.WithHashreleaseVersion(hashrel.ManagerVersion),
			}
			if hashrelRegistry != "" {
				managerOpts = append(managerOpts, manager.WithHashreleaseRegistry(hashrelRegistry))
			}
			manager, err := manager.NewManager(managerOpts...)
			if err != nil {
				return fmt.Errorf("failed to create tigera-manager manager: %v", err)
			}
			if err := manager.Publish(); err != nil {
				return fmt.Errorf("failed to publish tigera-manager: %v", err)
			}
			logrus.Info("Published tigera-manager")

			// Publish the rest of the release.
			if _, err := command.GitInDir(cfg.RepoRootDir, "checkout", fmt.Sprintf("%s-%s", c.String(releaseBranchPrefixFlag.Name), ver.Stream())); err != nil {
				return fmt.Errorf("failed to checkout release branch: %w", err)
			}
			opts := []calico.Option{
				calico.WithVersion(ver.FormattedString()),
				calico.WithOperatorVersion(operatorVer.FormattedString()),
				calico.WithRepoRoot(cfg.RepoRootDir),
				calico.WithGithubOrg(c.String(orgFlag.Name)),
				calico.WithRepoName(c.String(repoFlag.Name)),
				calico.WithRepoRemote(c.String(repoRemoteFlag.Name)),
				calico.WithValidate(!c.Bool(skipValidationFlag.Name)),
				calico.WithPublishImages(c.Bool(publishImagesFlag.Name)),
			}
			entOpts := []calico.EnterpriseOption{
				calico.WithDevTagIdentifier(c.String(devTagSuffixFlag.Name)),
				calico.WithChartVersion(c.String(chartVersionFlag.Name)),
				calico.WithAWSProfile(c.String(awsProfileFlag.Name)),
				calico.WithDryRun(!c.Bool(confirmFlag.Name)),
				calico.WithPublishWindowsArchive(c.Bool(publishWindowsArchiveFlag.Name)),
				calico.WithPublishToS3(c.Bool(publishToS3Flag.Name)),
				calico.WithPublishGitChanges(c.Bool(publishGitFlag.Name)),
				calico.WithEnterpriseHashrelease(*hashrel, hashreleaseserver.Config{}),
			}
			if hashrelRegistry != "" {
				entOpts = append(entOpts, calico.WithEnterpriseHashreleaseRegistry(hashrelRegistry))
			}
			m := calico.NewEnterpriseManager(opts, entOpts...)

			return m.PublishRelease()
		},
	}
}

func enterpriseReleaseValidationSubCommand(cfg *Config) *cli.Command {
	return &cli.Command{
		Name:  "validate",
		Usage: "Post-release validation",
		Flags: []cli.Flag{
			releaseBranchPrefixFlag,
			chartVersionFlag,
			githubTokenFlag,
		},
		Action: func(c *cli.Context) error {
			configureLogging("postrelease-validation.log")

			ver, operatorVer, err := version.VersionsFromManifests(cfg.RepoRootDir)
			if err != nil {
				return err
			}

			pinnedCfg := pinnedversion.EnterpriseReleaseVersions{
				CalicoReleaseVersions: pinnedversion.CalicoReleaseVersions{
					Dir:                 cfg.TmpDir,
					ProductVersion:      ver.FormattedString(),
					ReleaseBranchPrefix: c.String(releaseBranchPrefixFlag.Name),
					OperatorVersion:     operatorVer.FormattedString(),
					OperatorCfg: pinnedversion.OperatorConfig{
						Image:    operator.DefaultImage,
						Registry: operator.DefaultRegistry,
					},
				},
			}
			if _, err := pinnedCfg.GenerateFile(); err != nil {
				return fmt.Errorf("failed to generate pinned version file: %w", err)
			}
			images, err := pinnedCfg.ImageList()
			if err != nil {
				return fmt.Errorf("failed to get image list: %w", err)
			}

			postreleaseDir := filepath.Join(cfg.RepoRootDir, utils.ReleaseFolderName, "pkg", "postrelease", "enterprise")
			args := []string{
				"--format=testname",
				"--", "-v", "./...",
				fmt.Sprintf("-repo-root=%s", cfg.RepoRootDir),
				fmt.Sprintf("-release-version=%s", ver.FormattedString()),
				fmt.Sprintf("-operator-version=%s", operatorVer.FormattedString()),
				fmt.Sprintf("-chart-version=%s", c.String(chartVersionFlag.Name)),
				fmt.Sprintf("-images=%s", strings.Join(images, " ")),
			}
			if c.String(githubTokenFlag.Name) != "" {
				args = append(args, fmt.Sprintf("-github-token=%s", c.String(githubTokenFlag.Name)))
			}

			cmd := exec.Command(filepath.Join(cfg.RepoRootDir, "bin", "gotestsum"), args...)
			cmd.Dir = postreleaseDir
			var errb strings.Builder
			if logrus.IsLevelEnabled(logrus.DebugLevel) {
				// If debug level is enabled, also write to stdout.
				cmd.Stdout = io.MultiWriter(os.Stdout, logrus.StandardLogger().Out)
				cmd.Stderr = io.MultiWriter(os.Stderr, &errb)
			} else {
				// Otherwise, just capture the output to return.
				cmd.Stdout = io.MultiWriter(logrus.StandardLogger().Out)
				cmd.Stderr = io.MultiWriter(&errb)
			}
			logTestCmdSecure(postreleaseDir, "gotestsum", args)
			err = cmd.Run()
			if err != nil {
				err = fmt.Errorf("%s: %s", err, strings.TrimSpace(errb.String()))
			}
			return err
		},
	}
}

func validateReleaseVersion(c *cli.Context, ver string) error {
	if c.Bool(skipReleaseVersionCheckFlag.Name) {
		logrus.Warn("Skipping release version and helm chart version check, this is not recommended")
		return nil
	}
	// Determine the versions to use for the release.
	determinedVer, err := version.DetermineReleaseVersion(version.GitVersion(), c.String(devTagSuffixFlag.Name))
	if err != nil {
		return err
	}

	// Ensure the determined version and the version we are releasing matches.
	if determinedVer.FormattedString() != ver {
		return fmt.Errorf("version mismatch: determined %s, got %s", determinedVer, ver)
	}
	return nil
}
