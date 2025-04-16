package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/pinnedversion"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
	"github.com/projectcalico/calico/release/pkg/manager/calico"
	"github.com/projectcalico/calico/release/pkg/manager/manager"
)

func enterpriseReleaseSubCommand(cfg *Config) []*cli.Command {
	return []*cli.Command{
		enterpriseReleasePrepCommand(cfg),
		enterpriseReleaseBuildCommand(cfg),
		enterpriseReleasePublishCommand(cfg),
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
		skipReleaseVersionCheckFlag,
		skipValidationFlag,
		confirmFlag,
	}

	return &cli.Command{
		Name:  "build",
		Usage: "Run steps to build an enterprise release",
		Flags: flags,
		Action: func(c *cli.Context) error {
			// Load version from calico/_data/versions.yaml
			versions, err := pinnedversion.LoadVersionsFile(cfg.RepoRootDir)
			if err != nil {
				return err
			}
			// Validate the release version.
			if err := validateReleaseVersion(c, versions.Title); err != nil {
				return err
			}

			// Build the release.
			opts := []calico.Option{
				calico.WithVersion(versions.Title),
				calico.WithOperatorVersion(versions.TigeraOperator.Version),
				calico.WithOutputDir(releaseOutputDir(cfg.RepoRootDir, versions.Title)),
				calico.WithRepoRoot(cfg.RepoRootDir),
				calico.WithGithubOrg(c.String(orgFlag.Name)),
				calico.WithRepoName(c.String(repoFlag.Name)),
				calico.WithRepoRemote(c.String(repoRemoteFlag.Name)),
				calico.WithValidate(!c.Bool(skipValidationFlag.Name)),
			}
			entOpts := []calico.EnterpriseOption{
				calico.WithChartVersion(versions.HelmRelease),
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
		publishImagesFlag,
		publishGitFlag,
		publishToS3Flag,
		publishWindowsArchiveFlag,
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
			if err := utils.Clone(fmt.Sprintf("git@github.com:%s/%s.git", c.String(managerOrgFlag.Name), c.String(managerRepoFlag.Name)), c.String(managerBranchFlag.Name), managerDir); err != nil {
				return fmt.Errorf("failed to clone manager repository: %v", err)
			}

			// Download the pinned versions of the hashrelease.
			hashrel, err := pinnedversion.LoadEnterpriseHashreleaseFromRemote(c.String(hashreleaseNameFlag.Name), cfg.TmpDir, cfg.RepoRootDir)
			if err != nil {
				return err
			}

			// Release the cnx-manager image(s).
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
			manager, err := manager.NewManager(managerOpts...)
			if err != nil {
				return fmt.Errorf("failed to create cnx-manager manager: %v", err)
			}
			if err := manager.Publish(); err != nil {
				return fmt.Errorf("failed to publish cnx-manager: %v", err)
			}
			logrus.Info("Published cnx-manager")

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
				calico.WithAWSProfile(c.String(awsProfileFlag.Name)),
				calico.WithDryRun(!c.Bool(confirmFlag.Name)),
				calico.WithPublishWindowsArchive(c.Bool(publishWindowsArchiveFlag.Name)),
				calico.WithPublishToS3(c.Bool(publishToS3Flag.Name)),
				calico.WithPublishGitChanges(c.Bool(publishGitFlag.Name)),
				calico.WithEnterpriseHashrelease(*hashrel, hashreleaseserver.Config{}),
			}
			m := calico.NewEnterpriseManager(opts, entOpts...)

			return m.PublishRelease()
		},
	}
}

func validateReleaseVersion(c *cli.Context, ver string) error {
	if c.Bool(skipReleaseVersionCheckFlag.Name) {
		logrus.Warn("Skipping release version check, this is not recommended")
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

func triggerSemaphoreRelease(c *cli.Context, repoDirVersionMap map[string]string) error {
	runner := command.RealCommandRunner{}
	for dir, ver := range repoDirVersionMap {
		if err := utils.CheckoutHashreleaseVersion(ver, dir); err != nil {
			return err
		}
		env := append(os.Environ(), "CNX=true")
		env = append(env, fmt.Sprintf("RELEASE_TAG=%s", ver))
		env = append(env, fmt.Sprintf("RELEASE_VERSION=%s", c.String(releaseVersionFlag.Name)))
		if c.Bool(confirmFlag.Name) {
			env = append(env, "CONFIRM=true")
		}
		if _, err := runner.RunInDir(dir, "make", []string{"clean", "sem-cut-release"}, env); err != nil {
			return fmt.Errorf("error triggering %s releaseon semaphore: %v", filepath.Base(dir), err)
		}
	}
	return nil
}
