package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v3"

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
			releaseVersionFlag,
			operatorVersionFlag,
			chartVersionFlag,
			hashreleaseNameFlag,
			registryFlag,
			imageReleaseDirsFlag,
			operatorRegistryFlag,
			operatorImageFlag,
			confirmFlag,
			skipReleaseVersionCheckFlag,
			skipValidationFlag,
			skipBranchCheckFlag,
			skipManagerFlag,
			githubTokenFlag,
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			configureLogging("release-prep.log")

			ver := c.String(releaseVersionFlag.Name)

			// Validate the release version.
			if err := validateReleaseVersion(ctx, c, ver); err != nil {
				return err
			}

			calicoOpts := []calico.Option{
				calico.WithRepoRoot(cfg.RepoRootDir),
				calico.WithVersion(ver),
				calico.WithOperator(c.String(operatorRegistryFlag.Name), c.String(operatorImageFlag.Name), c.String(operatorVersionFlag.Name)),
				calico.WithReleaseBranchPrefix(c.String(releaseBranchPrefixFlag.Name)),
				calico.WithGithubOrg(c.String(orgFlag.Name)),
				calico.WithRepoName(c.String(repoFlag.Name)),
				calico.WithRepoRemote(c.String(repoRemoteFlag.Name)),
				calico.WithValidate(!c.Bool(skipValidationFlag.Name)),
				calico.WithReleaseBranchValidation(!c.Bool(skipBranchCheckFlag.Name)),
				calico.WithTmpDir(cfg.TmpDir),
			}
			if reg := c.StringSlice(registryFlag.Name); len(reg) > 0 {
				calicoOpts = append(calicoOpts, calico.WithImageRegistries(reg))
			}
			enterpriseOpts := []calico.EnterpriseOption{
				calico.WithDevTagIdentifier(c.String(devTagSuffixFlag.Name)),
				calico.WithDryRun(!c.Bool(confirmFlag.Name)),
				calico.WithManager(!c.Bool(skipManagerFlag.Name)),
				calico.WithEnterpriseHashrelease(hashreleaseserver.EnterpriseHashrelease{
					Hashrelease: hashreleaseserver.Hashrelease{
						Name: c.String(hashreleaseNameFlag.Name),
					},
				}, hashreleaseserver.Config{}),
				calico.WithChartVersion(c.String(chartVersionFlag.Name)),
			}
			if dirs := c.StringSlice(imageReleaseDirsFlag.Name); len(dirs) > 0 {
				enterpriseOpts = append(enterpriseOpts, calico.WithImageReleaseDirs(dirs))
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
		releaseBranchPrefixFlag,
		baseArtifactsURLFlag,
		s3BucketFlag,
		skipReleaseVersionCheckFlag,
		skipBranchCheckFlag,
		skipValidationFlag,
		skipRPMsFlag,
		awsProfileFlag,
	}

	return &cli.Command{
		Name:  "build",
		Usage: "Run steps to build an enterprise release",
		Flags: flags,
		Action: func(ctx context.Context, c *cli.Command) error {
			configureLogging("release-build.log")
			// Load version from manifests.
			ver, operatorVer, err := version.VersionsFromManifests(cfg.RepoRootDir)
			if err != nil {
				return err
			}

			// Load the release pinned versions.
			versions, err := pinnedversion.LoadEnterpriseVersionsFromDataFile(cfg.RepoRootDir, ver.FormattedString())
			if err != nil {
				return fmt.Errorf("failed to load release versions: %w", err)
			}

			// Validate the release version.
			if err := validateReleaseVersion(ctx, c, versions.Title); err != nil {
				return err
			}
			if !c.Bool(skipReleaseVersionCheckFlag.Name) && operatorVer.FormattedString() != versions.TigeraOperator.Version {
				return fmt.Errorf("operator version mismatch: expected %s, got %s", versions.TigeraOperator.Version, operatorVer.FormattedString())
			}

			// Build the release.
			opts := []calico.Option{
				calico.WithVersion(versions.Title),
				calico.WithOperator(versions.TigeraOperator.Registry, versions.TigeraOperator.Image, versions.TigeraOperator.Version),
				calico.WithOutputDir(releaseOutputDir(cfg.RepoRootDir, versions.Title)),
				calico.WithRepoRoot(cfg.RepoRootDir),
				calico.WithGithubOrg(c.String(orgFlag.Name)),
				calico.WithRepoName(c.String(repoFlag.Name)),
				calico.WithRepoRemote(c.String(repoRemoteFlag.Name)),
				calico.WithReleaseBranchPrefix(c.String(releaseBranchPrefixFlag.Name)),
				calico.WithValidate(!c.Bool(skipValidationFlag.Name)),
				calico.WithReleaseBranchValidation(!c.Bool(skipBranchCheckFlag.Name)),
				calico.WithTmpDir(cfg.TmpDir),
			}
			entOpts := []calico.EnterpriseOption{
				calico.WithDevTagIdentifier(c.String(devTagSuffixFlag.Name)),
				calico.WithChartVersion(versions.HelmRelease),
				calico.WithDryRun(false),
				calico.WithRPMs(!c.Bool(skipRPMsFlag.Name)),
			}
			if v := c.String(awsProfileFlag.Name); v != "" {
				opts = append(opts, calico.WithAWSProfile(v))
			}
			if v := c.String(s3BucketFlag.Name); v != "" {
				opts = append(opts, calico.WithS3Bucket(v))
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
		gitPublishFlag,
		registryFlag,
		hashReleaseRegistryFlag,
		publishImagesFlag,
		helmRegistryFlag,
		publishChartsFlag,
		awsProfileFlag,
		s3BucketFlag,
		publishToS3Flag,
		windowsArchiveBucketFlag,
		publishWindowsArchiveFlag,
	}
	flags = append(flags, managerFlags...)
	flags = append(flags, imageScannerAPIFlags...)
	flags = append(flags,
		skipManagerFlag,
		skipImageScanFlag,
		skipValidationFlag,
		skipBranchCheckFlag,
		skipReleaseVersionCheckFlag,
		confirmFlag,
	)
	return &cli.Command{
		Name:  "publish",
		Usage: "Run steps to publish an enterprise release",
		Flags: flags,
		Action: func(ctx context.Context, c *cli.Command) error {
			configureLogging("release-publish.log")

			// Load the versions.
			ver, operatorVer, err := version.VersionsFromManifests(cfg.RepoRootDir)
			if err != nil {
				return err
			}

			// Load the release pinned versions.
			versions, err := pinnedversion.LoadEnterpriseVersionsFromDataFile(cfg.RepoRootDir, ver.FormattedString())
			if err != nil {
				return fmt.Errorf("failed to load release versions: %w", err)
			}

			// Validate the release version.
			if err := validateReleaseVersion(ctx, c, versions.Title); err != nil {
				return err
			}
			if !c.Bool(skipReleaseVersionCheckFlag.Name) && operatorVer.FormattedString() != versions.TigeraOperator.Version {
				return fmt.Errorf("operator version mismatch: expected %s, got %s", versions.TigeraOperator.Version, operatorVer.FormattedString())
			}

			// Download the pinned versions of the hashrelease.
			hashrel, err := pinnedversion.LoadEnterpriseHashreleaseFromRemote(versions.ReleaseName, cfg.TmpDir, cfg.RepoRootDir)
			if err != nil {
				return err
			}
			registries := c.StringSlice(registryFlag.Name)
			hashrelRegistry := c.String(hashReleaseRegistryFlag.Name)

			if _, exists := versions.Components[manager.ComponentName]; exists && !c.Bool(skipManagerFlag.Name) {
				// Clone the manager repository.
				managerDir := filepath.Join(cfg.TmpDir, manager.DefaultRepoName)
				if err := manager.Clone(c.String(managerOrgFlag.Name), c.String(managerRepoFlag.Name), c.String(managerBranchFlag.Name), managerDir); err != nil {
					return fmt.Errorf("failed to clone manager repository: %v", err)
				}

				// Release the tigera-manager image(s).
				managerOpts := []manager.Option{
					manager.WithDirectory(managerDir),
					manager.WithCalicoDirectory(cfg.RepoRootDir),
					manager.WithRepoName(c.String(managerRepoFlag.Name)),
					manager.WithRepoRemote(c.String(managerRemoteFlag.Name)),
					manager.WithGithubOrg(c.String(managerOrgFlag.Name)),
					manager.WithBranch(c.String(managerBranchFlag.Name)),
					manager.WithDevTagIdentifier(c.String(managerDevTagSuffixFlag.Name)),
					manager.WithReleaseBranchPrefix(c.String(releaseBranchPrefixFlag.Name)),
					manager.WithValidate(!c.Bool(skipValidationFlag.Name)),
					manager.WithPublishImages(c.Bool(publishImagesFlag.Name)),
					manager.WithPublishTag(c.Bool(gitPublishFlag.Name)),
					manager.WithVersion(versions.Title),
					manager.WithHashreleaseVersion(hashrel.ManagerVersion),
					manager.WithDryRun(!c.Bool(confirmFlag.Name)),
				}
				if hashrelRegistry != "" {
					managerOpts = append(managerOpts, manager.WithHashreleaseRegistry(hashrelRegistry))
				}
				if len(registries) > 0 {
					managerOpts = append(managerOpts, manager.WithRegistry(registries[0]))
				}
				manager, err := manager.NewManager(managerOpts...)
				if err != nil {
					return fmt.Errorf("failed to create tigera-manager manager: %v", err)
				}
				if err := manager.Publish(); err != nil {
					return fmt.Errorf("failed to publish tigera-manager: %v", err)
				}
				logrus.Info("Published tigera-manager")
			}

			// Publish the rest of the release.
			opts := []calico.Option{
				calico.WithVersion(versions.Title),
				calico.WithOperatorVersion(versions.TigeraOperator.Version),
				calico.WithRepoRoot(cfg.RepoRootDir),
				calico.WithGithubOrg(c.String(orgFlag.Name)),
				calico.WithRepoName(c.String(repoFlag.Name)),
				calico.WithRepoRemote(c.String(repoRemoteFlag.Name)),
				calico.WithReleaseBranchPrefix(c.String(releaseBranchPrefixFlag.Name)),
				calico.WithValidate(!c.Bool(skipValidationFlag.Name)),
				calico.WithPublishImages(c.Bool(publishImagesFlag.Name)),
				calico.WithPublishGitTag(c.Bool(gitPublishFlag.Name)),
				calico.WithReleaseBranchValidation(!c.Bool(skipBranchCheckFlag.Name)),
				calico.WithOutputDir(releaseOutputDir(cfg.RepoRootDir, versions.Title)),
				calico.WithTmpDir(cfg.TmpDir),
				calico.WithComponents(versions.ImageComponents(true)),
				calico.WithImageScanning(!c.Bool(skipImageScanFlag.Name), *imageScanningAPIConfig(c)),
				calico.WithPublishCharts(c.Bool(publishChartsFlag.Name)),
			}
			if len(registries) > 0 {
				opts = append(opts, calico.WithImageRegistries(registries))
			}
			if reg := c.StringSlice(helmRegistryFlag.Name); len(reg) > 0 {
				opts = append(opts, calico.WithHelmRegistries(reg))
			}
			entOpts := []calico.EnterpriseOption{
				calico.WithDevTagIdentifier(c.String(devTagSuffixFlag.Name)),
				calico.WithChartVersion(versions.HelmRelease),
				calico.WithDryRun(!c.Bool(confirmFlag.Name)),
				calico.WithPublishWindowsArchive(c.Bool(publishWindowsArchiveFlag.Name)),
				calico.WithPublishToS3(c.Bool(publishToS3Flag.Name)),
				calico.WithEnterpriseHashrelease(*hashrel, hashreleaseserver.Config{}),
			}
			if hashrelRegistry != "" {
				entOpts = append(entOpts, calico.WithEnterpriseHashreleaseRegistry(hashrelRegistry))
			}
			if v := c.String(windowsArchiveBucketFlag.Name); v != "" {
				entOpts = append(entOpts, calico.WithWindowsArchiveBucket(v))
			}
			if v := c.String(awsProfileFlag.Name); v != "" {
				opts = append(opts, calico.WithAWSProfile(v))
			}
			if v := c.String(s3BucketFlag.Name); v != "" {
				opts = append(opts, calico.WithS3Bucket(v))
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
			registryFlag,
			windowsArchiveBucketFlag,
			baseArtifactsURLFlag,
			githubTokenFlag,
			skipOperatorValidationFlag,
			skipImageValidationFlag,
		},
		Action: func(_ context.Context, c *cli.Command) error {
			configureLogging("postrelease-validation.log")

			// Load the versions.
			ver, _, err := version.VersionsFromManifests(cfg.RepoRootDir)
			if err != nil {
				return err
			}
			versions, err := pinnedversion.LoadEnterpriseVersionsFromDataFile(cfg.RepoRootDir, ver.FormattedString())
			if err != nil {
				return fmt.Errorf("failed to load release versions: %w", err)
			}

			postreleaseDir := filepath.Join(cfg.RepoRootDir, utils.ReleaseFolderName, "pkg", "postrelease", "enterprise")
			args := []string{
				"--format=testname",
				"--", "-v", "./...",
				fmt.Sprintf("-repo-root=%s", cfg.RepoRootDir),
				fmt.Sprintf("-release-version=%s", versions.Title),
				fmt.Sprintf("-operator-version=%s", versions.TigeraOperator.Version),
				fmt.Sprintf("-skip-operator=%t", c.Bool(skipImageValidationFlag.Name)),
				fmt.Sprintf("-chart-version=%s", versions.HelmRelease),
				fmt.Sprintf("-images=%s", strings.Join(versions.GetComponentImageNames(false), " ")),
				fmt.Sprintf("-skip-images=%t", c.Bool(skipImageValidationFlag.Name)),
			}
			if v := c.String(githubTokenFlag.Name); v != "" {
				args = append(args, fmt.Sprintf("-github-token=%s", v))
			}
			if v := c.String(windowsArchiveBucketFlag.Name); v != "" {
				args = append(args, fmt.Sprintf("-windows-bucket=%s", v))
			}
			if v := c.StringSlice(registryFlag.Name); len(v) > 0 {
				args = append(args, fmt.Sprintf("-registry=%s", v[0]))
			}
			if v := c.String(baseArtifactsURLFlag.Name); v != "" {
				args = append(args, fmt.Sprintf("-artifacts-base-url=%s", v))
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

func validateReleaseVersion(_ context.Context, c *cli.Command, ver string) error {
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
