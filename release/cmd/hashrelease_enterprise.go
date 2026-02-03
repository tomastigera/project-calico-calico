package main

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"

	"github.com/projectcalico/calico/release/internal/imagescanner"
	"github.com/projectcalico/calico/release/internal/pinnedversion"
	"github.com/projectcalico/calico/release/pkg/manager/calico"
	"github.com/projectcalico/calico/release/pkg/manager/manager"
	"github.com/projectcalico/calico/release/pkg/manager/operator"
	"github.com/projectcalico/calico/release/pkg/tasks"
)

func enterpriseHashreleaseSubCommands(cfg *Config) []*cli.Command {
	return []*cli.Command{
		enterpriseBuildHashreleaseCommand(cfg),
		enterprisePublishHashreleaseCommand(cfg),
		enterpriseMetadataCommand(cfg),
		enterpriseHashreleaseValidationSubCommand(cfg),
	}
}

func enterpriseBuildHashreleaseCommand(cfg *Config) *cli.Command {
	flags := append(productFlags, managerFlags...)
	flags = append(flags, operatorBuildFlags...)
	flags = append(flags,
		archFlag,
		registryFlag,
		skipRPMsFlag,
		skipOperatorFlag,
		skipBranchCheckFlag,
		skipValidationFlag,
		githubTokenFlag)
	return &cli.Command{
		Name:  "build",
		Usage: "build a Enterprise hashrelease locally",
		Flags: flags,
		Action: func(_ context.Context, c *cli.Command) error {
			configureLogging("hashrelease-build.log")

			if err := validateHashreleaseBuildFlags(c); err != nil {
				return err
			}

			// Define the base hashrelease directory.
			baseHashreleaseDir := baseHashreleaseOutputDir(cfg.RepoRootDir)

			// Clone the operator repository.
			operatorDir := filepath.Join(cfg.TmpDir, operator.DefaultRepoName)
			if err := operator.Clone(c.String(operatorOrgFlag.Name), c.String(operatorRepoFlag.Name), c.String(operatorBranchFlag.Name), operatorDir); err != nil {
				return fmt.Errorf("failed to clone operator repository: %v", err)
			}

			// Clone the manager repository.
			managerDir := filepath.Join(cfg.TmpDir, manager.DefaultRepoName)
			if err := manager.Clone(c.String(managerOrgFlag.Name), c.String(managerRepoFlag.Name), c.String(managerBranchFlag.Name), managerDir); err != nil {
				return fmt.Errorf("failed to clone manager repository: %v", err)
			}

			pinned := pinnedversion.EnteprisePinnedVersions{
				CalicoPinnedVersions: pinnedversion.CalicoPinnedVersions{
					Dir:                 cfg.TmpDir,
					RootDir:             cfg.RepoRootDir,
					ReleaseBranchPrefix: c.String(releaseBranchPrefixFlag.Name),
					OperatorCfg: pinnedversion.OperatorConfig{
						Image:    c.String(operatorImageFlag.Name),
						Registry: c.String(operatorRegistryFlag.Name),
						Branch:   c.String(operatorBranchFlag.Name),
						Dir:      operatorDir,
					},
					BaseHashreleaseDir: baseHashreleaseDir,
				},
				ManagerCfg: pinnedversion.ManagerConfig{
					Dir:    managerDir,
					Branch: c.String(managerBranchFlag.Name),
				},
			}

			data, err := pinned.GenerateFile()
			if err != nil {
				return fmt.Errorf("failed to generate pinned version file: %v", err)
			}

			// Check if the hashrelease has already been published.
			if published, err := tasks.HashreleasePublished(hashreleaseServerConfig(c), data.Hash(), c.Bool(ciFlag.Name)); err != nil {
				return fmt.Errorf("failed to check if hashrelease has been published: %v", err)
			} else if published {
				// On CI, if the hashrelease has already been published, we exit successfully (return nil).
				// However, on local builds, we just log a warning and continue.
				if c.Bool(ciFlag.Name) {
					logrus.Infof("hashrelease %s has already been published", data.Hash())
					return nil
				} else {
					logrus.Warnf("hashrelease %s has already been published", data.Hash())
				}
			}

			// Define the hashrelease directory using the hash from the pinned file.
			hashrel, err := pinnedversion.LoadEnterpriseHashrelease(cfg.RepoRootDir, cfg.TmpDir, baseHashreleaseDir, c.Bool(latestFlag.Name))
			if err != nil {
				return fmt.Errorf("failed to load hashrelease from pinned file: %v", err)
			}

			productRegistries := c.StringSlice(registryFlag.Name)

			// Build the operator
			operatorOpts := []operator.Option{
				operator.WithOperatorDirectory(operatorDir),
				operator.WithReleaseBranchPrefix(c.String(operatorReleaseBranchPrefixFlag.Name)),
				operator.WithDevTagIdentifier(c.String(operatorDevTagSuffixFlag.Name)),
				operator.WithImage(c.String(operatorImageFlag.Name)),
				operator.IsHashRelease(),
				operator.WithArchitectures(c.StringSlice(archFlag.Name)),
				operator.WithValidate(!c.Bool(skipValidationFlag.Name)),
				operator.WithReleaseBranchValidation(!c.Bool(skipBranchCheckFlag.Name)),
				operator.WithVersion(data.OperatorVersion()),
				operator.WithCalicoDirectory(cfg.RepoRootDir),
				operator.WithTempDirectory(cfg.TmpDir),
				operator.WithOutputDirectory(hashrel.Source),
			}
			if reg := c.String(operatorRegistryFlag.Name); reg != "" {
				operatorOpts = append(operatorOpts, operator.WithRegistry(reg))
			}
			if len(productRegistries) > 0 {
				operatorOpts = append(operatorOpts, operator.WithProductRegistry(productRegistries[0]))
			}
			if !c.Bool(skipOperatorFlag.Name) {
				o := operator.NewEnterpriseManager(operatorOpts...)
				if err := o.Build(); err != nil {
					return err
				}
			}

			calicoOpts := []calico.Option{
				calico.WithVersion(data.ProductVersion()),
				calico.WithOperator(c.String(operatorRegistryFlag.Name), c.String(operatorImageFlag.Name), data.OperatorVersion()),
				calico.WithOperatorGit(c.String(operatorOrgFlag.Name), c.String(operatorRepoFlag.Name), c.String(operatorBranchFlag.Name)),
				calico.WithRepoRoot(cfg.RepoRootDir),
				calico.WithReleaseBranchPrefix(c.String(releaseBranchPrefixFlag.Name)),
				calico.IsHashRelease(),
				calico.WithOutputDir(hashrel.Source),
				calico.WithTmpDir(cfg.TmpDir),
				calico.WithBuildImages(c.Bool(buildHashreleaseImagesFlag.Name)),
				calico.WithValidate(!c.Bool(skipValidationFlag.Name)),
				calico.WithReleaseBranchValidation(!c.Bool(skipBranchCheckFlag.Name)),
				calico.WithGithubOrg(c.String(orgFlag.Name)),
				calico.WithRepoName(c.String(repoFlag.Name)),
				calico.WithRepoRemote(c.String(repoRemoteFlag.Name)),
				calico.WithArchitectures(c.StringSlice(archFlag.Name)),
			}
			if len(productRegistries) > 0 {
				calicoOpts = append(calicoOpts, calico.WithImageRegistries(productRegistries))
			}
			enterpriseOpts := []calico.EnterpriseOption{
				calico.WithDevTagIdentifier(c.String(devTagSuffixFlag.Name)),
				calico.WithEnterpriseHashrelease(*hashrel, *hashreleaseServerConfig(c)),
				calico.WithRPMs(!c.Bool(skipRPMsFlag.Name)),
			}

			m := calico.NewEnterpriseManager(calicoOpts, enterpriseOpts...)
			if err := m.Build(); err != nil {
				return err
			}

			return tasks.ReformatEnterpriseHashrelease(hashrel.Source, cfg.TmpDir)
		},
	}
}

// validateEnterpriseHashreleasePublishFlags checks that the flags are set correctly for the enterprise hashrelease publish command.
func validateEnterpriseHashreleasePublishFlags(_ context.Context, c *cli.Command) error {
	// If publishing the hashrelease
	if c.Bool(publishHashreleaseFlag.Name) {
		//  check that hashrelease server configuration is set.
		if !hashreleaseServerConfig(c).Valid() {
			return fmt.Errorf("missing hashrelease publishing configuration, ensure --%s is set",
				hashreleaseServerBucketFlag.Name)
		}
		// If building locally, do not allow setting the hashrelease as latest.
		if c.Bool(latestFlag.Name) && !c.Bool(ciFlag.Name) {
			return fmt.Errorf("cannot set hashrelease as latest when building locally, use --%s=false instead", latestFlag.Name)
		}
	}

	// If skipValidationFlag is set, then skipImageScanFlag must also be set.
	if c.Bool(skipValidationFlag.Name) && !c.Bool(skipImageScanFlag.Name) {
		return fmt.Errorf("%s must be set if %s is set", skipImageScanFlag, skipValidationFlag)
	}
	return nil
}

func enterprisePublishHashreleaseCommand(cfg *Config) *cli.Command {
	flags := append(gitFlags,
		devTagSuffixFlag,
		operatorDevTagSuffixFlag,
		archFlag,
		registryFlag,
		windowsArchiveBucketFlag,
		publishWindowsArchiveFlag,
		publishChartsFlag,
		helmRegistryFlag,
		publishHashreleaseFlag,
		latestFlag,
		skipOperatorFlag,
		skipValidationFlag,
		skipImageScanFlag)
	flags = append(flags, imageScannerAPIFlags...)
	return &cli.Command{
		Name:  "publish",
		Usage: "publish a pre-built Enterprise hashrelease",
		Flags: flags,
		Action: func(ctx context.Context, c *cli.Command) error {
			configureLogging("hashrelease-publish.log")

			// Validate flags.
			if err := validateEnterpriseHashreleasePublishFlags(ctx, c); err != nil {
				return err
			}

			// Extract the pinned version as a hashrelease.
			hashrel, err := pinnedversion.LoadEnterpriseHashrelease(cfg.RepoRootDir, cfg.TmpDir, baseHashreleaseOutputDir(cfg.RepoRootDir), c.Bool(latestFlag.Name))
			if err != nil {
				return fmt.Errorf("failed to load hashrelease from pinned file: %v", err)
			}

			// Check if the hashrelease has already been published.
			serverCfg := hashreleaseServerConfig(c)
			if published, err := tasks.HashreleasePublished(serverCfg, hashrel.Hash, c.Bool(ciFlag.Name)); err != nil {
				return fmt.Errorf("failed to check if hashrelease has been published: %v", err)
			} else if published {
				// On CI, we exit successfully (return nil) if the hashrelease has already been published.
				// This is not an error scenario; we just log a warning and continue locally.
				if c.Bool(ciFlag.Name) {
					logrus.Infof("hashrelease %s has already been published", hashrel.Hash)
					return nil
				} else {
					logrus.Warnf("hashrelease %s has already been published", hashrel.Hash)
				}
			}

			productRegistries := c.StringSlice(registryFlag.Name)

			// Push the operator hashrelease first before validation.
			// This is because validation checks all images exists and sends to Image Scan Service
			o := operator.NewEnterpriseManager(
				operator.WithOperatorDirectory(filepath.Join(cfg.TmpDir, operator.DefaultRepoName)),
				operator.IsHashRelease(),
				operator.WithDevTagIdentifier(c.String(operatorDevTagSuffixFlag.Name)),
				operator.WithArchitectures(c.StringSlice(archFlag.Name)),
				operator.WithValidate(!c.Bool(skipValidationFlag.Name)),
				operator.WithTempDirectory(cfg.TmpDir),
			)
			if !c.Bool(skipOperatorFlag.Name) {
				if err := o.Publish(); err != nil {
					return err
				}
			}

			calicoOpts := []calico.Option{
				calico.WithRepoRoot(cfg.RepoRootDir),
				calico.IsHashRelease(),
				calico.WithVersion(hashrel.ProductVersion),
				calico.WithOperatorVersion(hashrel.OperatorVersion),
				calico.WithGithubOrg(c.String(orgFlag.Name)),
				calico.WithRepoName(c.String(repoFlag.Name)),
				calico.WithRepoRemote(c.String(repoRemoteFlag.Name)),
				calico.WithValidate(!c.Bool(skipValidationFlag.Name)),
				calico.WithTmpDir(cfg.TmpDir),
				calico.WithOutputDir(filepath.Join(baseHashreleaseOutputDir(cfg.RepoRootDir), hashrel.Hash)),
				calico.WithPublishHashrelease(c.Bool(publishHashreleaseFlag.Name)),
				calico.WithPublishImages(false), // Enterprise does not publish images
				calico.WithPublishCharts(c.Bool(publishChartsFlag.Name)),
				calico.WithImageScanning(!c.Bool(skipImageScanFlag.Name), *imageScanningAPIConfig(c)),
				calico.WithPublishCharts(c.Bool(publishChartsFlag.Name)),
			}
			if len(productRegistries) > 0 {
				calicoOpts = append(calicoOpts,
					calico.WithImageRegistries(productRegistries),
				)
			}
			if helmRegistries := c.StringSlice(helmRegistryFlag.Name); len(helmRegistries) > 0 {
				calicoOpts = append(calicoOpts,
					calico.WithHelmRegistries(helmRegistries),
				)
			}
			components, err := pinnedversion.RetrieveEnterpriseImageComponents(cfg.TmpDir)
			if err != nil {
				return fmt.Errorf("failed to retrieve images for the hashrelease: %v", err)
			}
			calicoOpts = append(calicoOpts, calico.WithComponents(components))
			enterpriseOpts := []calico.EnterpriseOption{
				calico.WithDevTagIdentifier(c.String(devTagSuffixFlag.Name)),
				calico.WithChartVersion(hashrel.ChartVersion),
				calico.WithEnterpriseHashrelease(*hashrel, *serverCfg),
				calico.WithPublishWindowsArchive(c.Bool(publishWindowsArchiveFlag.Name)),
			}
			if b := c.String(windowsArchiveBucketFlag.Name); b != "" {
				enterpriseOpts = append(enterpriseOpts, calico.WithWindowsArchiveBucket(b))
			}
			m := calico.NewEnterpriseManager(calicoOpts, enterpriseOpts...)
			if err := m.PublishRelease(); err != nil {
				return err
			}

			if !c.Bool(skipImageScanFlag.Name) {
				url, err := imagescanner.RetrieveResultURL(cfg.TmpDir)
				// Only log error as a warning if the image scan result URL could not be retrieved
				// as it is not an error that should stop the hashrelease process.
				if err != nil {
					logrus.WithError(err).Warn("Failed to retrieve image scan result URL")
				} else if url == "" {
					logrus.Warn("Image scan result URL is empty")
				}
				hashrel.ImageScanResultURL = url
			}

			// Send a slack message to notify that the hashrelease has been published.
			if c.Bool(publishHashreleaseFlag.Name) {
				if _, err := tasks.AnnounceHashrelease(slackConfig(c), &hashrel.Hashrelease, ciJobURL(c)); err != nil {
					logrus.WithError(err).Warn("Failed to send hashrelease announcement to Slack")
				}
			}
			return nil
		},
	}
}

func enterpriseMetadataCommand(cfg *Config) *cli.Command {
	return &cli.Command{
		Name:  "metadata",
		Usage: "Generate metadata for a hashrelease",
		Flags: []cli.Flag{
			orgFlag,
			repoFlag,
			repoRemoteFlag,
			&cli.StringFlag{Name: "dir", Usage: "Directory to write metadata to", Sources: cli.EnvVars("METADATA_DIR"), Value: "", Required: true},
			&cli.StringFlag{Name: "versions-file", Usage: "Path to the versions file", Sources: cli.EnvVars("VERSIONS_FILE"), Value: "", Required: true},
		},
		Action: func(_ context.Context, c *cli.Command) error {
			configureLogging("hashrelease-metadata.log")
			pinnedVersionFileDir := filepath.Dir(c.String("versions-file"))
			versions, err := pinnedversion.RetrieveVersions(pinnedVersionFileDir)
			if err != nil {
				return fmt.Errorf("failed to retrieve versions: %v", err)
			}
			op, err := pinnedversion.RetrievePinnedOperator(pinnedVersionFileDir)
			if err != nil {
				return fmt.Errorf(("failed to retrieve pinned operator: %v"), err)
			}
			opts := []calico.Option{
				calico.IsHashRelease(),
				calico.WithVersion(versions.ProductVersion()),
				calico.WithOperator(op.Image, op.Version, op.Registry),
				calico.WithRepoRoot(cfg.RepoRootDir),
				calico.WithGithubOrg(c.String(orgFlag.Name)),
				calico.WithRepoName(c.String(repoFlag.Name)),
				calico.WithRepoRemote(c.String(repoRemoteFlag.Name)),
			}
			r := calico.NewEnterpriseManager(opts)
			return r.BuildMetadata(c.String("dir"))
		},
	}
}
func enterpriseHashreleaseValidationSubCommand(cfg *Config) *cli.Command {
	return &cli.Command{
		Name:  "validate",
		Usage: "Post-hashrelease validation (smoke tests)",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "hashrelease-metadata-file",
				Usage: "Path to hashrelease metadata file for setting URL environment variables",
				Value: "hashrelease-metadata-file.txt",
			},
		},
		Action: func(_ context.Context, c *cli.Command) error {
			configureLogging("postrelease-hashrelease-validation.log")

			postreleaseDir := filepath.Join(cfg.RepoRootDir, utils.ReleaseFolderName, "pkg", "postrelease", "enterprise")
			args := []string{
				"--format=testname",
				"--", "-v", "./...",
				fmt.Sprintf("-hashrelease-metadata-file=%s", c.String("hashrelease-metadata-file")),
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
			err := cmd.Run()
			if err != nil {
				err = fmt.Errorf("%s: %s", err, strings.TrimSpace(errb.String()))
			}
			return err
		},
	}
}