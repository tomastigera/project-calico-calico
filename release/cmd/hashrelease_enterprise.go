package main

import (
	"fmt"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/projectcalico/calico/release/internal/pinnedversion"
	"github.com/projectcalico/calico/release/internal/registry"
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
		hashreleaseGarbageCollectCommand(cfg),
	}
}

func enterpriseBuildHashreleaseCommand(cfg *Config) *cli.Command {
	flags := append(productFlags, chartVersionFlag)
	flags = append(flags, managerFlags...)
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
		Action: func(c *cli.Context) error {
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
				ChartVersion: c.String(chartVersionFlag.Name),
			}

			data, err := pinned.GenerateFile()
			if err != nil {
				return fmt.Errorf("failed to generate pinned version file: %v", err)
			}

			// Check if the hashrelease has already been published.
			if published, err := tasks.HashreleasePublished(hashreleaseServerConfig(c), data.Hash(), c.Bool(ciFlag.Name)); err != nil {
				return fmt.Errorf("failed to check if hashrelease has been published: %v", err)
			} else if published {
				// On CI, we want it to fail if the hashrelease has already been published.
				// However, on local builds, we just log a warning and continue.
				if c.Bool(ciFlag.Name) {
					return fmt.Errorf("hashrelease %s has already been published", data.Hash())
				} else {
					logrus.Warnf("hashrelease %s has already been published", data.Hash())
				}
			}

			// Define the hashrelease directory using the hash from the pinned file.
			hashreleaseDir := filepath.Join(baseHashreleaseDir, data.Hash())
			hashrel, err := pinnedversion.LoadEnterpriseHashrelease(cfg.RepoRootDir, cfg.TmpDir, baseHashreleaseDir, c.Bool(latestFlag.Name))
			if err != nil {
				return fmt.Errorf("failed to load hashrelease from pinned file: %v", err)
			}

			// Build the operator
			operatorOpts := []operator.Option{
				operator.WithOperatorDirectory(operatorDir),
				operator.WithReleaseBranchPrefix(c.String(operatorReleaseBranchPrefixFlag.Name)),
				operator.IsHashRelease(),
				operator.WithArchitectures(c.StringSlice(archFlag.Name)),
				operator.WithValidate(!c.Bool(skipValidationFlag.Name)),
				operator.WithReleaseBranchValidation(!c.Bool(skipBranchCheckFlag.Name)),
				operator.WithVersion(data.OperatorVersion()),
				operator.WithCalicoDirectory(cfg.RepoRootDir),
				operator.WithTempDirectory(cfg.TmpDir),
				operator.WithOutputDirectory(hashreleaseDir),
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
				calico.WithRepoRoot(cfg.RepoRootDir),
				calico.WithReleaseBranchPrefix(c.String(releaseBranchPrefixFlag.Name)),
				calico.IsHashRelease(),
				calico.WithOutputDir(hashreleaseDir),
				calico.WithTmpDir(cfg.TmpDir),
				calico.WithBuildImages(c.Bool(buildHashreleaseImageFlag.Name)),
				calico.WithValidate(!c.Bool(skipValidationFlag.Name)),
				calico.WithReleaseBranchValidation(!c.Bool(skipBranchCheckFlag.Name)),
				calico.WithGithubOrg(c.String(orgFlag.Name)),
				calico.WithRepoName(c.String(repoFlag.Name)),
				calico.WithRepoRemote(c.String(repoRemoteFlag.Name)),
				calico.WithArchitectures(c.StringSlice(archFlag.Name)),
			}
			if reg := c.StringSlice(registryFlag.Name); len(reg) > 0 {
				calicoOpts = append(calicoOpts, calico.WithImageRegistries(reg))
			} else {
				calicoOpts = append(calicoOpts, calico.WithImageRegistries([]string{registry.TigeraDevCIGCRRegistry}))
			}

			enterpriseOpts := []calico.EnterpriseOption{
				calico.WithChartVersion(c.String(chartVersionFlag.Name)),
				calico.WithEnterpriseHashrelease(*hashrel, *hashreleaseServerConfig(c)),
				calico.WithRPMs(!c.Bool(skipRPMsFlag.Name)),
			}

			m := calico.NewEnterpriseManager(calicoOpts, enterpriseOpts...)
			if err := m.Build(); err != nil {
				return err
			}

			return tasks.ReformatEnterpriseHashrelease(hashreleaseDir, cfg.TmpDir)
		},
	}
}

func enterprisePublishHashreleaseCommand(cfg *Config) *cli.Command {
	flags := append(gitFlags,
		archFlag,
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
		Action: func(c *cli.Context) error {
			configureLogging("hashrelease-publish.log")

			// Validate flags.
			if err := validateHashreleasePublishFlags(c); err != nil {
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
				return fmt.Errorf("%s hashrelease (%s) has already been published", hashrel.Name, hashrel.Hash)
			}

			// Push the operator hashrelease first before validation.
			// This is because validation checks all images exists and sends to Image Scan Service
			o := operator.NewEnterpriseManager(
				operator.WithOperatorDirectory(filepath.Join(cfg.TmpDir, operator.DefaultRepoName)),
				operator.IsHashRelease(),
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
				calico.WithImageScanning(!c.Bool(skipImageScanFlag.Name), *imageScanningAPIConfig(c)),
			}
			componentRegistry := registry.TigeraDevCIGCRRegistry
			if reg := c.StringSlice(registryFlag.Name); len(reg) > 0 {
				calicoOpts = append(calicoOpts, calico.WithImageRegistries(reg))
				componentRegistry = reg[0]
			} else {
				calicoOpts = append(calicoOpts, calico.WithImageRegistries([]string{componentRegistry}))
			}

			components, err := pinnedversion.RetrieveEnterpriseImageComponents(cfg.TmpDir, componentRegistry)
			if err != nil {
				return fmt.Errorf("failed to retrieve images for the hashrelease: %v", err)
			}
			calicoOpts = append(calicoOpts, calico.WithComponents(components))

			enterpriseOpts := []calico.EnterpriseOption{
				calico.WithChartVersion(hashrel.ChartVersion),
				calico.WithEnterpriseHashrelease(*hashrel, *serverCfg),
				calico.WithPublishCharts(c.Bool(publishChartsFlag.Name)),
				calico.WithPublishWindowsArchive(c.Bool(publishWindowsArchiveFlag.Name)),
				calico.WithHelmRegistry(c.String(helmRegistryFlag.Name)),
			}

			m := calico.NewEnterpriseManager(calicoOpts, enterpriseOpts...)
			if err := m.PublishRelease(); err != nil {
				return err
			}

			// Send a slack message to notify that the hashrelease has been published.
			if c.Bool(publishHashreleaseFlag.Name) {
				return tasks.AnnounceHashrelease(slackConfig(c), &hashrel.Hashrelease, ciJobURL(c))
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
			&cli.StringFlag{Name: "dir", Usage: "Directory to write metadata to", EnvVars: []string{"METADATA_DIR"}, Value: "", Required: true},
			&cli.StringFlag{Name: "versions-file", Usage: "Path to the versions file", EnvVars: []string{"VERSIONS_FILE"}, Value: "", Required: true},
		},
		Action: func(c *cli.Context) error {
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
