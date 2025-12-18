package calico

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"text/template"

	"github.com/sirupsen/logrus"
	"go.yaml.in/yaml/v3"
	"golang.org/x/sync/errgroup"

	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/imagescanner"
	"github.com/projectcalico/calico/release/internal/pinnedversion"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
	"github.com/projectcalico/calico/release/pkg/manager/branch"
	"github.com/projectcalico/calico/release/pkg/manager/manager"
	"github.com/projectcalico/calico/release/pkg/manager/operator"
)

var (
	defaultEnterpriseRegistry = registry.DefaultEnterpriseRegistry

	enterpriseWindowsGCSBucket = utils.EnterpriseWindowsGCSBucketName

	docsURL = "https://docs.tigera.io"

	enterpriseArtifactsBaseURL = utils.EnterpriseArtifactsBaseURL

	enterpriseS3Bucket = "tigera-public/ee"
	s3ACLPublicRead    = []string{"--acl", "public-read"}

	enterpriseImageReleaseDirs = utils.EnterpriseImageReleaseDirs

	// Directories that publish images for cloud.
	cloudImageReleaseDirs = []string{
		"kube-controllers",
		"kibana",
	}

	// Directories that publish images for windows releases.
	enterpriseWindowsReleaseDirs = []string{
		"cni-plugin",
		"fluentd",
		"node",
	}

	// Directories that publish binaries for enterprise releases.
	enterpriseBinaryReleaseDirs = []string{
		"calicoctl",
		"calicoq",
	}

	//go:embed templates/yum.conf.gotmpl
	rpmRepoTemplate string
	RHELVersions    = []string{"8", "9"}
	rpmDirs         = []string{
		"node",
		"fluent-bit",
		"selinux",
	}
)

func NewEnterpriseManager(calicoOpts []Option, opts ...EnterpriseOption) *EnterpriseManager {
	defaultCalicoOpts := []Option{
		WithImageRegistries([]string{defaultEnterpriseRegistry}),
		WithBuildImages(false),
		WithArchiveImages(false),
		WithPublishGithubRelease(false),
	}
	calicoOpts = append(defaultCalicoOpts, calicoOpts...)
	calicoManager := NewManager(calicoOpts...)
	calicoManager.productCode = utils.EnterpriseProductCode

	m := &EnterpriseManager{
		CalicoManager:                 *calicoManager,
		publishWindowsArchive:         true,
		windowsArchiveBucket:          enterpriseWindowsGCSBucket,
		publishCharts:                 true,
		helmRegistry:                  registry.HelmDevRegistry, // Defaults to dev registry as currently only used for hashreleases.
		enterpriseHashreleaseRegistry: registry.DefaultEnterpriseHashreleaseRegistry,
		s3Bucket:                      enterpriseS3Bucket,
		baseArtifactsURL:              enterpriseArtifactsBaseURL,
		imageReleaseDirs:              enterpriseImageReleaseDirs,
		includeManager:                true,
	}

	for _, o := range opts {
		if err := o(m); err != nil {
			logrus.WithError(err).Fatal("Failed to apply option to enterprise manager")
		}
	}
	if m.chartVersion != "" {
		logrus.WithField("chartVersion", m.chartVersion).Info("Using chart version")
	}

	return m
}

type EnterpriseManager struct {
	CalicoManager

	// imageReleaseDirs is the list of directories from which we should publish images.
	imageReleaseDirs []string

	// manager variables
	includeManager bool

	devTagSuffix string

	// chartVersion is the version of the helm chart to build.
	chartVersion string

	enterpriseHashrelease hashreleaseserver.EnterpriseHashrelease

	// enterpriseHashreleaseRegistry is the registry to get hashrelease images that are used for release.
	enterpriseHashreleaseRegistry string

	// publishing options
	dryRun                bool
	publishWindowsArchive bool
	publishCharts         bool
	publishToS3           bool

	rpm bool

	helmRegistry         string
	windowsArchiveBucket string
	awsProfile           string
	s3Bucket             string
	baseArtifactsURL     string
}

func (m *EnterpriseManager) helmChartVersion() string {
	if m.chartVersion == "" {
		return m.calicoVersion
	}
	return fmt.Sprintf("%s-%s", m.calicoVersion, m.chartVersion)
}

func (m *EnterpriseManager) resetCharts() {
	// Reset the changes to the charts directory.
	if _, err := m.runner.RunInDir(m.repoRoot, "git", []string{"checkout", "charts/"}, nil); err != nil {
		logrus.WithError(err).Error("Failed to reset changes to charts")
	}
}

func (m *EnterpriseManager) modifyHelmChartsValues() error {
	if err := m.CalicoManager.modifyHelmChartsValues(); err != nil {
		return err
	}

	// Modify the tigera-prometheus-operator values.yaml file to use the calico version.
	prometheusValuesYAML := filepath.Join(m.repoRoot, "charts", "tigera-prometheus-operator", "values.yaml")
	if _, err := m.runner.Run("sed", []string{"-i", fmt.Sprintf(`s/tag: .*/tag: %s/g`, m.calicoVersion), prometheusValuesYAML}, nil); err != nil {
		logrus.WithError(err).Error("Failed to update calicoctl version in values.yaml")
		return err
	}

	// Update the registry in the tigera-operator & tigera-prometheus-operator values.yaml file.
	operatorValuesYAML := filepath.Join(m.repoRoot, "charts", "tigera-operator", "values.yaml")
	if _, err := m.runner.Run("sed", []string{"-i", fmt.Sprintf(`s~registry: %s~registry: %s~g`, operator.DefaultRegistry, m.operatorRegistry), operatorValuesYAML}, nil); err != nil {
		logrus.WithField("file", operatorValuesYAML).WithError(err).Error("failed to update operator registry in values file")
		return err
	}
	if _, err := m.runner.Run("sed", []string{"-i", fmt.Sprintf(`s~image: %s~image: %s~g`, operator.DefaultImage, m.operatorImage), operatorValuesYAML}, nil); err != nil {
		logrus.WithField("file", operatorValuesYAML).WithError(err).Error("failed to update operator image in values file")
		return err
	}
	var registry string
	if len(m.imageRegistries) > 0 {
		registry = m.imageRegistries[0]
	}
	manifestRegistry, err := m.getRegistryFromCharts()
	if err != nil {
		logrus.WithError(err).Error("failed to get registry from charts")
		return err
	}
	if _, err := m.runner.Run("sed", []string{"-i", fmt.Sprintf(`s~image: %s~image: %s~g`, manifestRegistry, registry), operatorValuesYAML}, nil); err != nil {
		logrus.WithField("file", operatorValuesYAML).WithError(err).Error("failed to update product registry in values file")
		return err
	}
	if _, err := m.runner.Run("sed", []string{"-i", fmt.Sprintf(`s~%s~%s~g`, manifestRegistry, registry), prometheusValuesYAML}, nil); err != nil {
		logrus.WithField("file", prometheusValuesYAML).WithError(err).Error("failed to update registry in values file")
		return err
	}
	return nil
}

func (m *EnterpriseManager) BuildHelm() error {
	logrus.Info("Building helm charts")
	if m.isHashRelease {
		// Reset the changes to the charts directory.
		defer m.resetCharts()

		if err := m.modifyHelmChartsValues(); err != nil {
			return err
		}
	}

	// Build the helm chart, passing the version to use.
	env := append(os.Environ(), fmt.Sprintf("GIT_VERSION=%s", m.calicoVersion))
	env = append(env, fmt.Sprintf("RELEASE_STREAM=%s", m.calicoVersion))
	if m.chartVersion != "" {
		env = append(env, fmt.Sprintf("CHART_RELEASE=%s", m.chartVersion))
	}
	if err := m.makeInDirectoryIgnoreOutput(m.repoRoot, "chart", env...); err != nil {
		return err
	}

	logrus.Info("Done building helm charts")
	return nil
}

func (m *EnterpriseManager) PreBuildValidation() error {
	if m.isHashRelease {
		return m.PreHashreleaseValidate()
	}
	return m.PreReleaseValidate()
}

func (m *EnterpriseManager) PreReleaseValidate() error {
	// Cheeck that we are on a release branch
	if m.validateBranch {
		branch, err := utils.GitBranch(m.repoRoot)
		if err != nil {
			return fmt.Errorf("failed to determine branch: %s", err)
		}
		match := fmt.Sprintf(`^%s-v\d+\.\d+(?:-\d+)?$`, m.releaseBranchPrefix)
		re := regexp.MustCompile(match)
		if !re.MatchString(branch) {
			return fmt.Errorf("current branch (%s) is not a release branch", branch)
		}
	}

	// Check that the chart version is specified.
	if m.chartVersion == "" {
		return fmt.Errorf("chart version is not specified")
	}

	// Check that code generation is up-to-date.
	if err := m.makeInDirectoryIgnoreOutput(m.repoRoot, "generate get-operator-crds check-dirty"); err != nil {
		return fmt.Errorf("code generation error (try 'make generate' and/or 'make get-operator-crds' ?): %s", err)
	}
	if m.rpm {
		createrepo := "createrepo_c"
		if path, err := exec.LookPath(createrepo); err != nil {
			logrus.WithError(err).Errorf("Error trying to find %s in PATH", createrepo)
			return fmt.Errorf("unable to find %s in PATH", createrepo)
		} else if path == "" {
			logrus.Errorf("%s not found in PATH", createrepo)
			return fmt.Errorf("%s not found in PATH", createrepo)
		}
	}

	// Check that the helm chart version is specified.
	if m.chartVersion == "" {
		logrus.Fatal("No chart version specified")
	}

	return m.prepPrereqs()
}

func (m *EnterpriseManager) generateManifests() error {
	// Manifests are expecting registry to be the Contaier registry platform.
	env := os.Environ()
	env = append(env, fmt.Sprintf("PRODUCT_VERSION=%s", m.calicoVersion))
	env = append(env, fmt.Sprintf("REGISTRY=%s", m.imageRegistries[0]))
	env = append(env, fmt.Sprintf("OPERATOR_VERSION=%s", m.operatorVersion))
	env = append(env, fmt.Sprintf("OPERATOR_REGISTRY_OVERRIDE=%s", m.operatorRegistry))
	env = append(env, fmt.Sprintf("OPERATOR_IMAGE_OVERRIDE=%s", m.operatorImage))
	if m.isHashRelease {
		env = append(env, fmt.Sprintf("VERSIONS_FILE=%s", pinnedversion.PinnedVersionFilePath(m.tmpDir)))
	}
	if err := m.makeInDirectoryIgnoreOutput(m.repoRoot, "gen-manifests", env...); err != nil {
		logrus.WithError(err).Error("Failed to make manifests")
		return err
	}
	return nil
}

func (m *EnterpriseManager) Build() error {
	// Make sure output directory exists.
	if err := os.MkdirAll(m.uploadDir(), utils.DirPerms); err != nil {
		return fmt.Errorf("failed to create output dir: %s", err)
	}
	// Make sure tmp directory exists.
	if m.tmpDir != "" {
		if err := os.MkdirAll(m.tmpDir, utils.DirPerms); err != nil {
			return fmt.Errorf("failed to create tmp dir: %s", err)
		}
	}

	if m.validate {
		if err := m.validateGitVersion(); err != nil {
			return err
		}
		if err := m.PreBuildValidation(); err != nil {
			return fmt.Errorf("failed pre-build validation: %s", err)
		}
	}

	if err := m.BuildHelm(); err != nil {
		return err
	}

	if m.isHashRelease {
		if err := m.generateManifests(); err != nil {
			return err
		}
		defer m.resetManifests()
	}

	// Build OCP bundle from manifests
	if err := m.buildOCPBundle(); err != nil {
		return err
	}

	// Build binaries
	if err := m.buildBinaries(); err != nil {
		return err
	}

	// Build release archives
	if err := m.buildArchives(); err != nil {
		return err
	}

	// Build the RPMs for non-cluster hosts.
	if err := m.assembleRPMs(); err != nil {
		return err
	}

	if err := m.collectArtifacts(); err != nil {
		return err
	}

	return nil
}

type enterpriseMetadata struct {
	metadata      `json:",inline" yaml:",inline"`
	CalicoVersion string `json:"calico_oss_version" yaml:"CalicoOSSVersion"`
}

func (m *EnterpriseManager) getRegistryFromManifests() (string, error) {
	args := []string{"-Po", `image:\K(.*)`, "calicoctl.yaml"}
	out, err := m.runner.RunInDir(filepath.Join(m.repoRoot, "manifests"), "grep", args, nil)
	if err != nil {
		return "", err
	}
	imgs := strings.Split(out, "\n")
	for _, i := range imgs {
		if strings.Contains(i, "operator") {
			continue
		} else if strings.Contains(i, "calicoctl") {
			splits := strings.SplitAfter(i, "/calicoctl")
			registry := strings.TrimSuffix(splits[0], "/calicoctl")
			logrus.WithField("registry", registry).Debugf("Using registry from image %s", i)
			return registry, nil
		}
	}
	return "", fmt.Errorf("failed to determine registry from manifests")
}

func (m *EnterpriseManager) getRegistryFromCharts() (string, error) {
	args := []string{"-Po", `image:\K(.*)`, "tigera-operator/values.yaml"}
	out, err := m.runner.RunInDir(filepath.Join(m.repoRoot, "charts"), "grep", args, nil)
	if err != nil {
		return "", err
	}
	imgs := strings.Split(out, "\n")
	for _, i := range imgs {
		if strings.Contains(i, "operator") {
			continue
		} else if strings.Contains(i, "tigera/") {
			splits := strings.SplitAfter(i, "/tigera/")
			registry := strings.TrimSuffix(splits[0], "/")
			registry = strings.TrimSpace(registry)
			logrus.WithField("registry", registry).Debugf("Using registry from image %s", i)
			return registry, nil
		}
	}
	return "", fmt.Errorf("failed to determine registry from charts")
}

func (m *EnterpriseManager) BuildMetadata(dir string) error {
	if err := os.MkdirAll(dir, utils.DirPerms); err != nil {
		return fmt.Errorf("failed to create metadata dir: %w", err)
	}
	registry, err := m.getRegistryFromManifests()
	if err != nil {
		return fmt.Errorf("failed to get registry from manifests: %w", err)
	}

	calicoVer, err := utils.DetermineCalicoVersion(m.repoRoot)
	if err != nil {
		return fmt.Errorf("failed to determine calico version: %w", err)
	}

	enterpriseImages, err := utils.BuildReleaseImageList(m.repoRoot, m.imageReleaseDirs...)
	if err != nil {
		return fmt.Errorf("failed to get images built by release dirs: %w", err)
	}
	managerImage := fmt.Sprintf("%s/%s:%s", registry, manager.DefaultImage, m.calicoVersion)
	if m.isHashRelease {
		// For hash releases, the manager image is a different version.
		managerImage = fmt.Sprintf("%s/%s:%s", registry, manager.DefaultImage, m.enterpriseHashrelease.ManagerVersion)
	}
	images := releaseImages(enterpriseImages, m.calicoVersion, registry, m.operatorImage, m.operatorVersion, m.operatorRegistry)
	if m.includeManager {
		images = append(images, managerImage)
	}

	data := enterpriseMetadata{
		metadata: metadata{
			Version:          m.calicoVersion,
			OperatorVersion:  m.operatorVersion,
			Images:           images,
			HelmChartVersion: m.helmChartVersion(),
		},
		CalicoVersion: calicoVer,
	}

	// Render it as yaml and write it to a file.
	bs, err := yaml.Marshal(data)
	if err != nil {
		return err
	}

	err = os.WriteFile(filepath.Join(dir, metadataFileName), []byte(bs), 0o644)
	if err != nil {
		return err
	}

	return nil
}

// buildArchives build windows and release archives.“
func (m *EnterpriseManager) buildArchives() error {
	// Build the release archive.
	logrus.Info("Building release archive")
	env := os.Environ()
	if m.isHashRelease {
		env = append(env, fmt.Sprintf("VERSIONS_FILE=%s", pinnedversion.PinnedVersionFilePath(m.tmpDir)))
	}
	if m.chartVersion != "" {
		env = append(env, fmt.Sprintf("CHART_RELEASE=%s", m.chartVersion))
	}
	if err := m.makeInDirectoryIgnoreOutput(m.repoRoot, "release-archive", env...); err != nil {
		return err
	}

	// Build the windows archive.
	logrus.Info("Building windows release archive")
	env = append(os.Environ(), fmt.Sprintf("VERSION=%s", m.calicoVersion))
	if err := m.makeInDirectoryIgnoreOutput(filepath.Join(m.repoRoot, "node"), "release-windows-archive", env...); err != nil {
		return fmt.Errorf("failed to build windows archive: %s", err)
	}
	return nil
}

func (m *EnterpriseManager) buildBinaries() error {
	env := append(os.Environ(), fmt.Sprintf("VERSION=%s", m.calicoVersion))
	for _, dir := range enterpriseBinaryReleaseDirs {
		out, err := m.makeInDirectoryWithOutput(filepath.Join(m.repoRoot, dir), "release-build-binaries", env...)
		if err != nil {
			logrus.Error(out)
			return fmt.Errorf("failed to build %s: %s", dir, err)
		}
		logrus.Info(out)
	}
	return nil
}

type rpmRepoData struct {
	BaseURL string
	Version string
}

func createRPMPackageList(dir, out string) error {
	var rpmFiles []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logrus.WithError(err).Error("Error accessing path")
			return nil
		}
		if !info.IsDir() && filepath.Ext(path) == ".rpm" {
			relPath, _ := filepath.Rel(dir, path)
			rpmFiles = append(rpmFiles, relPath)
		}
		return nil
	})
	if err != nil {
		return err
	}
	file, err := os.Create(out)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	for _, rpmFileName := range rpmFiles {
		if _, err := fmt.Fprintf(file, "%s\n", rpmFileName); err != nil {
			return err
		}
	}
	return nil
}

func (m *EnterpriseManager) assembleRPMs() error {
	if !m.rpm {
		logrus.Info("Skipping building RPMs")
		return nil
	}

	logrus.Info("Building RPMs")
	outDir := filepath.Join(m.uploadDir(), "non-cluster-host-rpms")
	if err := os.MkdirAll(outDir, utils.DirPerms); err != nil {
		return err
	}

	rsyncOpts := []string{"--recursive", "--prune-empty-dirs", "--exclude=BUILD", "--exclude=SRPMS", "--exclude=*debuginfo*", "--exclude=*debugsource*"}
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		rsyncOpts = append(rsyncOpts, "--verbose", "--progress")
	}

	ver := version.Version(m.calicoVersion)
	if !m.isHashRelease {
		// Get the metadata from the remote repo.
		// This is needed as we publish based on vX.Y to ease upgrading.
		logrus.Debug("Downloading RPM metadata from remote")
		if err := m.s3Cp(fmt.Sprintf("s3://%s/rpms/%s/", m.s3Bucket, ver.PrimaryStream()), outDir+"/", "--exclude", `"*.rpm"`); err != nil {
			// Only log the error and continue as it likely means the metadata is not available.
			logrus.WithError(err).Errorf("failed to download RPM metadata for %s", ver.PrimaryStream())
		}
	}

	for _, dir := range rpmDirs {
		logrus.WithField("package", dir).Info("Building RPM package")
		if err := m.makeInDirectoryIgnoreOutput(filepath.Join(m.repoRoot, dir), "package"); err != nil {
			logrus.WithError(err).Errorf("Failed to build RPM package for %s", dir)
			return err
		}
		srcDir := filepath.Join(m.repoRoot, dir, "package") + "/"
		destDir := outDir + "/"
		logrus.WithFields(logrus.Fields{
			"package": dir,
			"srcDir":  srcDir,
			"destDir": destDir,
		}).Debug("Copying RPM package")
		if _, err := m.runner.Run("rsync", append(rsyncOpts, srcDir, destDir), nil); err != nil {
			logrus.WithFields(logrus.Fields{
				"package": dir,
				"sr":      srcDir,
				"dest":    destDir,
			}).WithError(err).Error("Failed copy RPMs")
			return err
		}
	}

	createrepo := "createrepo_c"
	var rpmURLBase string
	if m.isHashRelease {
		rpmURLBase = fmt.Sprintf("%s/non-cluster-host-rpms", m.hashrelease.URL())
	} else {
		rpmURLBase = fmt.Sprintf("%s/rpms/%s", m.baseArtifactsURL, ver.PrimaryStream())
	}

	tmpl, err := template.New("yum.conf").Parse(rpmRepoTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse yum repo template: %s", err)
	}
	for _, version := range RHELVersions {
		rhelDir := filepath.Join(outDir, fmt.Sprintf("rhel%s", version))
		pkgListPath := filepath.Join(m.tmpDir, fmt.Sprintf("%s-rhel%s-pkglist.txt", m.calicoVersion, version))
		rpmURL := filepath.Join(rpmURLBase, fmt.Sprintf("rhel%s/", version))
		if err := createRPMPackageList(rhelDir, pkgListPath); err != nil {
			logrus.WithError(err).Errorf("Failed to create RPM package list for RHEL %s", version)
			return fmt.Errorf("failed to create RPM package list for RHEL %s: %s", version, err)
		}
		logrus.WithField("RHELVersion", version).Debug("Creating repo to test with yum/dnf/etc")
		args := []string{
			"--update",
			"--recycle-pkglist",
			fmt.Sprintf("--pkglist=%s", pkgListPath),
			fmt.Sprintf("--baseurl=%s", rpmURL),
			"--xz",
		}
		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			args = append(args, "--verbose")
		} else {
			args = append(args, "--skip-stat")
		}
		args = append(args, ".")
		if _, err := m.runner.RunInDir(rhelDir, createrepo, args, nil); err != nil {
			logrus.WithError(err).Errorf("Failed to create repo for RHEL %s", version)
			return fmt.Errorf("failed to create repo for RHEL %s: %s", version, err)
		}
		logrus.WithField("RHELVersion", version).Info("Writing yum repo config file")

		repoFile, err := os.Create(filepath.Join(outDir, fmt.Sprintf("calico_rhel%s.repo", version)))
		if err != nil {
			return fmt.Errorf("failed to create yum repo config file: %s", err)
		}
		defer func() { _ = repoFile.Close() }()
		data := &rpmRepoData{
			BaseURL: rpmURLBase,
			Version: version,
		}
		if err := tmpl.Execute(repoFile, data); err != nil {
			logrus.WithField("version", version).WithError(err).Error("Failed to write yum repo config file")
			return fmt.Errorf("failed to write yum repo config file: %s", err)
		}
		logrus.WithField("RHELVersion", version).Debug("Wrote yum repo config file")
	}

	// Add combined repo config file.
	logrus.Infof("Creating yum repo config file for %s", ver.PrimaryStream())
	combinedRepoFile, err := os.Create(filepath.Join(outDir, "calico_enterprise.repo"))
	if err != nil {
		return fmt.Errorf("failed to create combined yum repo config file: %s", err)
	}
	defer func() { _ = combinedRepoFile.Close() }()
	data := &rpmRepoData{
		BaseURL: rpmURLBase,
	}
	if err := tmpl.Execute(combinedRepoFile, data); err != nil {
		logrus.WithError(err).Error("Failed to write combined yum repo config file")
		return fmt.Errorf("failed to write combined yum repo config file: %s", err)
	}
	logrus.Debug("Wrote combined yum repo config file")
	return nil
}

func (m *EnterpriseManager) collectArtifacts() error {
	// Artifacts will be moved here.
	uploadDir := m.uploadDir()

	// Add in a release metadata file.
	err := m.BuildMetadata(uploadDir)
	if err != nil {
		return fmt.Errorf("failed to build release metadata file: %s", err)
	}

	// Add the manifests (this includes OCP bundle).
	manifestsSrc := filepath.Join(m.repoRoot, "manifests") + "/"
	manifestsDest := filepath.Join(uploadDir, "manifests") + "/"
	if err := os.MkdirAll(manifestsDest, utils.DirPerms); err != nil {
		return fmt.Errorf("failed to create manifests directory: %s", err)
	}
	rsyncArgs := []string{"-av", "--delete", "--exclude=generate.sh", "--exclude=README.md", "--exclude=.gitattributes"}
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		rsyncArgs = append(rsyncArgs, "--verbose", "--progress")
	}
	if _, err := m.runner.Run("rsync", append(rsyncArgs, manifestsSrc, manifestsDest), nil); err != nil {
		logrus.WithError(err).Error("Failed to copy manifests to output directory")
		return fmt.Errorf("failed to copy manifests to output directory: %w", err)
	}

	if err := os.MkdirAll(m.scriptsDir(), utils.DirPerms); err != nil {
		return fmt.Errorf("failed to create scripts directory: %w", err)
	}

	// Add the Windows install script
	if _, err := m.runner.RunInDir(m.repoRoot, "cp", []string{"node/windows-packaging/install-calico-windows.ps1", m.scriptsDir()}, nil); err != nil {
		return fmt.Errorf("failed to copy Windows install script: %w", err)
	}
	// Move the Windows archive to temp dir
	if _, err := m.runner.RunInDir(m.repoRoot, "cp", []string{fmt.Sprintf("node/dist/tigera-calico-windows-%s.zip", m.calicoVersion), m.tmpDir}, nil); err != nil {
		return fmt.Errorf("failed to move Windows archive: %w", err)
	}

	// Add helm charts
	charts, err := listCharts(filepath.Join(m.repoRoot, "bin"), m.calicoVersion)
	if err != nil {
		logrus.WithError(err).Error("Failed to get list of charts")
	}
	chartsDir := filepath.Join(uploadDir, "charts")
	if err := os.MkdirAll(chartsDir, utils.DirPerms); err != nil {
		return fmt.Errorf("failed to create charts directory: %s", err)
	}
	for _, chart := range charts {
		logrus.WithField("chart", chart).Debug("Copying chart")
		chartName := filepath.Base(chart)
		chartDest := filepath.Join(chartsDir, strings.ReplaceAll(chartName, m.calicoVersion, m.helmChartVersion()))
		if err := utils.CopyFile(chart, chartDest); err != nil {
			logrus.WithError(err).Error("Failed to copy chart")
			return err
		}
		if strings.Contains(chartName, "tigera-operator") {
			if _, err := m.runner.RunInDir(m.repoRoot, "cp", []string{chartDest, uploadDir}, nil); err != nil {
				return err
			}
		}
	}

	// Add the binaries
	rsyncArgs = []string{"-av"}
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		rsyncArgs = append(rsyncArgs, "--verbose", "--progress")
	}
	binDir := filepath.Join(uploadDir, "binaries")
	if err := os.MkdirAll(binDir, utils.DirPerms); err != nil {
		return fmt.Errorf("failed to create binaries directory: %s", err)
	}
	for _, dir := range enterpriseBinaryReleaseDirs {
		rsyncArgs = append(rsyncArgs, "--include", fmt.Sprintf("%s-*", dir))
		src := filepath.Join(m.repoRoot, dir, "bin") + "/"
		dest := binDir + "/"
		if _, err := m.runner.Run("rsync", append(rsyncArgs, src, dest), nil); err != nil {
			return fmt.Errorf("failed to copy %s binaries from %s to %s: %w", dir, src, dest, err)
		}
		defaultSuffix := "-amd64"
		if dir == "calicoctl" {
			defaultSuffix = "-linux" + defaultSuffix
		}
		if _, err := m.runner.RunInDir(binDir, "mv", []string{fmt.Sprintf("%s%s", dir, defaultSuffix), dir}, nil); err != nil {
			return fmt.Errorf("failed to rename %s-%s binary to %s: %w", dir, defaultSuffix, dir, err)
		}
	}

	// Add the release archive
	if _, err := m.runner.RunInDir(m.repoRoot, "cp", []string{fmt.Sprintf("_release_archive/release-%s-%s.tgz", m.calicoVersion, m.operatorVersion), uploadDir}, nil); err != nil {
		return err
	}

	if m.isHashRelease {
		if err := m.fetchEnterpriseScripts(); err != nil {
			return err
		}
	}

	return nil
}

func listCharts(dir, version string) ([]string, error) {
	matchingFiles := []string{}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logrus.WithField("path", path).WithError(err).Error("Error accessing path")
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".tgz") && strings.Contains(info.Name(), version) {
			matchingFiles = append(matchingFiles, path)
		}
		return nil
	})
	return matchingFiles, err
}

func (m *EnterpriseManager) scriptsDir() string {
	return filepath.Join(m.uploadDir(), "scripts")
}

// Retrieve scripts from the docs site and include them in the hashrelease.
func (m *EnterpriseManager) fetchEnterpriseScripts() error {
	// Fetch switch-active-operator.sh script from the latest docs
	switchActiveOperatorFilename := "switch-active-operator.sh"
	switchActiveOperatorFile, err := os.Create(filepath.Join(m.scriptsDir(), switchActiveOperatorFilename))
	if err != nil {
		return err
	}
	defer func() { _ = switchActiveOperatorFile.Close() }()
	resp, err := http.Get(fmt.Sprintf("%s/%s/next/scripts/%s", docsURL, strings.ReplaceAll(utils.CalicoEnterprise, " ", "-"), switchActiveOperatorFilename))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return err
	}
	if _, err := io.Copy(switchActiveOperatorFile, resp.Body); err != nil {
		return err
	}

	return nil
}

func (m *EnterpriseManager) publishPrereqs() error {
	if !m.validate {
		logrus.Warn("Skipping pre-publish validation")
		return nil
	}
	if dirty, err := utils.GitIsDirty(m.repoRoot); dirty || err != nil {
		return fmt.Errorf("there are uncommitted changes in the repository, please commit or stash them before publishing the release")
	}
	if err := m.validateGitVersion(); err != nil {
		return err
	}
	if m.isHashRelease {
		return m.hashreleasePrereqs()
	}

	// Check that the helm chart version is specified.
	if m.chartVersion == "" {
		logrus.Fatal("No chart version specified")
	}
	return m.prepPrereqs()
}

// validateGitVersion checks that the git version contains the dev tag suffix.
// This is used to ensure that we do not publish a release with the wrong dev tag.
func (m *EnterpriseManager) validateGitVersion() error {
	gitVersion := version.GitVersion()
	if !version.HasDevTag(gitVersion, m.devTagSuffix) {
		err := fmt.Errorf("git version %s does not contain dev tag suffix %s", gitVersion, m.devTagSuffix)
		logrus.Error(err)
		return err
	}
	return nil
}

func (m *EnterpriseManager) PublishRelease() error {
	// Check that the environment has the necessary prereqs.
	if err := m.publishPrereqs(); err != nil {
		return err
	}

	if !m.isHashRelease {
		if err := m.publishReleaseImages(); err != nil {
			return err
		}
	}

	if m.imageScanning {
		logrus.Info("Sending images to ISS")
		imageScanner := imagescanner.New(m.imageScanningConfig)
		// For ISS, it does not care if it is EP1 or EP2 or GA, we just need the main stream.
		mainStream := strings.Split(m.hashrelease.Stream, "-")[0]
		err := imageScanner.Scan(m.productCode, slices.Collect(maps.Values(m.componentImages())), mainStream, !m.isHashRelease, m.tmpDir)
		if err != nil {
			// Error is logged and ignored as a failure fron ISS should not halt the release process.
			logrus.WithError(err).Error("Failed to scan images")
		}
	}

	if err := m.publishWindowsArchiveToGCS(); err != nil {
		return err
	}
	if err := m.publishHelmCharts(); err != nil {
		return err
	}
	if m.isHashRelease {
		return m.publishToHashreleaseServer()
	}

	if err := m.publishArtifactsToS3(); err != nil {
		return err
	}

	if !m.isHashRelease {
		// Create the next development tag.
		ver := version.Version(m.calicoVersion)
		branchManager := branch.NewManager(branch.WithRepoRoot(m.repoRoot),
			branch.WithRepoRemote(m.remote),
			branch.WithMainBranch(fmt.Sprintf("%s-%s", m.releaseBranchPrefix, ver.Stream())),
			branch.WithDevTagIdentifier(m.devTagSuffix),
			branch.WithReleaseBranchPrefix(m.releaseBranchPrefix),
			branch.WithValidate(m.validate),
			branch.WithPublish(m.publishTag && !m.dryRun))

		return branchManager.CreateNextDevelopmentTag(m.calicoVersion)
	}
	return nil
}

// makeInDirectoryWithOutputFn defines a function type for running make
// in a given directory returning the command output and an error if the command fails.
type makeInDirectoryWithOutputFn func(dir, target string, env ...string) (string, error)

// cutReleaseImage attempts to cut release images in specified directory
// by using the provided make function to run "cut-release-image" make target
// in the provided dir with the specified environment variables.
func cutReleaseImage(ctx context.Context, fn makeInDirectoryWithOutputFn, dir string, env []string) error {
	// We allow for a certain number of retries when publishing each directory, since
	// network flakes can occasionally result in images failing to push.
	log := logrus.WithField("directory", dir)
	for _, e := range env {
		if strings.HasPrefix(e, "TESLA") {
			log = log.WithField("cloud_image", strings.SplitN(e, "=", 2)[1])
		} else if strings.HasPrefix(e, "WINDOWS_RELEASE") {
			log = log.WithField("windows_image", strings.SplitN(e, "=", 2)[1])
		}
	}
	maxRetries := 1
	attempt := 0
	for {
		// Check if the context has been cancelled
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Attempt to cut the release image
		out, err := fn(dir, "cut-release-image", env...)
		if err != nil {
			if attempt < maxRetries {
				log.WithField("attempt", attempt).WithError(err).Error("Publish failed, retrying")
				attempt++
				continue
			}
			// Log the output and return a formatted error
			log.Error(out)
			return fmt.Errorf("failed to publish %s images: %w", dir, err)
		}
		// Success - move on
		log.Info(out)
		break
	}
	return nil
}

// publishReleaseImages publishes the release images for enterprise
// It will only publish images if the publishImages flag is set to true.
//
// It uses concurrency to publish images from multiple directories in parallel.
// The actual publishing is done by the cutReleaseImage function.
// Using sync.errgroup to manage goroutines, this ensures that all publishing
// tasks are completed before returning.
// If any of the publishing fails, the error is returned and the entire process is halted.
func (m *EnterpriseManager) publishReleaseImages() error {
	if !m.publishImages {
		logrus.Info("Skipping publishing release images")
		return nil
	}

	eg, ctx := errgroup.WithContext(context.Background())

	// Publish release images.
	logrus.Info("Start publishing release images")
	env := append(os.Environ(),
		"RELEASE=true",
		"IMAGE_ONLY=true",
		fmt.Sprintf("DEV_TAG=%s", m.enterpriseHashrelease.ProductVersion),
		fmt.Sprintf("DEV_REGISTRIES=%s", m.enterpriseHashreleaseRegistry),
		fmt.Sprintf("RELEASE_REGISTRIES=%s", m.imageRegistries[0]),
		fmt.Sprintf("RELEASE_TAG=%s", m.calicoVersion),
	)
	if m.dryRun {
		env = append(env, "DRYRUN=true")
	} else {
		env = append(env, "CONFIRM=true")
	}
	if !m.publishTag {
		env = append(env, "SKIP_DEV_IMAGE_RETAG=true")
	}
	for _, dir := range enterpriseImageReleaseDirs {
		baseEnv := slices.Clone(env)
		current := dir
		d := filepath.Join(m.repoRoot, current)
		eg.Go(func() error {
			return cutReleaseImage(ctx, m.makeInDirectoryWithOutput, d, baseEnv)
		})

		// Publish images for cloud if the directory produces Calico Cloud images
		if slices.Contains(cloudImageReleaseDirs, dir) {
			eg.Go(func() error {
				return cutReleaseImage(ctx, m.makeInDirectoryWithOutput, d, append(baseEnv, "TESLA=true"))
			})
		}

		// Publish images for Windows if the directory produces Windows images
		if slices.Contains(enterpriseWindowsReleaseDirs, current) {
			eg.Go(func() error {
				return cutReleaseImage(ctx, m.makeInDirectoryWithOutput, d, append(baseEnv, "WINDOWS_RELEASE=true"))
			})
		}
	}
	if err := eg.Wait(); err != nil {
		return fmt.Errorf("failed to publish release images: %s", err)
	}
	logrus.Info("Finished publishing release images")
	return nil
}

func (m *EnterpriseManager) publishArtifactsToS3() error {
	if !m.publishToS3 {
		logrus.Info("Skipping publishing release artifacts to S3")
		return nil
	}
	logrus.Info("Start publishing release artifacts to S3")
	logrus.WithField("artifact", "manifests").Info("Publishing artifacts to S3")
	if err := m.s3Cp(filepath.Join(m.uploadDir(), "manifests")+"/", fmt.Sprintf("s3://%s/%s/manifests/", m.s3Bucket, m.calicoVersion), s3ACLPublicRead...); err != nil {
		return fmt.Errorf("failed to publish manifests: %s", err)
	}
	logrus.WithField("artifact", "binaries").Info("Publishing artifacts to S3")
	if err := m.s3Cp(filepath.Join(m.uploadDir(), "binaries")+"/", fmt.Sprintf("s3://%s/binaries/%s/", m.s3Bucket, m.calicoVersion), s3ACLPublicRead...); err != nil {
		return fmt.Errorf("failed to publish binaries: %s", err)
	}
	logrus.WithField("artifact", "release archive").Info("Publishing artifacts to S3")
	if err := m.s3Cp(filepath.Join(m.uploadDir(), fmt.Sprintf("release-%s-%s.tgz", m.calicoVersion, m.operatorVersion)), fmt.Sprintf("s3://%s/archives/", m.s3Bucket), s3ACLPublicRead...); err != nil {
		return fmt.Errorf("failed to publish release archive: %s", err)
	}
	logrus.WithField("artifact", "rpms").Info("Publishing artifacts to S3")
	ver := version.Version(m.calicoVersion)
	if err := m.s3Sync(filepath.Join(m.uploadDir(), "non-cluster-host-rpms")+"/", fmt.Sprintf("s3://%s/rpms/%s/", m.s3Bucket, ver.PrimaryStream()), s3ACLPublicRead...); err != nil {
		return fmt.Errorf("failed to publish %s RHEL repo: %s", ver.PrimaryStream(), err)
	}
	logrus.Info("Finished publishing release artifacts to S3")
	return nil
}

func (m *EnterpriseManager) publishWindowsArchiveToGCS() error {
	if !m.publishWindowsArchive {
		logrus.Info("Skipping publishing windows archive")
		return nil
	}
	logrus.Info("Start publishing windows archive to GCS")

	publishSuffix := m.calicoVersion
	if m.isHashRelease {
		publishSuffix = m.enterpriseHashrelease.Name
	}

	src := filepath.Join(m.tmpDir, fmt.Sprintf("tigera-calico-windows-%s.zip", m.calicoVersion))
	dest := fmt.Sprintf("gs://%s/tigera-calico-windows-%s.zip", m.windowsArchiveBucket, publishSuffix)

	if err := m.gcsCp(src, dest); err != nil {
		return fmt.Errorf("failed to publish windows archive to GCS: %s", err)
	}

	logrus.Info("Published windows archive to GCS")
	return nil
}

func (m *EnterpriseManager) publishHelmCharts() error {
	if !m.publishCharts {
		logrus.Info("Skipping publishing helm charts")
		return nil
	}
	logrus.Info("Start publishing helm charts")
	charts, err := listCharts(filepath.Join(m.uploadDir(), "charts"), m.helmChartVersion())
	if err != nil {
		return fmt.Errorf("failed to list charts: %s", err)
	}
	for _, chart := range charts {
		if m.isHashRelease {
			if _, err := m.runner.Run("helm", []string{"push", chart, m.helmRegistry}, nil); err != nil {
				return err
			}
		} else {
			if err := m.s3Cp(chart, fmt.Sprintf("s3://%s/charts/", m.s3Bucket), s3ACLPublicRead...); err != nil {
				return fmt.Errorf("failed to push chart %s: %w", chart, err)
			}
		}
		logrus.WithField("chart", chart).Info("Published helm chart")
	}
	logrus.Info("Finished publishing helm charts")
	return nil
}

func (m *EnterpriseManager) prepPrereqs() error {
	if !m.validate {
		logrus.Info("Skipping release prep validation")
		return nil
	}

	// Check that the git repo is clean.
	if dirty, err := utils.GitIsDirty(m.repoRoot); dirty || err != nil {
		return fmt.Errorf("there are uncommitted changes in the repository, please commit or stash them before publishing the release")
	}

	// Check that we're not on the master branch. We never prep releases from master.
	if branch, err := m.determineBranch(); err != nil {
		return fmt.Errorf("failed to determine current git branch: %w", err)
	} else if branch == "master" {
		return fmt.Errorf("cannot cut release from branch: %s", branch)
	}

	// Check that the versions are release version.
	versionRegex := regexp.MustCompile(`^v\d+\.\d+\.\d+$`)
	if !versionRegex.MatchString(m.operatorVersion) {
		return fmt.Errorf("operator version (%s) is not a release version", m.operatorVersion)
	}
	versionRegex = regexp.MustCompile(`^v\d+\.\d+\.\d+(-\d+.\d+)?$`)
	if !versionRegex.MatchString(m.calicoVersion) {
		return fmt.Errorf("version (%s) is not a release version", m.calicoVersion)
	}
	return nil
}

func (m *EnterpriseManager) PrepareRelease() error {
	if err := m.prepPrereqs(); err != nil {
		return err
	}

	releaseDirs := m.imageReleaseDirs
	if m.includeManager {
		releaseDirs = append(releaseDirs, manager.ReleaseDir)
	}

	// Create or update versions file.
	v := &pinnedversion.EnterpriseReleaseVersions{
		Hashrelease:     m.hashrelease.Name,
		RepoRootDir:     m.repoRoot,
		TmpDir:          m.tmpDir,
		ProductVersion:  m.calicoVersion,
		OperatorVersion: m.operatorVersion,
		OperatorCfg: pinnedversion.OperatorConfig{
			Image:    m.operatorImage,
			Registry: m.operatorRegistry,
		},
		HelmReleaseVersion: m.chartVersion,
		ReleaseDirs:        releaseDirs,
	}
	if err := v.AddToEnterprisePinnedVersionFile(); err != nil {
		return fmt.Errorf("failed to create pinned version file: %w", err)
	}

	ver := version.New(m.calicoVersion)
	baseBranch := fmt.Sprintf("%s-%s", m.releaseBranchPrefix, ver.Stream())
	if b, err := utils.GitBranch(m.repoRoot); err != nil {
		logrus.WithError(err).Error("Failed to determine current git branch for release preparation, will use determined release branch")
	} else {
		baseBranch = b
	}
	defer func() {
		if _, err := m.git("switch", "-f", baseBranch); err != nil {
			logrus.WithError(err).Errorf("Failed to reset to %q branch", baseBranch)
		}
	}()

	// Generate manifests.
	if err := m.generateManifests(); err != nil {
		return fmt.Errorf("failed to generate manifests: %s", err)
	}

	// Update chart values.
	if err := m.modifyHelmChartsValues(); err != nil {
		return fmt.Errorf("failed to update chart versions: %w", err)
	}

	// Create a new branch for the release and commit the changes.
	// Use "switch -C" to force-create the branch in case it already exists.
	// This allows re-running the preparation if needed.
	// Also, force push the branch to remote to update any existing PR.
	prepBranch := fmt.Sprintf("prep-%s", m.calicoVersion)
	if _, err := m.git("switch", "-C", prepBranch); err != nil {
		return fmt.Errorf("failed to create branch %s: %s", prepBranch, err)
	}
	if _, err := m.git("add", filepath.Join(m.repoRoot, "calico"), filepath.Join(m.repoRoot, "charts"), filepath.Join(m.repoRoot, "manifests")); err != nil {
		return fmt.Errorf("failed to add files to git: %s", err)
	}
	if _, err := m.git("commit", "-m", fmt.Sprintf("Updates for %s release", m.calicoVersion)); err != nil {
		return fmt.Errorf("failed to commit changes: %s", err)
	}
	if m.dryRun {
		logrus.WithField("branch", prepBranch).Infof("Dry-run: git push -f %s %s", m.remote, prepBranch)
	} else {
		if _, err := m.git("push", "-f", m.remote, prepBranch); err != nil {
			return fmt.Errorf("failed to push %q branch: %s", prepBranch, err)
		}
	}

	// Create a PR for the release preparation.
	out, err := m.git("config", "--get", "remote.origin.url")
	if err != nil {
		return fmt.Errorf("failed to get remote origin url: %s", err)
	}
	owner := strings.Split(out[strings.Index(out, "git@github.com:")+len("git@github.com:"):strings.LastIndex(out, ".git")], "/")[0]
	args := []string{
		"pr", "create", "--fill",
		"--repo", fmt.Sprintf("%s/%s", m.githubOrg, m.repo),
		"--base", baseBranch,
	}
	if owner != m.githubOrg {
		args = append(args, "--head", fmt.Sprintf("%s:%s", owner, prepBranch))
	} else {
		args = append(args, "--head", prepBranch)
	}
	if m.githubOrg == utils.TigeraOrg && m.repo == utils.CalicoPrivateRepo {
		args = append(args, []string{
			"--reviewer", fmt.Sprintf("%s/release-team", utils.TigeraOrg),
			"--label", "merge-when-ready,delete-branch,release-note-not-required,docs-not-required",
		}...)
	}
	logrus.WithField("args", strings.Join(args, " ")).Debug("Creating PR for release preparation")
	if m.dryRun {
		logrus.WithField("cmd", fmt.Sprintf("bin/gh %s", strings.Join(args, " "))).Info("Dry-run: create PR for release preparation")
	} else {
		pr, err := m.runner.RunInDir(m.repoRoot, "bin/gh", args, nil)
		if err != nil {
			if strings.Contains(err.Error(), "already exists") {
				logrus.Warnf("PR already exists, skipping creation. Find PR at: https://github.com/%s/%s/pulls?q=is%%3Aopen+head%%3A%s", m.githubOrg, m.repo, prepBranch)
				return nil
			}
			logrus.WithError(err).Error("Failed to create PR for release preparation")
			return fmt.Errorf("failed to create PR: %s", err)
		}
		logrus.WithField("PR", pr).Info("Created PR, please review and merge after release is published")
	}
	return nil
}

func (m *EnterpriseManager) s3Cp(src, dest string, additionalFlags ...string) error {
	args := []string{
		"--profile", m.awsProfile,
		"s3", "cp",
		src, dest,
	}
	if len(additionalFlags) > 0 {
		args = append(args, additionalFlags...)
	}
	if strings.HasSuffix(src, "/") {
		args = append(args, "--recursive")
	}
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		args = append(args, "--debug")
	}
	if m.dryRun {
		args = append(args, "--dryrun")
		logrus.WithField("cmd", fmt.Sprintf("aws %s", strings.Join(args, " "))).Info("Dry-run: upload to S3")
	}
	if _, err := m.runner.Run("aws", args, nil); err != nil {
		return err
	}
	return nil
}

func (m *EnterpriseManager) s3Sync(src, dest string, additionalFlags ...string) error {
	args := []string{
		"--profile", m.awsProfile,
		"s3", "sync",
		src, dest,
	}
	if len(additionalFlags) > 0 {
		args = append(args, additionalFlags...)
	}
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		args = append(args, "--debug")
	}
	if m.dryRun {
		args = append(args, "--dryrun")
		logrus.WithField("cmd", fmt.Sprintf("aws %s", strings.Join(args, " "))).Info("Dry-run: sync to S3")
	}
	if _, err := m.runner.Run("aws", args, nil); err != nil {
		return err
	}
	return nil
}

func (m *EnterpriseManager) gcsCp(src, dest string, additionalFlags ...string) error {
	args := []string{
		"storage", "cp",
		src, dest,
	}
	if strings.HasSuffix(src, "/") {
		args = append(args, "--recursive")
	}
	if len(additionalFlags) > 0 {
		args = append(args, additionalFlags...)
	}
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		args = append(args, "--verbosity=debug")
	}
	if m.dryRun {
		logrus.WithField("cmd", fmt.Sprintf("gcloud %s", strings.Join(args, " "))).Info("Dry-run: upload to GCS")
		return nil
	}
	if _, err := m.runner.Run("gcloud", args, nil); err != nil {
		return err
	}
	return nil
}

// SetupReleaseBranch sets up the repository for a new release branch by updating:
//   - Chart versions: Set the chart versions to match the new release stream for the release branch & Tigera operator
//   - metadata.mk: Update OPERATOR_BRANCH, and MANAGER_BRANCH variables
//   - CAPZ Windows FV test script: Update the RELEASE_STREAM variable to match the new release stream
//   - Code generation: Run code generation to ensure all generated code is up to date
//
// Finally, it commits the changes to the new release branch.
func (m *EnterpriseManager) SetupReleaseBranch(branch string) error {
	if err := m.releaseBranchPrereqs(branch); err != nil {
		return err
	}

	// Set calico version and operator version to their respective branches for pre-release branch.
	m.calicoVersion = branch
	m.operatorVersion = m.operatorBranch

	// Modify values in charts
	if err := m.modifyHelmChartsValues(); err != nil {
		return err
	}

	// Modify values in metadata.mk
	makeMetadataFilePath := filepath.Join(m.repoRoot, "metadata.mk")
	for key, replacement := range map[string]string{
		"OPERATOR_BRANCH": m.operatorBranch,
		"MANAGER_BRANCH":  branch,
	} {
		logrus.WithField(key, replacement).Debug("Updating variable in metadata.mk")
		if out, err := m.runner.Run("sed", []string{"-i", fmt.Sprintf(`s/^%s.*/%s ?= %s/g`, key, key, replacement), makeMetadataFilePath}, nil); err != nil {
			logrus.Error(out)
			return fmt.Errorf("failed to update %s in %s: %w", key, makeMetadataFilePath, err)
		}
	}

	// Update release stream used for ASO export-env script.
	releaseStream := strings.TrimPrefix(branch, m.releaseBranchPrefix+"-")
	logrus.WithField("releaseStream", releaseStream).Debug("Updating release stream in export-env script for ASO tests")
	envScriptFilePath := filepath.Join(m.repoRoot, "process", "testing", "aso", "export-env.sh")
	if out, err := m.runner.Run("sed", []string{"-i", fmt.Sprintf(`s/RELEASE_STREAM="master"/RELEASE_STREAM="%s"/`, releaseStream), envScriptFilePath}, nil); err != nil {
		logrus.Error(out)
		return fmt.Errorf("failed to update release stream in %s: %w", envScriptFilePath, err)
	}

	// Update release stream used for ASO install-calico script.
	logrus.WithField("releaseStream", releaseStream).Debug("Updating release stream in install-calico script for ASO tests")
	installScriptFilePath := filepath.Join(m.repoRoot, "process", "testing", "aso", "install-calico.sh")
	if out, err := m.runner.Run("sed", []string{"-i", fmt.Sprintf(`s/RELEASE_STREAM:="master"/RELEASE_STREAM:="%s"/`, releaseStream), installScriptFilePath}, nil); err != nil {
		logrus.Error(out)
		return fmt.Errorf("failed to update release stream in %s: %w", installScriptFilePath, err)
	}

	// Run code generation.
	logrus.Debug("Running code generation")
	env := append(os.Environ(), fmt.Sprintf("DEFAULT_BRANCH_OVERRIDE=%s", branch))
	if err := m.makeInDirectoryIgnoreOutput(m.repoRoot, "generate", env...); err != nil {
		return fmt.Errorf("failed to run code generation: %w", err)
	}

	// Commit the changes.
	if out, err := m.git("add",
		filepath.Join(m.repoRoot, ".semaphore"),
		filepath.Join(m.repoRoot, "charts"),
		filepath.Join(m.repoRoot, "manifests"),
		filepath.Join(m.repoRoot, "metadata.mk"),
		filepath.Join(m.repoRoot, "process", "testing"),
		filepath.Join(m.repoRoot, "test-tools", "mocknode"),
	); err != nil {
		logrus.Error(out)
		return fmt.Errorf("failed to add files to git: %s", err)
	}
	if out, err := m.git("commit", "-m", fmt.Sprintf("Updates for %s release branch", branch)); err != nil {
		logrus.Error(out)
		return fmt.Errorf("failed to commit changes: %s", err)
	}

	return nil
}

// UpdateMainBranch updates the main branch after a release branch has been cut by:
//   - Updating the CALICO_VERSION in Makefile to the next development version if necessary
//
// Finally, it adds the changes to git for committing by BranchManager.
func (m *EnterpriseManager) UpdateMainBranch(releaseBranchStream string) error {
	makeMetadataFilePath := filepath.Join(m.repoRoot, "metadata.mk")
	// if the new cut release branch is EP1, we need to update the CALICO_VERSION in Makefile
	// to the next development version of Calico OSS for future EP2/GA branch cut.
	if !strings.HasSuffix(releaseBranchStream, "-1") {
		logrus.Infof("No need to update CALICO_VERSION in %s for release branch %s-%s", makeMetadataFilePath, m.releaseBranchPrefix, releaseBranchStream)
		return nil
	}
	// get current CALICO_VERSION from Makefile
	out, err := m.runner.Run("grep", []string{"-oP", `^CALICO_VERSION=\K(.*)`, makeMetadataFilePath}, nil)
	if err != nil {
		logrus.Error(out)
		return fmt.Errorf("failed to get current CALICO_VERSION from Makefile: %w", err)
	}
	ossVersion := version.New(out)
	nextVersion := ossVersion.NextBranchVersion()
	if _, err := m.runner.Run("sed", []string{"-i", fmt.Sprintf(`s/^CALICO_VERSION=.*/CALICO_VERSION=%s/g`, nextVersion.FormattedString()), makeMetadataFilePath}, nil); err != nil {
		logrus.Error(out)
		return fmt.Errorf("failed to update CALICO_VERSION in %s: %w", makeMetadataFilePath, err)
	}
	// add changes to git for BranchManager to commit
	if out, err := m.git("add", makeMetadataFilePath); err != nil {
		logrus.Error(out)
		return fmt.Errorf("failed to add %s to git: %s", makeMetadataFilePath, err)
	}
	return nil
}
