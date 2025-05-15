package calico

import (
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/pinnedversion"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
	"github.com/projectcalico/calico/release/pkg/manager/branch"
	"github.com/projectcalico/calico/release/pkg/manager/manager"
)

var (
	defaultEnterpriseRegistry = registry.QuayRegistry + "/tigera"

	windowsGCSBucket = "tigera-windows"

	docsURL = "https://docs.tigera.io"

	s3Bucket = "s3://tigera-public/ee"

	// images produced in this repo that should be expected for a release.
	// This list needs to be kept up-to-date
	// as images are added or removed.
	enterpriseImages = []string{
		"voltron",
		"guardian",
		"cnx-apiserver",
		"cnx-queryserver",
		"kube-controllers",
		"calicoq",
		"typha",
		"calicoctl",
		"cnx-node",
		"dikastes",
		"dex",
		"fluentd",
		"ui-apis",
		"kibana",
		"elasticsearch",
		"intrusion-detection-job-installer",
		"intrusion-detection-controller",
		"webhooks-processor",
		"compliance-controller",
		"compliance-reporter",
		"compliance-snapshotter",
		"compliance-server",
		"compliance-benchmarker",
		"ingress-collector",
		"l7-collector",
		"l7-admission-controller",
		"license-agent",
		"cni",
		"firewall-integration",
		"egress-gateway",
		"linseed",
		"policy-recommendation",
		"elasticsearch-metrics",
		"packetcapture",
		"prometheus",
		"prometheus-operator",
		"prometheus-config-reloader",
		"prometheus-service",
		"es-gateway",
		"deep-packet-inspection",
		"eck-operator",
		"alertmanager",
		"envoy",
		"envoy-init",
		"pod2daemon-flexvol",
		"csi",
		"node-driver-registrar",
		"key-cert-provisioner",
	}
	enterpriseWindowsImages = []string{
		"fluentd-windows",
		"cni-windows",
		"cnx-node-windows",
	}

	enterpriseImageReleaseDirs = []string{
		"apiserver",
		"app-policy",
		"calicoctl",
		"cni-plugin",
		"kube-controllers",
		"node",
		"typha",
		"calicoq",
		"compliance",
		"deep-packet-inspection",
		"egress-gateway",
		"elasticsearch-metrics",
		"elasticsearch",
		"es-gateway",
		"ui-apis",
		"firewall-integration",
		"fluentd",
		"ingress-collector",
		"intrusion-detection-controller",
		"key-cert-provisioner",
		"kibana",
		"l7-admission-controller",
		"l7-collector",
		"license-agent",
		"linseed",
		"packetcapture",
		"pod2daemon",
		"policy-recommendation",
		"prometheus-service",
		"queryserver",
		"voltron",
		"webhooks-processor",
		"third_party/alertmanager",
		"third_party/dex",
		"third_party/eck-operator",
		"third_party/envoy-gateway",
		"third_party/envoy-proxy",
		"third_party/envoy-ratelimit",
		"third_party/prometheus-operator",
		"third_party/prometheus",
	}
	enterpriseWindowsReleaseDirs = []string{
		"cni-plugin",
		"fluentd",
		"node",
	}

	enterpriseBinaryReleaseDirs = []string{
		"calicoctl",
		"calicoq",
	}

	//go:embed templates/yum.conf.gotmpl
	rpmRepoTemplate string
	rhelVersions    = []string{"8", "9"}
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
		WithPublishGitTag(false),
		WithPublishGithubRelease(false),
	}
	calicoOpts = append(defaultCalicoOpts, calicoOpts...)
	calicoManager := NewManager(calicoOpts...)
	calicoManager.productCode = utils.EnterpriseProductCode

	m := &EnterpriseManager{
		CalicoManager:         *calicoManager,
		publishWindowsArchive: true,
		publishCharts:         true,
		helmRegistry:          registry.HelmDevRegistry, // Defaults to dev registry as currently only used for hashreleases.
	}

	for _, o := range opts {
		if err := o(m); err != nil {
			logrus.WithError(err).Fatal("Failed to apply option to enterprise manager")
		}
	}

	if !m.isHashRelease && m.chartVersion == "" {
		logrus.Fatal("No chart version specified")
	}
	if m.chartVersion != "" {
		logrus.WithField("chartVersion", m.chartVersion).Info("Using chart version")
	}

	return m
}

type EnterpriseManager struct {
	CalicoManager

	devTagSuffix string

	// chartVersion is the version of the helm chart to build.
	chartVersion string

	enterpriseHashrelease hashreleaseserver.EnterpriseHashrelease

	// publishing options
	dryRun                bool
	publishWindowsArchive bool
	publishCharts         bool
	publishToS3           bool
	publishGitChanges     bool

	rpm bool

	helmRegistry string

	awsProfile string
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
	manifestRegistry, err := m.getOperatorRegistryFromManifests()
	if err != nil {
		return err
	}
	operatorValuesYAML := filepath.Join(m.repoRoot, "charts", "tigera-operator", "values.yaml")
	if _, err := m.runner.Run("sed", []string{"-i", fmt.Sprintf(`s~%s~%s~g`, manifestRegistry, m.operatorRegistry), operatorValuesYAML}, nil); err != nil {
		logrus.WithField("file", operatorValuesYAML).WithError(err).Error("failed to update registry in values file")
		return err
	}
	var registry string
	if len(m.imageRegistries) > 0 {
		registry = m.imageRegistries[0]
	}
	manifestRegistry, err = m.getRegistryFromManifests()
	if err != nil {
		return err
	}
	manifestRegistry = strings.TrimSuffix(manifestRegistry, "/tigera")
	if _, err := m.runner.Run("sed", []string{"-i", fmt.Sprintf(`s~%s~%s~g`, manifestRegistry, registry), prometheusValuesYAML}, nil); err != nil {
		logrus.WithField("file", prometheusValuesYAML).WithError(err).Error("failed to update registry in values file")
		return err
	}
	return nil
}

func (m *EnterpriseManager) BuildHelm() error {
	if m.isHashRelease {
		// Reset the changes to the charts directory.
		defer m.resetCharts()

		if err := m.modifyHelmChartsValues(); err != nil {
			return err
		}
	}

	// Build the helm chart, passing the version to use.
	env := append(os.Environ(), fmt.Sprintf("GIT_VERSION=%s", m.calicoVersion))
	if m.chartVersion != "" {
		env = append(env, fmt.Sprintf("CHART_RELEASE=%s", m.chartVersion))
	}
	if err := m.makeInDirectoryIgnoreOutput(m.repoRoot, "chart", env...); err != nil {
		return err
	}

	return nil
}

func (m *EnterpriseManager) PreReleaseValidate(ver string) error {
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

	// Check that code generation is up-to-date.
	if err := m.makeInDirectoryIgnoreOutput(m.repoRoot, "generate get-operator-crds check-dirty"); err != nil {
		return fmt.Errorf("code generation error (try 'make generate' and/or 'make get-operator-crds' ?): %s", err)
	}
	if m.rpm {
		createrepo := "createrepo_c"
		if path, err := exec.LookPath(createrepo); err != nil {
			logrus.WithError(err).Errorf("Error trying to find %s in PATH", createrepo)
			return fmt.Errorf("Unable to find %s in PATH", createrepo)
		} else if path == "" {
			logrus.Errorf("%s not found in PATH", createrepo)
			return fmt.Errorf("%s not found in PATH", createrepo)
		}
	}

	return m.prepPrereqs()
}

func (m *EnterpriseManager) generateManifests() error {
	// Manifests are expecting registry to be the Contaier registry platform.
	reg := strings.TrimSuffix(m.imageRegistries[0], "/tigera")
	env := os.Environ()
	env = append(env, fmt.Sprintf("CALICO_VERSION=%s", m.calicoVersion))
	env = append(env, fmt.Sprintf("OPERATOR_VERSION=%s", m.operatorVersion))
	env = append(env, fmt.Sprintf("REGISTRY_OPERATOR=%s", m.operatorRegistry))
	env = append(env, fmt.Sprintf("REGISTRY=%s", reg))
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
	ver := m.calicoVersion

	// Make sure output directory exists.
	if err := os.MkdirAll(m.uploadDir(), utils.DirPerms); err != nil {
		return fmt.Errorf("failed to create output dir: %s", err)
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

	// Build the Windows archive.
	env := append(os.Environ(), fmt.Sprintf("VERSION=%s", ver))
	if err := m.makeInDirectoryIgnoreOutput(filepath.Join(m.repoRoot, "node"), "release-windows-archive", env...); err != nil {
		return fmt.Errorf("failed to build windows archive: %s", err)
	}

	if err := m.buildArchive(); err != nil {
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
		} else if strings.Contains(i, "tigera/") {
			splits := strings.SplitAfter(i, "/tigera/")
			registry := strings.TrimSuffix(splits[0], "/")
			logrus.WithField("registry", registry).Debugf("Using registry from image %s", i)
			return registry, nil
		}
	}
	return "", fmt.Errorf("failed to find registry from manifests")
}

func (m *EnterpriseManager) getOperatorRegistryFromManifests() (string, error) {
	args := []string{"-Po", `image:\K(.*)`, "tigera-operator.yaml"}
	out, err := m.runner.RunInDir(filepath.Join(m.repoRoot, "manifests"), "grep", args, nil)
	if err != nil {
		return "", err
	}
	imgs := strings.Split(out, "\n")
	for _, i := range imgs {
		if strings.Contains(i, "operator") {
			splits := strings.SplitAfter(i, "/tigera/")
			registry := strings.TrimSuffix(splits[0], "/tigera/")
			logrus.WithField("registry", registry).Debugf("Using operator registry from image %s", i)
			return registry, nil
		}
	}
	return "", fmt.Errorf("failed to find registry from manifests")
}

func (m *EnterpriseManager) BuildMetadata(dir string) error {
	if err := os.MkdirAll(dir, utils.DirPerms); err != nil {
		logrus.WithError(err).Errorf("Failed to create metadata folder %s", dir)
		return err
	}
	registry, err := m.getRegistryFromManifests()
	if err != nil {
		return err
	}

	calicoVer, err := utils.DetermineCalicoVersion(m.repoRoot)
	if err != nil {
		return err
	}

	// For releases, all images (including the manager, except operator) are the same version.
	// For hash releases, the manager image is a different version.
	var images []string
	if m.isHashRelease {
		images = releaseImages(append(enterpriseImages, enterpriseWindowsImages...), m.calicoVersion, registry, m.operatorImage, m.operatorVersion, m.operatorRegistry)
		images = append(images, fmt.Sprintf("%s/%s:%s", registry, manager.DefaultImage, m.enterpriseHashrelease.ManagerVersion))
	} else {
		images = releaseImages(append(append(enterpriseImages, manager.DefaultImage), enterpriseWindowsImages...), m.calicoVersion, registry, m.operatorImage, m.operatorVersion, m.operatorRegistry)
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

func (m *EnterpriseManager) buildArchive() error {
	// Build the release archive.
	env := os.Environ()
	if m.isHashRelease {
		env = append(env, fmt.Sprintf("VERSIONS_FILE=%s", pinnedversion.PinnedVersionFilePath(m.tmpDir)))
	}
	if err := m.makeInDirectoryIgnoreOutput(m.repoRoot, "release-archive", env...); err != nil {
		return err
	}
	return nil
}

type rpmRepoData struct {
	ReleaseURL string
	Version    string
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
	defer file.Close()
	for _, rpmFileName := range rpmFiles {
		if _, err := file.WriteString(fmt.Sprintf("%s\n", rpmFileName)); err != nil {
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
	outDir := filepath.Join(m.uploadDir(), "non-cluster-host-rpms")
	if err := os.MkdirAll(outDir, utils.DirPerms); err != nil {
		return err
	}

	rsyncOpts := []string{"--recursive", "--prune-empty-dirs", "--exclude=BUILD", "--exclude=SRPMS", "--exclude=*debuginfo*", "--exclude=*debugsource*"}
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		rsyncOpts = append(rsyncOpts, "--verbose", "--progress")
	}
	for _, dir := range rpmDirs {
		logrus.WithField("package", dir).Debug("Building RPM package")
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
			logrus.WithError(err).Errorf("Failed copy %s RPM to %s", dir, destDir)
			return err
		}
	}

	createrepo := "createrepo_c"

	for _, version := range rhelVersions {
		rhelDir := filepath.Join(outDir, fmt.Sprintf("rhel%s", version))
		pkgListPath := filepath.Join(m.tmpDir, fmt.Sprintf("%s-rhel%s-pkglist.txt", m.calicoVersion, version))
		rpmURL := fmt.Sprintf("%s/non-cluster-host-rpms/rhel%s", m.hashrelease.URL(), version)
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
			"--xz", ".",
		}
		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			args = append(args, "--verbose")
		}
		if _, err := m.runner.RunInDir(rhelDir, createrepo, args, nil); err != nil {
			logrus.WithError(err).Errorf("Failed to create repo for RHEL %s", version)
			return fmt.Errorf("failed to create repo for RHEL %s: %s", version, err)
		}
		logrus.WithField("RHELVersion", version).Debug("Writing yum repo config file")
		tmpl, err := template.New("yum.conf").Parse(rpmRepoTemplate)
		if err != nil {
			return fmt.Errorf("failed to parse yum repo template: %s", err)
		}
		f, err := os.Create(filepath.Join(outDir, fmt.Sprintf("calico_rhel%s.repo", version)))
		if err != nil {
			return fmt.Errorf("failed to create yum repo config file: %s", err)
		}
		defer f.Close()
		data := &rpmRepoData{
			ReleaseURL: rpmURL,
			Version:    version,
		}
		if err := tmpl.Execute(f, data); err != nil {
			logrus.WithField("version", version).WithError(err).Error("Failed to write yum repo config file")
			return fmt.Errorf("failed to write yum repo config file: %s", err)
		}
		logrus.WithField("RHELVersion", version).Debug("Wrote yum repo config file")
	}
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
		return err
	}

	if err := os.MkdirAll(m.scriptsDir(), utils.DirPerms); err != nil {
		return err
	}

	// Add the Windows install script
	if _, err := m.runner.RunInDir(m.repoRoot, "cp", []string{"node/windows-packaging/install-calico-windows.ps1", m.scriptsDir()}, nil); err != nil {
		return err
	}
	// Move the Windows archive to temp dir
	if _, err := m.runner.RunInDir(m.repoRoot, "cp", []string{fmt.Sprintf("node/dist/tigera-calico-windows-%s.zip", m.calicoVersion), m.tmpDir}, nil); err != nil {
		return err
	}

	// Add helm charts
	charts, err := listCharts(filepath.Join(m.repoRoot, "bin"), m.helmChartVersion())
	if err != nil {
		logrus.WithError(err).Error("Failed to get list of charts")
	}
	chartsDir := filepath.Join(uploadDir, "charts")
	if err := os.MkdirAll(chartsDir, utils.DirPerms); err != nil {
		return fmt.Errorf("failed to create charts directory: %s", err)
	}
	for _, chart := range charts {
		logrus.WithField("chart", chart).Debug("Copying chart")
		if _, err := m.runner.Run("cp", []string{chart, chartsDir}, nil); err != nil {
			return err
		}
		if strings.HasSuffix(chart, fmt.Sprintf("tigera-operator-%s.tgz", m.helmChartVersion())) {
			if _, err := m.runner.Run("cp", []string{chart, uploadDir}, nil); err != nil {
				return err
			}
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
	defer switchActiveOperatorFile.Close()
	resp, err := http.Get(fmt.Sprintf("%s/%s/next/scripts/%s", docsURL, strings.ReplaceAll(utils.CalicoEnterprise, " ", "-"), switchActiveOperatorFilename))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
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

	if err := m.publishWindowsArchiveToGCS(); err != nil {
		return err
	}
	if err := m.publishHelmCharts(); err != nil {
		return err
	}
	if m.isHashRelease {
		return m.publishToHashreleaseServer()
	}

	if err := m.publishReleaseArtifacts(); err != nil {
		return err
	}

	if !m.isHashRelease {
		// Create the next development tag.
		ver := version.Version(m.calicoVersion)
		branchManager := branch.NewManager(branch.WithRepoRoot(m.repoRoot),
			branch.WithRepoRemote(m.remote),
			branch.WithMainBranch(fmt.Sprintf("%s-%s", m.releaseBranchPrefix, ver.Stream())),
			branch.WithDevTagIdentifier(m.devTagSuffix),
			branch.WithValidate(m.validate),
			branch.WithPublish(m.publishTag && !m.dryRun))

		return branchManager.CreateNextDevelopmentTag()
	}
	return nil
}

func (m *EnterpriseManager) publishReleaseImages() error {
	if !m.publishImages {
		logrus.Info("Skipping publishing images")
		return nil
	}

	env := append(os.Environ(),
		"IMAGE_ONLY=true",
		fmt.Sprintf("DEV_TAG=%s", m.enterpriseHashrelease.ProductVersion),
		fmt.Sprintf("DEV_REGISTRIES=%s", registry.TigeraDevCIGCRRegistry),
		fmt.Sprintf("RELEASE_TAG=%s", m.calicoVersion),
	)
	if m.dryRun {
		env = append(env, "DRYRUN=true")
	} else {
		env = append(env, "CONFIRM=true")
	}
	// We allow for a certain number of retries when publishing each directory, since
	// network flakes can occasionally result in images failing to push.
	maxRetries := 1
	for _, dir := range enterpriseImageReleaseDirs {
		attempt := 0
		for {
			out, err := m.makeInDirectoryWithOutput(filepath.Join(m.repoRoot, dir), "cut-release-image", env...)
			if err != nil {
				if attempt < maxRetries {
					logrus.WithField("attempt", attempt).WithError(err).Warn("Publish failed, retrying")
					attempt++
					continue
				}
				logrus.Error(out)
				return fmt.Errorf("Failed to publish %s: %s", dir, err)
			}

			// Success - move on to the next directory.
			logrus.Info(out)
			break
		}
	}
	for _, dir := range enterpriseWindowsReleaseDirs {
		attempt := 0
		for {
			out, err := m.makeInDirectoryWithOutput(filepath.Join(m.repoRoot, dir), "cut-release-image", append(env, "WINDOWS_RELEASE=true")...)
			if err != nil {
				if attempt < maxRetries {
					logrus.WithField("attempt", attempt).WithError(err).Warn("Publish failed, retrying")
					attempt++
					continue
				}
				logrus.Error(out)
				return fmt.Errorf("Failed to publish %s: %s", dir, err)
			}

			// Success - move on to the next directory.
			logrus.Info(out)
			break
		}
	}
	env = append(os.Environ(),
		fmt.Sprintf("VERSION=%s", m.calicoVersion),
	)
	if m.dryRun {
		env = append(env, "DRYRUN=true")
	} else {
		env = append(env, "CONFIRM=true")
	}
	for _, dir := range enterpriseBinaryReleaseDirs {
		attempt := 0
		for {
			out, err := m.makeInDirectoryWithOutput(filepath.Join(m.repoRoot, dir), "release-publish-binaries", env...)
			if err != nil {
				if attempt < maxRetries {
					logrus.WithField("attempt", attempt).WithError(err).Warn("Publish failed, retrying")
					attempt++
					continue
				}
				logrus.Error(out)
				return fmt.Errorf("Failed to publish %s: %s", dir, err)
			}

			// Success - move on to the next directory.
			logrus.Info(out)
			break
		}
	}
	return nil
}

func (m *EnterpriseManager) publishReleaseArtifacts() error {
	if !m.publishToS3 {
		logrus.Info("Skipping publishing manifests, release archive and RPMs to S3")
		return nil
	}
	if err := m.uploadToS3(filepath.Join(m.uploadDir(), "manifests")+"/", fmt.Sprintf("%s/%s/manifests/", s3Bucket, m.calicoVersion)); err != nil {
		return fmt.Errorf("failed to publish manifests: %s", err)
	}
	if err := m.uploadToS3(filepath.Join(m.uploadDir(), fmt.Sprintf("release-%s-%s.tgz", m.calicoVersion, m.operatorVersion)), fmt.Sprintf("%s/archives/", s3Bucket)); err != nil {
		return fmt.Errorf("failed to publish release archive: %s", err)
	}
	for _, rhelVer := range rhelVersions {
		if err := m.uploadToS3(filepath.Join(m.uploadDir(), "non-cluster-host-rpms", fmt.Sprintf("rhel%s", rhelVer)), fmt.Sprintf("%s/rpms/%s/rhel%s", s3Bucket, m.calicoVersion, rhelVer)); err != nil {
			return fmt.Errorf("failed to publish RHEL %s repo: %s", rhelVer, err)
		}
	}
	return nil
}

func (m *EnterpriseManager) publishWindowsArchiveToGCS() error {
	if !m.publishWindowsArchive {
		logrus.Info("Skipping publishing windows archive")
		return nil
	}

	bucket := windowsGCSBucket
	publishSuffix := m.calicoVersion
	if m.isHashRelease {
		bucket += "/dev"
		publishSuffix = m.enterpriseHashrelease.Name
	}

	cmd := "gsutil"
	args := []string{
		"cp",
		fmt.Sprintf("tigera-calico-windows-%s.zip", m.calicoVersion),
		fmt.Sprintf("gs://%s/tigera-calico-windows-%s.zip", bucket, publishSuffix),
	}
	if m.dryRun {
		logrus.WithField("cmd", fmt.Sprintf("%s %s", cmd, strings.Join(args, " "))).Info("Dry-run: would publish windows archive")
		return nil
	}
	if _, err := m.runner.RunInDir(m.tmpDir, cmd, args, nil); err != nil {
		return err
	}
	return nil
}

func (m *EnterpriseManager) publishHelmCharts() error {
	if !m.publishCharts {
		logrus.Info("Skipping publishing helm charts")
		return nil
	}
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
			if err := m.uploadToS3(chart, fmt.Sprintf("%s/charts/", s3Bucket)); err != nil {
				return fmt.Errorf("failed to push chart %s: %s", chart, err)
			}
		}
	}
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
	branch := m.determineBranch()
	if branch == "master" {
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

	ver := version.New(m.calicoVersion)
	releaseBranch := fmt.Sprintf("%s-%s", m.releaseBranchPrefix, ver.Stream())
	defer func() {
		if _, err := m.git("switch", "-f", releaseBranch); err != nil {
			logrus.WithError(err).Errorf("Failed to reset to %q branch", releaseBranch)
		}
	}()

	// Checkout the repo at the git hash
	if err := utils.CheckoutHashreleaseVersion(m.enterpriseHashrelease.ProductVersion, m.repoRoot); err != nil {
		return err
	}

	// Modify calico/_data/versions.yml, helm charts and generate manifests.
	if err := m.modifyVersionsFile(); err != nil {
		return err
	}
	if err := m.generateManifests(); err != nil {
		return fmt.Errorf("failed to generate manifests: %s", err)
	}

	// Create a new branch for the release and commit the changes.
	prepBranch := fmt.Sprintf("prep-%s", m.calicoVersion)
	if _, err := m.git("checkout", "-b", prepBranch); err != nil {
		return fmt.Errorf("failed to create branch %s: %s", prepBranch, err)
	}
	if _, err := m.git("add", filepath.Join(m.repoRoot, "calico"), filepath.Join(m.repoRoot, "charts"), filepath.Join(m.repoRoot, "manifests")); err != nil {
		return fmt.Errorf("failed to add files to git: %s", err)
	}
	if _, err := m.git("commit", "-m", fmt.Sprintf("Updates for %s release", m.calicoVersion)); err != nil {
		return fmt.Errorf("failed to commit changes: %s", err)
	}
	if m.dryRun {
		logrus.WithField("branch", prepBranch).Info("Dry-run: skipping push of branch")
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
		"--repo", fmt.Sprintf("%s/%s", utils.TigeraOrg, utils.CalicoPrivateRepo),
		"--base", releaseBranch,
		"--head", fmt.Sprintf("%s:%s", owner, prepBranch),
		"--reviewer", fmt.Sprintf("%s/release-team", utils.TigeraOrg),
		"--label", "merge-when-ready,delete-branch,release-note-not-required,docs-not-required",
	}
	logrus.WithField("args", strings.Join(args, " ")).Debug("Creating PR for release preparation")
	if m.dryRun {
		logrus.WithField("cmd", fmt.Sprintf("gh %s", strings.Join(args, " "))).Info("Dry-run: create PR for release preparation")
	} else {
		pr, err := m.runner.RunInDir(m.repoRoot, "bin/gh", args, nil)
		if err != nil {
			return fmt.Errorf("failed to create PR: %s", err)
		}
		logrus.WithField("PR", pr).Info("Created PR, please review and merge after release is published")
	}
	return nil
}

func (m *EnterpriseManager) modifyVersionsFile() error {
	versionData := version.NewEnterpriseReleaseVersionData(version.New(m.calicoVersion), m.chartVersion, m.operatorVersion)
	err := pinnedversion.UpdateVersionsFile(m.repoRoot, versionData)
	if err != nil {
		return fmt.Errorf("failed to update versions file: %s", err)
	}
	return nil
}

func (m *EnterpriseManager) uploadToS3(src, dest string) error {
	args := []string{
		"--profile", m.awsProfile,
		"s3", "cp",
		src, dest,
		"--acl", "public-read",
	}
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if info.IsDir() {
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
