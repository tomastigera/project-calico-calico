package pinnedversion

import (
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"go.yaml.in/yaml/v3"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
	"github.com/projectcalico/calico/release/pkg/manager/manager"
)

const (
	managerComponentName       = manager.ComponentName
	managerProxyComponentName  = managerComponentName + "-proxy"
	calicoPrivateComponentName = "calico-private"

	// coreos components
	coreosAlertmanagerComponentName       = "coreos-alertmanager"
	coreosConfigReloaderComponentName     = "coreos-config-reloader"
	coreosPrometheusComponentName         = "coreos-prometheus"
	coreosPrometheusOperatorComponentName = "coreos-prometheus-operator"
	coreosDexComponentName                = "coreos-dex"

	// eck components
	eckElasticsearchComponentName         = "eck-elasticsearch"
	eckElasticsearchOperatorComponentName = "eck-elasticsearch-operator"
	eckKibanaComponentName                = "eck-kibana"

	// upstream components
	upstreamFluentdComponentName = "upstream-fluentd"
)

var onceEnterprise sync.Once

var thirdPartyEnterpriseComponents = map[string]registry.Component{
	coreosAlertmanagerComponentName:       {Version: "v0.31.1"},
	coreosConfigReloaderComponentName:     {Version: "v0.89.0"},
	coreosDexComponentName:                {Version: "v2.45.0"},
	coreosPrometheusComponentName:         {Version: "v3.9.1"},
	coreosPrometheusOperatorComponentName: {Version: "v0.89.0"},
	eckElasticsearchComponentName:         {Version: "8.19.10"},
	eckElasticsearchOperatorComponentName: {Version: "2.16.0"},
	eckKibanaComponentName:                {Version: "8.19.10"},
	upstreamFluentdComponentName:          {Version: "1.19.2"},
}

var (
	// Components to be included for operator pinned_components.yaml
	// even if they do not produce images.
	operatorIncludedComponents = []string{
		eckElasticsearchComponentName,
		eckElasticsearchOperatorComponentName,
		eckKibanaComponentName,
		coreosAlertmanagerComponentName,
		coreosPrometheusComponentName,
	}
	// Components that do not produce images.
	noEnterpriseImageComponents = []string{
		calicoPrivateComponentName,
		managerProxyComponentName,
		coreosAlertmanagerComponentName,
		coreosConfigReloaderComponentName,
		coreosDexComponentName,
		coreosPrometheusComponentName,
		coreosPrometheusOperatorComponentName,
		eckElasticsearchComponentName,
		eckElasticsearchOperatorComponentName,
		eckKibanaComponentName,
		upstreamFluentdComponentName,
	}
)

var (
	// enterpriseComponentImageMap maps the component name to its image for enterprise.
	enterpriseComponentImageMap = map[string]string{
		"csi-node-driver-registrar":   "node-driver-registrar",
		"elastic-tsee-installer":      "intrusion-detection-job-installer",
		"elasticsearch-operator":      "eck-operator",
		"flexvol":                     "pod2daemon-flexvol",
		"tigera-cni":                  "cni",
		"tigera-cni-windows":          "cni-windows",
		"tigera-prometheus-service":   "prometheus-service",
		"gateway-api-envoy-gateway":   "envoy-gateway",
		"gateway-api-envoy-proxy":     "envoy-proxy",
		"gateway-api-envoy-ratelimit": "envoy-ratelimit",
	}
	// enterpriseImageComponentMap maps the image name to its component for enterprise.
	// It is initialized lazily and should be accessed via mapEnterpriseImageToComponent.
	enterpriseImageComponentMap = map[string]string{}
)

type ManagerConfig struct {
	Dir    string
	Branch string
}

func (m ManagerConfig) GitVersion() (string, error) {
	return command.GitVersion(m.Dir, true)
}

type CalicoComponent struct {
	MinorVersion string `yaml:"minor_version"`
	ArchivePath  string `yaml:"archive_path"`
}

type EnterprisePinnedVersion struct {
	PinnedVersion `yaml:",inline"`
	HelmRelease   string          `yaml:"helmRelease,omitempty"`
	Calico        CalicoComponent `yaml:"calico"`
}

// GetComponentImageNames returns a list of Enterprise images that are part of the pinned version.
// It excludes components that do not produce images or are not built by Tigera
// and Tigera operator itself unless includeOperator is true.
func (p *EnterprisePinnedVersion) GetComponentImageNames(includeOperator bool) []string {
	componentNames := make([]string, 0)
	for _, component := range p.ImageComponents(includeOperator) {
		componentNames = append(componentNames, component.Image)
	}
	return componentNames
}

// ImageComponents returns a map of all components that produce images
// including Tigera operator and its init image if includeOperator is true.
func (p *EnterprisePinnedVersion) ImageComponents(includeOperator bool) map[string]registry.Component {
	components := make(map[string]registry.Component)
	for name, component := range p.Components {
		// Remove components that should be excluded. Either because they do not have an image, or not built by Calico.
		if slices.Contains(noEnterpriseImageComponents, name) {
			continue
		}
		if img, found := enterpriseComponentImageMap[name]; found {
			component.Image = img
		} else if component.Image == "" {
			component.Image = name
		}
		components[name] = component
	}
	if includeOperator {
		maps.Copy(components, p.operatorComponents())
	}
	return components
}

type EnteprisePinnedVersions struct {
	CalicoPinnedVersions
	ManagerCfg   ManagerConfig
	ChartVersion string

	releaseName   string
	productBranch string
	calicoStream  string
	versionData   *version.EnterpriseVersions
}

func (p *EnteprisePinnedVersions) GenerateFile() (*version.EnterpriseVersions, error) {
	pinnedVersionPath := PinnedVersionFilePath(p.Dir)

	productBranch, err := utils.GitBranch(p.RootDir)
	if err != nil {
		return nil, err
	}
	p.productBranch = productBranch
	productVer, err := command.GitVersion(p.RootDir, true)
	if err != nil {
		logrus.WithError(err).Error("Failed to determine product git version")
		return nil, err
	}
	releaseName := fmt.Sprintf("%s-%s-%s", time.Now().Format("2006-01-02"), version.DeterminePublishStream(productBranch, productVer), RandomWord())
	p.releaseName = strings.ReplaceAll(releaseName, ".", "-")
	operatorVer, err := p.OperatorCfg.GitVersion()
	if err != nil {
		return nil, err
	}
	managerVer, err := p.ManagerCfg.GitVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to determine manager git version: %w", err)
	}
	calicoVer, err := utils.DetermineCalicoVersion(p.RootDir)
	if err != nil {
		return nil, fmt.Errorf("failed to determine calico version: %w", err)
	}
	parts := strings.Split(calicoVer, ".")
	p.calicoStream = fmt.Sprintf("%s.%s", parts[0], parts[1])

	p.versionData = version.NewEnterpriseHashreleaseVersions(version.New(productVer), p.ChartVersion, operatorVer, managerVer)
	if err := generateEnterprisePinnedVersionFile(p); err != nil {
		return nil, err
	}

	if p.BaseHashreleaseDir != "" {
		hashreleaseDir := filepath.Join(p.BaseHashreleaseDir, p.versionData.Hash())
		if err := os.MkdirAll(hashreleaseDir, utils.DirPerms); err != nil {
			return nil, err
		}
		if err := utils.CopyFile(pinnedVersionPath, filepath.Join(hashreleaseDir, pinnedVersionFileName)); err != nil {
			return nil, err
		}
	}

	return p.versionData, nil
}

func mapEnterpriseImageToComponent(imageName, version string) (string, registry.Component) {
	onceEnterprise.Do(func() {
		// Initialize the enterprise image to component map.
		for c, img := range enterpriseComponentImageMap {
			enterpriseImageComponentMap[img] = c
		}
	})
	if compName, found := enterpriseImageComponentMap[imageName]; found {
		return compName, registry.Component{
			Version: version,
			Image:   imageName,
		}
	}
	return imageName, registry.Component{Version: version}
}

func generateEnterprisePinnedVersionFile(p *EnteprisePinnedVersions) error {
	pinnedVersionPath := PinnedVersionFilePath(p.Dir)
	components := maps.Clone(thirdPartyEnterpriseComponents)
	components[calicoPrivateComponentName] = registry.Component{Version: p.versionData.ProductVersion()}
	note := fmt.Sprintf("%s - generated at %s using %s release branch with %s operator branch",
		p.releaseName, time.Now().Format(time.RFC1123), p.productBranch, p.OperatorCfg.Branch)
	if p.ManagerCfg.Branch != "" {
		note = fmt.Sprintf("%s and %s manager branch", note, p.ManagerCfg.Branch)
	}
	// If the manager dir is set, no version information is available.
	components[managerComponentName] = registry.Component{Version: p.versionData.ManagerVersion()}
	components[managerProxyComponentName] = registry.Component{Version: p.versionData.ManagerVersion()}
	for _, img := range utils.EnterpriseReleaseImages() {
		name, c := mapEnterpriseImageToComponent(img, p.versionData.ProductVersion())
		components[name] = c
	}

	pinned := EnterprisePinnedVersion{
		PinnedVersion: PinnedVersion{
			Title:       p.versionData.ProductVersion(),
			ManifestURL: fmt.Sprintf("https://%s.%s", p.releaseName, hashreleaseserver.BaseDomain),
			ReleaseName: p.releaseName,
			Note:        note,
			Hash:        p.versionData.Hash(),
			TigeraOperator: registry.Component{
				Image:    p.OperatorCfg.Image,
				Registry: p.OperatorCfg.Registry,
				Version:  p.versionData.OperatorVersion(),
			},
			Components: components,
		},
		HelmRelease: p.ChartVersion,
		Calico: CalicoComponent{
			MinorVersion: p.calicoStream,
			ArchivePath:  "archive",
		},
	}

	logrus.WithField("file", pinnedVersionPath).Info("Creating pinned version file")
	pinnedVersionFile, err := os.Create(pinnedVersionPath)
	if err != nil {
		return fmt.Errorf("cannot create pinned version file: %w", err)
	}
	defer func() { _ = pinnedVersionFile.Close() }()
	enc := yaml.NewEncoder(pinnedVersionFile)
	enc.SetIndent(2)
	defer func() { _ = enc.Close() }()

	if err := enc.Encode([]EnterprisePinnedVersion{pinned}); err != nil {
		return fmt.Errorf("failed to encode pinned version file: %w", err)
	}
	return nil
}

// retrieveEnterprisePinnedVersion retrieves the pinned version from the pinned version file.
func retrieveEnterprisePinnedVersion(outputDir string) (EnterprisePinnedVersion, error) {
	pinnedVersionPath := PinnedVersionFilePath(outputDir)
	var pinnedVersionFile []EnterprisePinnedVersion
	if pinnedVersionData, err := os.ReadFile(pinnedVersionPath); err != nil {
		return EnterprisePinnedVersion{}, err
	} else if err := yaml.Unmarshal([]byte(pinnedVersionData), &pinnedVersionFile); err != nil {
		return EnterprisePinnedVersion{}, err
	}
	return pinnedVersionFile[0], nil
}

func RetrieveEnterpriseVersions(outputDir string) (version.Versions, error) {
	pinnedVersion, err := retrieveEnterprisePinnedVersion(outputDir)
	if err != nil {
		return nil, err
	}

	managerVer := pinnedVersion.Components[managerComponentName].Version

	return version.NewEnterpriseHashreleaseVersions(version.New(pinnedVersion.Title), pinnedVersion.HelmRelease, pinnedVersion.TigeraOperator.Version, managerVer), nil
}

// GenerateEnterpriseOperatorComponents generates the pinned_components.yaml for operator.
// It also copies the generated file to the output directory if provided.
func GenerateEnterpriseOperatorComponents(srcDir, outputDir string) (registry.OperatorComponent, string, error) {
	op := registry.OperatorComponent{}
	pinnedVersion, err := retrieveEnterprisePinnedVersion(srcDir)
	if err != nil {
		return op, "", err
	}

	components := pinnedVersion.ImageComponents(false)
	// Include components that do not produce images but are required by the operator.
	for _, name := range operatorIncludedComponents {
		if component, ok := pinnedVersion.Components[name]; ok {
			components[name] = component
		}
	}
	pinnedVersion.Components = components
	operatorComponentsFilePath := filepath.Join(srcDir, operatorComponentsFileName)
	operatorComponentsFile, err := os.Create(operatorComponentsFilePath)
	if err != nil {
		return op, "", err
	}
	defer func() { _ = operatorComponentsFile.Close() }()

	enc := yaml.NewEncoder(operatorComponentsFile)
	enc.SetIndent(2)
	defer func() { _ = enc.Close() }()

	if err = enc.Encode(pinnedVersion); err != nil {
		return op, "", err
	}
	if outputDir != "" {
		if err := utils.CopyFile(operatorComponentsFilePath, filepath.Join(outputDir, operatorComponentsFileName)); err != nil {
			return op, "", err
		}
	}
	op.Component = pinnedVersion.TigeraOperator
	return op, operatorComponentsFilePath, nil
}

// LoadEnterpriseHashrelease loads the hashrelease from the pinned version file.
func LoadEnterpriseHashrelease(repoRootDir, outputDir, hashreleaseSrcBaseDir string, latest bool) (*hashreleaseserver.EnterpriseHashrelease, error) {
	productBranch, err := utils.GitBranch(repoRootDir)
	if err != nil {
		logrus.WithError(err).Error("Failed to get current branch")
		return nil, err
	}
	pinnedVersion, err := retrieveEnterprisePinnedVersion(outputDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get pinned version")
	}
	hashreleaseSrc := ""
	if hashreleaseSrcBaseDir != "" {
		hashreleaseSrc = filepath.Join(hashreleaseSrcBaseDir, pinnedVersion.Hash)
	}
	return &hashreleaseserver.EnterpriseHashrelease{
		Hashrelease: hashreleaseserver.Hashrelease{
			Name:            pinnedVersion.ReleaseName,
			Hash:            pinnedVersion.Hash,
			Note:            pinnedVersion.Note,
			Stream:          version.DeterminePublishStream(productBranch, pinnedVersion.Title),
			ProductVersion:  pinnedVersion.Title,
			OperatorVersion: pinnedVersion.TigeraOperator.Version,
			Source:          hashreleaseSrc,
			Latest:          latest,
		},
		ChartVersion:   pinnedVersion.HelmRelease,
		ManagerVersion: pinnedVersion.Components[managerComponentName].Version,
	}, nil
}

// RetrieveEnterpriseImageComponents retrieves all components from the pinned version file
// that produce images including Tigera operator and its init image.
func RetrieveEnterpriseImageComponents(outputDir string) (map[string]registry.Component, error) {
	pinnedVersion, err := retrieveEnterprisePinnedVersion(outputDir)
	if err != nil {
		return nil, err
	}
	return pinnedVersion.ImageComponents(true), nil
}

func LoadEnterpriseHashreleaseFromRemote(hashreleaseName, outputDir, repoRootDir string) (*hashreleaseserver.EnterpriseHashrelease, error) {
	if err := os.MkdirAll(outputDir, utils.DirPerms); err != nil {
		return nil, fmt.Errorf("failed to create %s: %w", outputDir, err)
	}
	hashreleaseURL := fmt.Sprintf("https://%s.%s/%s", hashreleaseName, hashreleaseserver.BaseDomain, pinnedVersionFileName)
	pinnedVersionPath := PinnedVersionFilePath(outputDir)
	file, err := os.Create(pinnedVersionPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s: %w", pinnedVersionPath, err)
	}
	defer func() { _ = file.Close() }()
	resp, err := http.Get(hashreleaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get %s pinned_versions.yml from %s: %w", hashreleaseName, hashreleaseURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get %s pinned_versions.yml: %s", hashreleaseName, resp.Status)
	}
	if _, err := io.Copy(file, resp.Body); err != nil {
		return nil, fmt.Errorf("failed to write %s pinned_versions.yml: %w", hashreleaseName, err)
	}
	return LoadEnterpriseHashrelease(repoRootDir, outputDir, "", false)
}
