package pinnedversion

import (
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/template"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
)

const managerComponent = "manager"

var (
	operatorExcludedComponents = []string{
		"coreos-config-reloader",
		"coreos-dex",
		"upstream-fluentd",
		"coreos-prometheus-operator",
	}
	noEntepriseImageComponents = []string{
		"calico-private",
		"manager-proxy",
		"coreos-alertmanager",
		"coreos-config-reloader",
		"coreos-dex",
		"coreos-prometheus",
		"coreos-prometheus-operator",
		"eck-elasticsearch",
		"eck-elasticsearch-operator",
		"eck-kibana",
		"upstream-fluentd",
	}
)

//go:embed templates/enterprise-versions.yaml.gotmpl
var enterpriseTemplate string

type ManagerConfig struct {
	Dir    string
	Branch string
}

func (m ManagerConfig) GitVersion() (string, error) {
	return command.GitVersion(m.Dir, true)
}

func (m ManagerConfig) GitBranch() (string, error) {
	return utils.GitBranch(m.Dir)
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

type enterpriseTemplateData struct {
	calicoTemplateData
	HelmReleaseVersion string
	CalicoMinorVersion string
	ManagerVersion     string
}

type EnteprisePinnedVersions struct {
	CalicoPinnedVersions
	ManagerCfg   ManagerConfig
	ChartVersion string
}

func (p *EnteprisePinnedVersions) GenerateFile() (version.Versions, error) {
	pinnedVersionPath := PinnedVersionFilePath(p.Dir)

	productBranch, err := utils.GitBranch(p.RootDir)
	if err != nil {
		return nil, err
	}
	productVer, err := command.GitVersion(p.RootDir, true)
	if err != nil {
		logrus.WithError(err).Error("Failed to determine product git version")
		return nil, err
	}
	releaseName := fmt.Sprintf("%s-%s-%s", time.Now().Format("2006-01-02"), version.DeterminePublishStream(productBranch, productVer), RandomWord())
	releaseName = strings.ReplaceAll(releaseName, ".", "-")
	operatorBranch, err := p.OperatorCfg.GitBranch()
	if err != nil {
		return nil, err
	}
	operatorVer, err := p.OperatorCfg.GitVersion()
	if err != nil {
		return nil, err
	}
	managerBranch, err := p.ManagerCfg.GitBranch()
	if err != nil {
		return nil, fmt.Errorf("failed to determine manager git branch: %w", err)
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
	calicoMajorMinor := fmt.Sprintf("%s.%s", parts[0], parts[1])

	versionData := version.NewEnterpriseHashreleaseVersions(version.New(productVer), p.ChartVersion, operatorVer, managerVer)
	tmpl, err := template.New("pinnedversion").Parse(enterpriseTemplate)
	if err != nil {
		return nil, err
	}
	tmplData := &enterpriseTemplateData{
		calicoTemplateData: calicoTemplateData{
			ReleaseName:    releaseName,
			BaseDomain:     hashreleaseserver.BaseDomain,
			ProductVersion: versionData.ProductVersion(),
			Operator: registry.Component{
				Version:  versionData.OperatorVersion(),
				Image:    p.OperatorCfg.Image,
				Registry: p.OperatorCfg.Registry,
			},
			Hash: versionData.Hash(),
			Note: fmt.Sprintf("%s - generated at %s using %s release branch with %s operator branch and %s manager branch",
				releaseName, time.Now().Format(time.RFC1123), productBranch, operatorBranch, managerBranch),
			ReleaseBranch: versionData.ReleaseBranch(p.ReleaseBranchPrefix),
		},
		HelmReleaseVersion: p.ChartVersion,
		CalicoMinorVersion: calicoMajorMinor,
		ManagerVersion:     managerVer,
	}
	logrus.WithField("file", pinnedVersionPath).Info("Generating pinned version file")
	pinnedVersionFile, err := os.Create(pinnedVersionPath)
	if err != nil {
		return nil, err
	}
	defer pinnedVersionFile.Close()
	if err := tmpl.Execute(pinnedVersionFile, tmplData); err != nil {
		return nil, err
	}

	if p.BaseHashreleaseDir != "" {
		hashreleaseDir := filepath.Join(p.BaseHashreleaseDir, versionData.Hash())
		if err := os.MkdirAll(hashreleaseDir, utils.DirPerms); err != nil {
			return nil, err
		}
		if err := utils.CopyFile(pinnedVersionPath, filepath.Join(hashreleaseDir, pinnedVersionFileName)); err != nil {
			return nil, err
		}
	}

	return versionData, nil
}

// retrieveEnterpisePinnedVersion retrieves the pinned version from the pinned version file.
func retrieveEnterpisePinnedVersion(outputDir string) (EnterprisePinnedVersion, error) {
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
	pinnedVersion, err := retrieveEnterpisePinnedVersion(outputDir)
	if err != nil {
		return nil, err
	}

	managerVer := pinnedVersion.Components[managerComponent].Version

	return version.NewEnterpriseHashreleaseVersions(version.New(pinnedVersion.Title), pinnedVersion.HelmRelease, pinnedVersion.TigeraOperator.Version, managerVer), nil
}

// GenerateEnterpriseOperatorComponents generates the pinned_components.yaml for operator.
// It also copies the generated file to the output directory if provided.
func GenerateEnterpriseOperatorComponents(srcDir, outputDir string) (registry.OperatorComponent, string, error) {
	op := registry.OperatorComponent{}
	pinnedVersion, err := retrieveEnterpisePinnedVersion(srcDir)
	if err != nil {
		return op, "", err
	}

	for name, component := range pinnedVersion.Components {
		// Remove components that are not part of the operator.
		if slices.Contains(operatorExcludedComponents, name) {
			delete(pinnedVersion.Components, name)
			continue
		}
		if component.Image == "" {
			img := registry.EnterpriseImageMap[name]
			if img != "" {
				component.Image = fmt.Sprintf("%s/%s", registry.TigeraNamespace, img)
			} else if component.Version == pinnedVersion.Title || strings.HasPrefix(name, managerComponent) {
				component.Image = fmt.Sprintf("%s/%s", registry.TigeraNamespace, name)
			}
		}
		pinnedVersion.Components[name] = component
	}

	operatorComponentsFilePath := filepath.Join(srcDir, operatorComponentsFileName)
	operatorComponentsFile, err := os.Create(operatorComponentsFilePath)
	if err != nil {
		return op, "", err
	}
	defer operatorComponentsFile.Close()
	if err = yaml.NewEncoder(operatorComponentsFile).Encode(pinnedVersion); err != nil {
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
	pinnedVersion, err := retrieveEnterpisePinnedVersion(outputDir)
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
			Product:         utils.ProductName,
			Stream:          version.DeterminePublishStream(productBranch, pinnedVersion.Title),
			ProductVersion:  pinnedVersion.Title,
			OperatorVersion: pinnedVersion.TigeraOperator.Version,
			Source:          hashreleaseSrc,
			Time:            time.Now(),
			Latest:          latest,
		},
		ChartVersion:   pinnedVersion.HelmRelease,
		ManagerVersion: pinnedVersion.Components[managerComponent].Version,
	}, nil
}

func RetrieveEnterpriseImageComponents(outputDir string) (map[string]registry.Component, error) {
	pinnedVersion, err := retrieveEnterpisePinnedVersion(outputDir)
	if err != nil {
		return nil, err
	}
	components := pinnedVersion.Components
	operator := registry.OperatorComponent{Component: pinnedVersion.TigeraOperator}
	components[operator.Image] = operator.Component
	initImage := operator.InitImage()
	components[initImage.Image] = operator.InitImage()
	for name, component := range components {
		// Remove components that do not produce images.
		if utils.Contains(noEntepriseImageComponents, name) {
			delete(components, name)
			continue
		}
		img := registry.EnterpriseImageMap[name]
		if img != "" {
			component.Image = img
		} else if component.Image == "" {
			component.Image = name
		}
		components[name] = component
	}
	return components, nil
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
	defer file.Close()
	resp, err := http.Get(hashreleaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get %s pinned_versions.yml from %s: %w", hashreleaseName, hashreleaseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get %s pinned_versions.yml: %s", hashreleaseName, resp.Status)
	}
	if _, err := io.Copy(file, resp.Body); err != nil {
		return nil, fmt.Errorf("failed to write %s pinned_versions.yml: %w", hashreleaseName, err)
	}
	return LoadEnterpriseHashrelease(repoRootDir, outputDir, "", false)
}
