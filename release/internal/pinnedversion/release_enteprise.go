package pinnedversion

import (
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
)

type EnterpriseReleaseVersions struct {
	CalicoReleaseVersions
	ChartVersion string
	RootDir      string
}

func (p *EnterpriseReleaseVersions) GenerateFile() (version.Data, error) {
	ver := version.New(p.ProductVersion)

	calicoVer, err := utils.DetermineCalicoVersion(p.RootDir)
	if err != nil {
		return nil, fmt.Errorf("failed to determine calico version: %w", err)
	}
	parts := strings.Split(calicoVer, ".")
	calicoMajorMinor := fmt.Sprintf("%s.%s", parts[0], parts[1])

	tmplData := &enterpriseTemplateData{
		calicoTemplateData: calicoTemplateData{
			ProductVersion: p.ProductVersion,
			Operator: registry.Component{
				Version:  p.OperatorVersion,
				Image:    p.OperatorCfg.Image,
				Registry: p.OperatorCfg.Registry,
			},
			ReleaseBranch: fmt.Sprintf("%s-%s", p.ReleaseBranchPrefix, ver.Stream()),
		},
		HelmReleaseVersion: p.ChartVersion,
		ManagerVersion:     p.ProductVersion,
		CalicoMinorVersion: calicoMajorMinor,
	}

	tmpl, err := template.New("versions").Parse(enterpriseTemplate)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(p.Dir, 0o755); err != nil {
		return nil, err
	}
	p.versionFilePath = PinnedVersionFilePath(p.Dir)
	pinnedVersionFile, err := os.Create(p.versionFilePath)
	if err != nil {
		return nil, err
	}
	defer pinnedVersionFile.Close()
	if err := tmpl.Execute(pinnedVersionFile, tmplData); err != nil {
		return nil, err
	}
	return nil, nil
}

func (p *EnterpriseReleaseVersions) ImageList() ([]string, error) {
	components, err := RetrieveEnterpriseImageComponents(p.Dir, "")
	if err != nil {
		return nil, err
	}
	componentNames := make([]string, 0, len(components))
	for _, component := range components {
		if strings.Contains(component.Image, "tigera/operator") {
			continue
		}
		componentNames = append(componentNames, strings.TrimPrefix(component.Image, "tigera/"))
	}
	return componentNames, nil
}
