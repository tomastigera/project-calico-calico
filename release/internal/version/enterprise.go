package version

import (
	"fmt"
	"strings"
)

func NewEnterpriseHashreleaseVersions(calico Version, chartVersion, operator, manager string) *EnterpriseVersions {
	return &EnterpriseVersions{
		HashreleaseVersions: HashreleaseVersions{
			calico:   calico,
			operator: operator,
		},
		chartVersion: chartVersion,
		manager:      manager,
	}
}

type EnterpriseVersions struct {
	HashreleaseVersions
	chartVersion string
	manager      string
	release      bool
}

func (v *EnterpriseVersions) ChartVersion() string {
	return v.chartVersion
}

func (v *EnterpriseVersions) HelmChartVersion() string {
	if v.chartVersion == "" {
		return v.calico.FormattedString()
	}
	return fmt.Sprintf("%s-%s", v.calico.FormattedString(), v.chartVersion)
}

func (v *EnterpriseVersions) OperatorVersion() string {
	if v.release {
		return v.operator
	}
	return fmt.Sprintf("%s-%s", v.operator, v.calico.FormattedString())
}

func (v *EnterpriseVersions) Hash() string {
	if v.manager == "" {
		return fmt.Sprintf("%s-%s", v.calico.FormattedString(), v.operator)
	}
	return fmt.Sprintf("%s-%s-%s", v.calico.FormattedString(), v.operator, v.manager)
}

func (v *EnterpriseVersions) ManagerVersion() string {
	return v.manager
}

func (v *Version) PrimaryStream() string {
	return strings.Split(v.Stream(), "-")[0]
}
