package version

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

func NewEnterpriseVersionData(calico Version, chartVersion, operator, manager string) Data {
	return &EnterpriseVersionData{
		CalicoVersionData: CalicoVersionData{
			calico:   calico,
			operator: operator,
		},
		chartVersion: chartVersion,
		manager:      manager,
	}
}

func NewEnterpriseReleaseVersionData(calico Version, chartVersion, operator string) *EnterpriseVersionData {
	return &EnterpriseVersionData{
		CalicoVersionData: CalicoVersionData{
			calico:   calico,
			operator: operator,
		},
		chartVersion: chartVersion,
		manager:      calico.FormattedString(),
		release:      true,
	}
}

type EnterpriseVersionData struct {
	CalicoVersionData
	chartVersion string
	manager      string
	release      bool
}

func (v *EnterpriseVersionData) ChartVersion() string {
	return v.chartVersion
}

func (v *EnterpriseVersionData) HelmChartVersion() string {
	if v.chartVersion == "" {
		return v.calico.FormattedString()
	}
	return fmt.Sprintf("%s-%s", v.calico.FormattedString(), v.chartVersion)
}

func (v *EnterpriseVersionData) OperatorVersion() string {
	if v.release {
		return v.operator
	}
	return fmt.Sprintf("%s-%s", v.operator, v.calico.FormattedString())
}

func (v *EnterpriseVersionData) Hash() string {
	return fmt.Sprintf("%s-%s-%s", v.calico.FormattedString(), v.operator, v.manager)
}

func (v *EnterpriseVersionData) ManagerVersion() string {
	return v.manager
}

func (v *Version) NextReleaseVersion() (Version, error) {
	ver := v.Semver()
	ep, epVer := IsEarlyPreviewVersion(ver)
	if ep {
		if epVer == 1 {
			// EP 1 = increment EP version i.e vX.Y.Z-1.0 to vX.Y.Z-1.1
			parts := strings.Split(ver.Prerelease(), ".")
			minorEPver, err := strconv.Atoi(strings.Split(parts[1], "1")[0])
			if err != nil {
				logrus.WithError(err).Error("Failed to parse minor EP version")
				return "", err
			}
			return New(fmt.Sprintf("v%d.%d.0-1.%d", ver.Major(), ver.Minor(), minorEPver+1)), nil
		}
		// EP 2 - increment to GA i.e vX.Y.Z-2.0 to vX.Y.1
		return New(fmt.Sprintf("v%d.%d.1", ver.Major(), ver.Minor())), nil
	}
	// GA versions - increment patch version i.e vX.Y.Z to vX.Y.Z+1
	return New(ver.IncPatch().String()), nil
}
