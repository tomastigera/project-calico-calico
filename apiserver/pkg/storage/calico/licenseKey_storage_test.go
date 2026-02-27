package calico

import (
	"testing"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/licensing/utils"
)

func TestLicenseKeyConverter_convertToAAPI(t *testing.T) {
	tests := []struct {
		name         string
		givenLicense resourceObject
	}{
		{name: "expired license", givenLicense: utils.ExpiredTestLicense()},
		{name: "enterprise license", givenLicense: utils.ValidEnterpriseTestLicense()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gc := LicenseKeyConverter{}
			licenseKey := v3.LicenseKey{}

			gc.convertToAAPI(tt.givenLicense, &licenseKey)
			if isEmpty(licenseKey.Status) {
				t.Errorf("License status cannot be empty %v", licenseKey.Status)
			}
		})
	}
}

func isEmpty(status v3.LicenseKeyStatus) bool {
	if status.Expiry.IsZero() {
		return true
	}

	if status.GracePeriod == "" {
		return true
	}

	if len(status.Features) == 0 {
		return true
	}

	if status.MaxNodes == 0 {
		return true
	}

	if status.Package == "" {
		return true
	}

	return false
}
