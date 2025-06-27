package helpers

import (
	"testing"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
)

func TestConvertToPackageType(t *testing.T) {
	tests := []struct {
		name     string
		features []string
		want     v3.LicensePackageType
	}{
		{name: "convert enterprise package from base features", features: []string{"cnx", "all"}, want: v3.Enterprise},
		{name: "convert enterprise package from base features and ingress", features: []string{"cnx", "all", "ingress"}, want: v3.Enterprise},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ConvertToPackageType(tt.features); got != tt.want {
				t.Errorf("ConvertToPackageType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExpandFeaturesShouldNotAffectPackageType(t *testing.T) {
	features := []string{"cnx", "all", "ingress"}
	ExpandFeatureNames(features)
	got := ConvertToPackageType(features)
	if got != v3.Enterprise {
		t.Errorf("ConvertToPackageType() = %v, want %v", got, v3.Enterprise)
	}
}
