// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package helpers

import (
	"sort"
	"strings"

	libcalicoapi "github.com/tigera/api/pkg/apis/projectcalico/v3"

	licFeatures "github.com/projectcalico/calico/licensing/client/features"
)

// ConvertToPackageType converts the features array extracted from a license
// to a LicensePackageType
func ConvertToPackageType(features []string) libcalicoapi.LicensePackageType {
	if len(features) < 2 {
		return ""
	}

	switch strings.Join(features[0:2], "|") {
	case licFeatures.Enterprise:
		return libcalicoapi.Enterprise
	default:
		return ""
	}
}

// ExpandFeatureNames expands the license package to the individual
// features that are available
func ExpandFeatureNames(features []string) []string {
	sortedFeatures := make([]string, len(features))
	copy(sortedFeatures, features)
	sort.Strings(sortedFeatures)
	return sortedFeatures
}
