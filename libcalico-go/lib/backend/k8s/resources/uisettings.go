// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package resources

import (
	"reflect"

	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/client-go/rest"
)

const (
	UISettingsResourceName = "UISettings"
	UISettingsCRDName      = "UISettings.crd.projectcalico.org"
)

func NewUISettingsClient(r rest.Interface, group BackingAPIGroup) K8sResourceClient {
	return &customResourceClient{
		restClient:      r,
		resource:        UISettingsResourceName,
		k8sResourceType: reflect.TypeFor[apiv3.UISettings](),
		k8sListType:     reflect.TypeFor[apiv3.UISettingsList](),
		kind:            apiv3.KindUISettings,
		apiGroup:        group,
	}
}
