// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package resources

import (
	"reflect"

	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/client-go/rest"
)

const (
	UISettingsGroupResourceName = "UISettingsGroups"
	UISettingsGroupCRDName      = "uisettingsgroups.crd.projectcalico.org"
)

func NewUISettingsGroupClient(r rest.Interface, group BackingAPIGroup) K8sResourceClient {
	return &customResourceClient{
		restClient:      r,
		resource:        UISettingsGroupResourceName,
		k8sResourceType: reflect.TypeFor[apiv3.UISettingsGroup](),
		k8sListType:     reflect.TypeFor[apiv3.UISettingsGroupList](),
		kind:            apiv3.KindUISettingsGroup,
		apiGroup:        group,
	}
}
