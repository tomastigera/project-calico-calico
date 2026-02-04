// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package resources

import (
	"reflect"

	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/client-go/rest"
)

const (
	DeepPacketInspectionResourceName = "DeepPacketInspections"
	DeepPacketInspectionCRDName      = "deeppacketinspections.crd.projectcalico.org"
)

func NewDeepPacketInspectionClient(r rest.Interface, group BackingAPIGroup) K8sResourceClient {
	return &customResourceClient{
		restClient:      r,
		resource:        DeepPacketInspectionResourceName,
		k8sResourceType: reflect.TypeOf(apiv3.DeepPacketInspection{}),
		k8sListType:     reflect.TypeOf(apiv3.DeepPacketInspectionList{}),
		kind:            apiv3.KindDeepPacketInspection,
		namespaced:      true,
		apiGroup:        group,
	}
}
