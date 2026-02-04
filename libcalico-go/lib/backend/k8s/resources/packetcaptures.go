// Copyright (c) 2020 Tigera, Inc. All rights reserved.

package resources

import (
	"reflect"

	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/client-go/rest"
)

const (
	PacketCaptureResourceName = "PacketCaptures"
	PacketCaptureCRDName      = "packetcaptures.crd.projectcalico.org"
)

func NewPacketCaptureClient(r rest.Interface, group BackingAPIGroup) K8sResourceClient {
	return &customResourceClient{
		restClient:      r,
		resource:        PacketCaptureResourceName,
		k8sResourceType: reflect.TypeOf(apiv3.PacketCapture{}),
		k8sListType:     reflect.TypeOf(apiv3.PacketCaptureList{}),
		namespaced:      true,
		kind:            apiv3.KindPacketCapture,
		apiGroup:        group,
	}
}
