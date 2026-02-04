// Copyright (c) 2018 Tigera, Inc. All rights reserved.

package resources

import (
	"reflect"

	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/client-go/rest"
)

const (
	RemoteClusterConfigurationResourceName = "RemoteClusterConfigurations"
	RemoteClusterConfigurationCRDName      = "remoteclusterconfigurations.crd.projectcalico.org"
)

func NewRemoteClusterConfigurationClient(r rest.Interface, group BackingAPIGroup) K8sResourceClient {
	return &customResourceClient{
		restClient:      r,
		resource:        RemoteClusterConfigurationResourceName,
		k8sResourceType: reflect.TypeOf(apiv3.RemoteClusterConfiguration{}),
		k8sListType:     reflect.TypeOf(apiv3.RemoteClusterConfigurationList{}),
		kind:            apiv3.KindRemoteClusterConfiguration,
		apiGroup:        group,
	}
}
