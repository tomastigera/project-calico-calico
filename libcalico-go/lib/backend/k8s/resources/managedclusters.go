// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package resources

import (
	"reflect"

	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/client-go/rest"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
)

const (
	ManagedClusterResourceName = "ManagedClusters"
	ManagedClusterCRDName      = "managedclusters.crd.projectcalico.org"
)

func NewManagedClusterClient(r rest.Interface, group BackingAPIGroup, cfg *apiconfig.CalicoAPIConfigSpec) K8sResourceClient {
	return &customResourceClient{
		restClient:      r,
		resource:        ManagedClusterResourceName,
		k8sResourceType: reflect.TypeOf(apiv3.ManagedCluster{}),
		k8sListType:     reflect.TypeOf(apiv3.ManagedClusterList{}),
		namespaced:      cfg.MultiTenantEnabled,
		kind:            apiv3.KindManagedCluster,
		apiGroup:        group,
	}
}
