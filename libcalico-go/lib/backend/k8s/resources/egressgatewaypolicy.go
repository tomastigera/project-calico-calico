// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package resources

import (
	"reflect"

	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/client-go/rest"
)

const (
	EgressGatewayPolicyResourceName = "EgressGatewayPolicies"
	EgressGatewayPolicyCRDName      = "egressgatewaypolicies.crd.projectcalico.org"
)

func NewEgressPolicyClient(r rest.Interface, group BackingAPIGroup) K8sResourceClient {
	return &customResourceClient{
		restClient:      r,
		resource:        EgressGatewayPolicyResourceName,
		k8sResourceType: reflect.TypeOf(apiv3.EgressGatewayPolicy{}),
		k8sListType:     reflect.TypeOf(apiv3.EgressGatewayPolicyList{}),
		kind:            apiv3.KindEgressGatewayPolicy,
		apiGroup:        group,
	}
}
