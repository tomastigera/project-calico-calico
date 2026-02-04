// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package resources

import (
	"reflect"

	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/client-go/rest"
)

const (
	AlertExceptionResourceName = "AlertExceptions"
	AlertExceptionCRDName      = "alertexceptions.crd.projectcalico.org"
)

func NewAlertExceptionClient(r rest.Interface, group BackingAPIGroup) K8sResourceClient {
	return &customResourceClient{
		restClient:      r,
		resource:        AlertExceptionResourceName,
		k8sResourceType: reflect.TypeOf(apiv3.AlertException{}),
		k8sListType:     reflect.TypeOf(apiv3.AlertExceptionList{}),
		kind:            apiv3.KindAlertException,
		apiGroup:        group,
	}
}
