// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package calico

import (
	"context"
	"reflect"

	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/storagebackend/factory"

	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// NewEgressGatewayPolicyStorage creates a new libcalico-based storage.Interface implementation for EgressGatewayPolicy
func NewEgressGatewayPolicyStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
	c := CreateClientFromConfig()
	createFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*api.EgressGatewayPolicy)
		return c.EgressGatewayPolicy().Create(ctx, res, oso)
	}
	updateFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*api.EgressGatewayPolicy)
		return c.EgressGatewayPolicy().Update(ctx, res, oso)
	}
	getFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		ogo := opts.(options.GetOptions)
		return c.EgressGatewayPolicy().Get(ctx, name, ogo)
	}
	deleteFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		odo := opts.(options.DeleteOptions)
		return c.EgressGatewayPolicy().Delete(ctx, name, odo)
	}
	listFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (resourceListObject, error) {
		olo := opts.(options.ListOptions)
		return c.EgressGatewayPolicy().List(ctx, olo)
	}
	watchFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (watch.Interface, error) {
		olo := opts.(options.ListOptions)
		return c.EgressGatewayPolicy().Watch(ctx, olo)
	}
	hasRestrictionsFn := func(obj resourceObject) bool {
		return false
	}

	dryRunnableStorage := registry.DryRunnableStorage{Storage: &resourceStore{
		client:            c,
		codec:             opts.RESTOptions.StorageConfig.Codec,
		versioner:         APIObjectVersioner{},
		aapiType:          reflect.TypeFor[api.EgressGatewayPolicy](),
		aapiListType:      reflect.TypeFor[api.EgressGatewayPolicyList](),
		libCalicoType:     reflect.TypeFor[api.EgressGatewayPolicy](),
		libCalicoListType: reflect.TypeFor[api.EgressGatewayPolicyList](),
		isNamespaced:      false,
		create:            createFn,
		update:            updateFn,
		get:               getFn,
		delete:            deleteFn,
		list:              listFn,
		watch:             watchFn,
		resourceName:      "EgressGatewayPolicy",
		converter:         EgressPolicyConverter{},
		hasRestrictions:   hasRestrictionsFn,
	}, Codec: opts.RESTOptions.StorageConfig.Codec}
	return dryRunnableStorage, func() {}
}

type EgressPolicyConverter struct {
}

func (gc EgressPolicyConverter) convertToLibcalico(aapiObj runtime.Object) resourceObject {
	aapiEgressPolicy := aapiObj.(*api.EgressGatewayPolicy)
	lcgEgressPolicy := &api.EgressGatewayPolicy{}
	lcgEgressPolicy.TypeMeta = aapiEgressPolicy.TypeMeta
	lcgEgressPolicy.ObjectMeta = aapiEgressPolicy.ObjectMeta
	lcgEgressPolicy.Kind = api.KindEgressGatewayPolicy
	lcgEgressPolicy.APIVersion = api.GroupVersionCurrent
	lcgEgressPolicy.Spec = aapiEgressPolicy.Spec
	return lcgEgressPolicy
}

func (gc EgressPolicyConverter) convertToAAPI(libcalicoObject resourceObject, aapiObj runtime.Object) {
	lcgEgressPolicy := libcalicoObject.(*api.EgressGatewayPolicy)
	aapiEgressPolicy := aapiObj.(*api.EgressGatewayPolicy)
	aapiEgressPolicy.Spec = lcgEgressPolicy.Spec
	aapiEgressPolicy.TypeMeta = lcgEgressPolicy.TypeMeta
	aapiEgressPolicy.ObjectMeta = lcgEgressPolicy.ObjectMeta
}

func (gc EgressPolicyConverter) convertToAAPIList(libcalicoListObject resourceListObject, aapiListObj runtime.Object, pred storage.SelectionPredicate) {
	lcgEgressPolicyList := libcalicoListObject.(*api.EgressGatewayPolicyList)
	aapiEgressPolicyList := aapiListObj.(*api.EgressGatewayPolicyList)
	if libcalicoListObject == nil {
		aapiEgressPolicyList.Items = []api.EgressGatewayPolicy{}
		return
	}
	aapiEgressPolicyList.TypeMeta = lcgEgressPolicyList.TypeMeta
	aapiEgressPolicyList.ListMeta = lcgEgressPolicyList.ListMeta
	for _, item := range lcgEgressPolicyList.Items {
		aapiEgressPolicy := api.EgressGatewayPolicy{}
		gc.convertToAAPI(&item, &aapiEgressPolicy)
		if matched, err := pred.Matches(&aapiEgressPolicy); err == nil && matched {
			aapiEgressPolicyList.Items = append(aapiEgressPolicyList.Items, aapiEgressPolicy)
		}
	}
}
